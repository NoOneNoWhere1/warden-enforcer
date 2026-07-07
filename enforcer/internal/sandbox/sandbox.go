// Package sandbox mirrors enforcer/src/sandbox_controller.rs: session
// sandbox lifecycle over an injectable kernel backend.
package sandbox

import (
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
)

// AlreadyExistsError mirrors SandboxError::AlreadyExists.
type AlreadyExistsError struct{ SessionID string }

func (e *AlreadyExistsError) Error() string { return "session already exists: " + e.SessionID }

// NotFoundError mirrors SandboxError::NotFound.
type NotFoundError struct{ SessionID string }

func (e *NotFoundError) Error() string { return "session not found: " + e.SessionID }

// BackendError mirrors SandboxError::Backend — a kernel operation failed;
// Msg carries the shell-out stderr where available.
type BackendError struct{ Msg string }

func (e *BackendError) Error() string { return "backend error: " + e.Msg }

// Backend abstracts the Linux kernel features used to enforce isolation.
// Allows unit tests to inject a no-op and gate tests to use the real backend.
type Backend interface {
	// Create makes a network namespace for sessionID and applies nftables
	// rules permitting only the listed CIDRs, with default-deny egress.
	Create(sessionID string, cidrs []cidr.Cidr) error
	// Destroy tears down the network namespace and nftables rules for
	// sessionID.
	Destroy(sessionID string) error
	// LostDrops reports how many packet facts the session's nflog listener
	// discarded because the drops channel was full — part of the visible
	// loss counter (E3.3).
	LostDrops(sessionID string) uint64
}

// NoopBackend is a no-op backend. Used in unit tests and on non-Linux
// platforms.
type NoopBackend struct{}

func (NoopBackend) Create(string, []cidr.Cidr) error { return nil }
func (NoopBackend) Destroy(string) error             { return nil }
func (NoopBackend) LostDrops(string) uint64          { return 0 }

// Controller tracks which sessions have an active sandbox.
//
// PARITY (Amendment 6): no mutex here on purpose. Rust nests the controller
// inside the single Arc<Mutex<AppState>> (api.rs:39-48); the Go api package
// mirrors that with one AppState lock. A second lock here would invent
// lock-ordering questions Rust never had.
type Controller struct {
	backend Backend
	active  map[string]struct{}
}

func NewController(backend Backend) *Controller {
	return &Controller{backend: backend, active: map[string]struct{}{}}
}

// CreateSandbox creates a sandbox for sessionID with the given CIDR
// allowlist. Returns AlreadyExistsError if the session is already active.
// Returns BackendError if the kernel operation fails; the session is NOT
// marked active on backend failure.
func (c *Controller) CreateSandbox(sessionID string, cidrs []cidr.Cidr) error {
	if _, ok := c.active[sessionID]; ok {
		return &AlreadyExistsError{SessionID: sessionID}
	}
	if err := c.backend.Create(sessionID, cidrs); err != nil {
		return err
	}
	c.active[sessionID] = struct{}{}
	return nil
}

// DestroySandbox tears down the sandbox for sessionID.
// Returns NotFoundError if the session is not active. On backend failure the
// session stays tracked — teardown did not complete, and silently dropping
// the record would leave an unenforced namespace unaccounted for.
func (c *Controller) DestroySandbox(sessionID string) error {
	if _, ok := c.active[sessionID]; !ok {
		return &NotFoundError{SessionID: sessionID}
	}
	if err := c.backend.Destroy(sessionID); err != nil {
		return err
	}
	delete(c.active, sessionID)
	return nil
}

func (c *Controller) IsActive(sessionID string) bool {
	_, ok := c.active[sessionID]
	return ok
}

func (c *Controller) ActiveCount() int {
	return len(c.active)
}

// LostDrops passes through the backend's channel-overflow count for the
// session (0 for backends without listeners).
func (c *Controller) LostDrops(sessionID string) uint64 {
	return c.backend.LostDrops(sessionID)
}
