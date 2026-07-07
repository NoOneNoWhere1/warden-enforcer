package sandbox

import (
	"errors"
	"testing"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
)

func newController() *Controller {
	return NewController(NoopBackend{})
}

func testCidrs(t *testing.T) []cidr.Cidr {
	t.Helper()
	c, err := cidr.Parse("10.99.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return []cidr.Cidr{c}
}

func mustCreate(t *testing.T, c *Controller, sessionID string) {
	t.Helper()
	if err := c.CreateSandbox(sessionID, testCidrs(t)); err != nil {
		t.Fatal(err)
	}
}

type failCreateBackend struct{ NoopBackend }

func (failCreateBackend) Create(string, []cidr.Cidr) error {
	return &BackendError{Msg: "netns create failed"}
}

type failDestroyBackend struct{ NoopBackend }

func (failDestroyBackend) Destroy(string) error {
	return &BackendError{Msg: "nft teardown failed"}
}

// ── Controller (ledger: sandbox_controller::*) ───────────────────────────────

func TestNewControllerHasZeroActiveSessions(t *testing.T) {
	if got := newController().ActiveCount(); got != 0 {
		t.Fatalf("active_count = %d, want 0", got)
	}
}

func TestUnknownSessionIsNotActive(t *testing.T) {
	if newController().IsActive("does-not-exist") {
		t.Fatal("unknown session must not be active")
	}
}

func TestCreateSandboxMakesSessionActive(t *testing.T) {
	c := newController()
	mustCreate(t, c, "sess-1")
	if !c.IsActive("sess-1") {
		t.Fatal("created session must be active")
	}
}

func TestCreateSandboxIncrementsActiveCount(t *testing.T) {
	c := newController()
	mustCreate(t, c, "sess-1")
	if got := c.ActiveCount(); got != 1 {
		t.Fatalf("active_count = %d, want 1", got)
	}
}

func TestCreateSandboxDuplicateReturnsAlreadyExists(t *testing.T) {
	c := newController()
	mustCreate(t, c, "sess-1")
	err := c.CreateSandbox("sess-1", testCidrs(t))
	var already *AlreadyExistsError
	if !errors.As(err, &already) {
		t.Fatalf("error = %v, want AlreadyExistsError", err)
	}
}

func TestDestroySandboxRemovesSession(t *testing.T) {
	c := newController()
	mustCreate(t, c, "sess-1")
	if err := c.DestroySandbox("sess-1"); err != nil {
		t.Fatal(err)
	}
	if c.IsActive("sess-1") {
		t.Fatal("destroyed session must not be active")
	}
}

func TestDestroySandboxDecrementsActiveCount(t *testing.T) {
	c := newController()
	mustCreate(t, c, "sess-1")
	if err := c.DestroySandbox("sess-1"); err != nil {
		t.Fatal(err)
	}
	if got := c.ActiveCount(); got != 0 {
		t.Fatalf("active_count = %d, want 0", got)
	}
}

func TestDestroyUnknownSessionReturnsNotFound(t *testing.T) {
	err := newController().DestroySandbox("unknown")
	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("error = %v, want NotFoundError", err)
	}
}

func TestMultipleSessionsAreTrackedIndependently(t *testing.T) {
	c := newController()
	mustCreate(t, c, "sess-a")
	mustCreate(t, c, "sess-b")
	if got := c.ActiveCount(); got != 2 {
		t.Fatalf("active_count = %d, want 2", got)
	}
	if err := c.DestroySandbox("sess-a"); err != nil {
		t.Fatal(err)
	}
	if got := c.ActiveCount(); got != 1 {
		t.Fatalf("active_count = %d, want 1", got)
	}
	if c.IsActive("sess-a") {
		t.Fatal("sess-a must not be active after destroy")
	}
	if !c.IsActive("sess-b") {
		t.Fatal("sess-b must still be active")
	}
}

func TestBackendErrorOnCreateIsPropagated(t *testing.T) {
	c := NewController(failCreateBackend{})
	err := c.CreateSandbox("sess-1", testCidrs(t))
	var backend *BackendError
	if !errors.As(err, &backend) {
		t.Fatalf("error = %v, want BackendError", err)
	}
}

func TestBackendErrorOnCreateDoesNotMarkSessionActive(t *testing.T) {
	c := NewController(failCreateBackend{})
	_ = c.CreateSandbox("sess-1", testCidrs(t))
	if c.IsActive("sess-1") {
		t.Fatal("failed create must not mark session active")
	}
	if got := c.ActiveCount(); got != 0 {
		t.Fatalf("active_count = %d, want 0", got)
	}
}

func TestBackendErrorOnDestroyIsPropagated(t *testing.T) {
	c := NewController(failDestroyBackend{})
	mustCreate(t, c, "sess-1")
	err := c.DestroySandbox("sess-1")
	var backend *BackendError
	if !errors.As(err, &backend) {
		t.Fatalf("error = %v, want BackendError", err)
	}
	// Session must remain active — teardown did not complete.
	// Operator must retry or force-remove; we must not silently drop the record.
	if !c.IsActive("sess-1") {
		t.Fatal("session must remain active after failed destroy")
	}
	if got := c.ActiveCount(); got != 1 {
		t.Fatalf("active_count = %d, want 1", got)
	}
}
