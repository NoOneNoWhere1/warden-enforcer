//go:build linux

package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/ruleset"
)

// LinuxSandbox is the production backend. Creates a per-session network
// namespace, programs nftables rules inside it via ruleset.Render, connects
// it to the root namespace over a veth uplink, and tears it all down on
// destroy. Requires root and a Linux kernel with nftables and iproute2.
//
// runsc (gVisor) is invoked by the orchestrator when placing an agent into
// the prepared namespace — it is not part of sandbox creation here.
type LinuxSandbox struct {
	uplinks *uplinkAllocator
	// drops receives packet facts from every session's nflog listener; the
	// single consumer in the api package turns them into signed events.
	drops chan<- Drop
	// listeners maps session → nflog listener stop func. No mutex — mutated
	// only under the api AppState lock, same as uplinks (Amendment 6).
	listeners map[string]func()
	// lost counts Drops discarded per session because the channel was full
	// (non-blocking send). Map mutated only under the AppState lock; the
	// listener goroutine holds its own counter pointer and only Add()s.
	lost map[string]*atomic.Uint64
}

func NewLinuxSandbox(drops chan<- Drop) *LinuxSandbox {
	return &LinuxSandbox{
		uplinks:   newUplinkAllocator(),
		drops:     drops,
		listeners: map[string]func(){},
		lost:      map[string]*atomic.Uint64{},
	}
}

// LostDrops reports the session's channel-overflow count (Backend interface).
func (s *LinuxSandbox) LostDrops(sessionID string) uint64 {
	if c, ok := s.lost[sessionID]; ok {
		return c.Load()
	}
	return 0
}

func (s *LinuxSandbox) Create(sessionID string, cidrs []cidr.Cidr) error {
	ns := netnsName(sessionID)

	//nolint:gosec // G204: session_id interpolation mirrors Rust sandbox_controller.rs:114 — parity-preserving by design
	cmd := exec.Command("ip", "netns", "add", ns)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &BackendError{Msg: fmt.Sprintf("ip netns add %s failed: %s", ns, strings.TrimSpace(stderr.String()))}
		}
		return &BackendError{Msg: fmt.Sprintf("ip netns add: %v", err)}
	}

	script := ruleset.New(sessionID, cidrs).Render()
	if err := applyRulesetInNS(ns, script); err != nil {
		// Namespace exists but has no rules — remove it so the controller
		// does not track a session that has no enforcement.
		//nolint:gosec // G204: same parity-preserving shell-out as above
		_ = exec.Command("ip", "netns", "del", ns).Run()
		return err
	}

	// Listener before uplink: once the namespace is routable, no dropped
	// packet may go unheard — same enforcement-before-connectivity order
	// as the rules themselves.
	lost := new(atomic.Uint64)
	stop, err := s.startDropListener(sessionID, ns, lost)
	if err != nil {
		//nolint:gosec // G204: same parity-preserving shell-out as above
		_ = exec.Command("ip", "netns", "del", ns).Run()
		return err
	}
	s.listeners[sessionID] = stop
	s.lost[sessionID] = lost

	// Uplink last, after rules are live: the namespace must never be
	// routable before its enforcement exists.
	if err := s.provisionUplink(sessionID, ns); err != nil {
		stop()
		delete(s.listeners, sessionID)
		delete(s.lost, sessionID)
		// Deleting the namespace destroys its veth end, which destroys the
		// whole pair — no separate host-side cleanup.
		//nolint:gosec // G204: same parity-preserving shell-out as above
		_ = exec.Command("ip", "netns", "del", ns).Run()
		return err
	}
	return nil
}

func (s *LinuxSandbox) Destroy(sessionID string) error {
	ns := netnsName(sessionID)

	// Stop the listener before the namespace goes away; safe on retry
	// after a failed ns deletion (the entry is already gone).
	if stop, ok := s.listeners[sessionID]; ok {
		stop()
		delete(s.listeners, sessionID)
	}
	delete(s.lost, sessionID)

	//nolint:gosec // G204: session_id interpolation mirrors Rust sandbox_controller.rs:139 — parity-preserving by design
	cmd := exec.Command("ip", "netns", "del", ns)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &BackendError{Msg: fmt.Sprintf("ip netns del %s failed: %s", ns, strings.TrimSpace(stderr.String()))}
		}
		return &BackendError{Msg: fmt.Sprintf("ip netns del: %v", err)}
	}
	// The ns deletion above destroyed the veth pair; only the index remains.
	s.uplinks.free(sessionID)
	return nil
}

// provisionUplink connects ns to the root namespace over a veth pair so the
// forward/masquerade rules already programmed inside carry packets: host
// side wdn<idx> gets the .1 of a per-session /30 from 10.200.0.0/16, the
// namespace side ("uplink") gets the .2 and a default route back to .1.
// On any failure the index is freed; the caller removes the namespace.
func (s *LinuxSandbox) provisionUplink(sessionID, ns string) error {
	idx, err := s.uplinks.alloc(sessionID)
	if err != nil {
		return &BackendError{Msg: err.Error()}
	}
	hostCIDR, nsCIDR, gateway := uplinkSubnet(idx)
	hostIf := fmt.Sprintf("wdn%d", idx)

	steps := [][]string{
		{"ip", "link", "add", hostIf, "type", "veth", "peer", "name", "uplink", "netns", ns},
		{"ip", "addr", "add", hostCIDR, "dev", hostIf},
		{"ip", "link", "set", hostIf, "up"},
		{"ip", "netns", "exec", ns, "ip", "addr", "add", nsCIDR, "dev", "uplink"},
		{"ip", "netns", "exec", ns, "ip", "link", "set", "uplink", "up"},
		{"ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gateway},
		{"ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
	}
	for _, args := range steps {
		if err := run(args); err != nil {
			s.uplinks.free(sessionID)
			return err
		}
	}
	return nil
}

// run executes one provisioning command, wrapping failure stderr in
// BackendError — the same reporting shape as the namespace/nft shell-outs
// above.
func run(args []string) error {
	//nolint:gosec // G204: argv varies only in the netnsName-derived namespace and allocator-derived interface/addresses — same Amendment 8 shell-out budget as the sites above
	cmd := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &BackendError{Msg: fmt.Sprintf("%s failed: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))}
		}
		return &BackendError{Msg: fmt.Sprintf("%s: %v", strings.Join(args, " "), err)}
	}
	return nil
}

// applyRulesetInNS pipes the ruleset into `nft -f -` executing inside
// namespace ns.
func applyRulesetInNS(ns, script string) error {
	//nolint:gosec // G204: namespace name derives from session_id, mirrors Rust sandbox_controller.rs:159 — parity-preserving by design
	cmd := exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &BackendError{Msg: fmt.Sprintf("nft -f failed: %s", strings.TrimSpace(stderr.String()))}
		}
		return &BackendError{Msg: fmt.Sprintf("ip netns exec nft: %v", err)}
	}
	return nil
}

// netnsName is the namespace name for a session. Mirrors ruleset.tableName
// so operators can correlate a namespace with its nftables tables by name.
func netnsName(sessionID string) string {
	return "warden_" + strings.ReplaceAll(sessionID, "-", "_")
}
