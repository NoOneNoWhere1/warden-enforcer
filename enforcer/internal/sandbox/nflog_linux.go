//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/vishvananda/netns"
)

// nflogGroup matches the `log group 1` statements ruleset.Render emits.
// Group numbers are per-netns, so a fixed group cannot collide across
// sessions.
const nflogGroup = 1

// startDropListener opens an NFLOG socket inside the session's network
// namespace and forwards parsed packet facts to s.drops. NFLOG delivery is
// per-netns, so the socket must live where the rules fire — this reverses
// M13's "no Go code inside the netns" decision exactly as that plan
// anticipated.
//
// The returned stop func cancels the listener and WAITS for it to release
// the namespace: the nflog socket and the listener thread's current netns
// both hold kernel references, and `ip netns del` only unlinks the name — a
// still-referenced namespace (and its veth pair) would outlive the session.
// The caller invokes stop under the AppState lock on the controller thread
// (Amendment 6 — no lock here). Send is non-blocking: a full channel
// increments dropOverflow instead of stalling the socket reader
// (attestation is best-effort with a visible loss counter; containment
// never depends on this path).
func (s *LinuxSandbox) startDropListener(sessionID, ns string, lost *atomic.Uint64) (func(), error) {
	nsh, err := netns.GetFromName(ns)
	if err != nil {
		return nil, &BackendError{Msg: fmt.Sprintf("netns handle %s: %v", ns, err)}
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan error, 1)
	done := make(chan struct{})

	go func() {
		defer close(done) // last: all namespace references below are released

		// The thread stays locked for the goroutine's lifetime and is
		// discarded by the runtime when it exits: netns.Set taints the
		// thread for every other goroutine.
		runtime.LockOSThread()
		defer func() { _ = nsh.Close() }()

		host, err := netns.Get()
		if err != nil {
			ready <- &BackendError{Msg: fmt.Sprintf("get host netns: %v", err)}
			return
		}
		// Leave the session netns before signalling done, so the thread no
		// longer pins it when stop returns.
		defer func() { _ = netns.Set(host); _ = host.Close() }()

		if err := netns.Set(nsh); err != nil {
			ready <- &BackendError{Msg: fmt.Sprintf("enter netns %s: %v", ns, err)}
			return
		}
		nf, err := nflog.Open(&nflog.Config{Group: nflogGroup, Copymode: nflog.CopyPacket})
		if err != nil {
			ready <- &BackendError{Msg: fmt.Sprintf("nflog open in %s: %v", ns, err)}
			return
		}
		defer func() { _ = nf.Close() }()

		hook := func(attrs nflog.Attribute) int {
			if attrs.Payload == nil {
				return 0
			}
			src, dst, port, proto, ok := parseDropPayload(*attrs.Payload)
			if !ok {
				return 0
			}
			// SessionID is the listener's own: one socket per netns, one
			// session per netns. The rule prefix ("warden:<sid>:") stays
			// operator-facing forensics.
			d := Drop{SessionID: sessionID, SrcIP: src, DstIP: dst, DstPort: port, Proto: proto, At: time.Now().UTC()}
			select {
			case s.drops <- d:
			default:
				lost.Add(1)
			}
			return 0
		}
		if err := nf.RegisterWithErrorFunc(ctx, hook, func(error) int { return 0 }); err != nil {
			ready <- &BackendError{Msg: fmt.Sprintf("nflog register in %s: %v", ns, err)}
			return
		}
		ready <- nil
		<-ctx.Done()
	}()

	if err := <-ready; err != nil {
		cancel()
		<-done
		return nil, err
	}
	return func() {
		cancel()
		<-done
	}, nil
}
