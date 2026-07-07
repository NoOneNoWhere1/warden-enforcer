// warden-enforcer mirrors enforcer/src/main.rs: serve the enforcer API on a
// unix socket, with the sandbox backend selected at build time.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/api"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/config"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/outbox"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/rekor"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		fatal("fatal: %v", err)
	}

	// Bounded raw-drop channel (E3.2): listeners send packet facts,
	// non-blocking; the single consumer below signs under the AppState lock.
	drops := make(chan sandbox.Drop, 256)

	// Durable attestation spool (E3.3), write-ahead of Rekor. Fail closed:
	// an enforcer that cannot durably record breaches must not run.
	spool, err := outbox.Open(cfg.OutboxPath)
	if err != nil {
		fatal("fatal: outbox: %v", err)
	}
	kick := make(chan struct{}, 1)

	state := &api.AppState{
		ActiveKey:   cfg.SigningKey,
		Sessions:    map[string]api.Credential{},
		Events:      map[string][]breachevent.Event{},
		EventLosses: map[string]uint64{},
		Sandbox:     sandbox.NewController(newBackend(drops)),
		Outbox:      spool,
		OutboxKick:  kick,
	}
	go state.ConsumeDrops(drops)

	if cfg.RekorURL != "" {
		client := rekor.New(cfg.RekorURL)
		go outbox.Run(context.Background(), spool, client.Submit, kick)
		fmt.Fprintf(os.Stderr, "warden-enforcer submitting attestations to %s\n", cfg.RekorURL)
	}

	listener, err := listen(cfg.SocketPath)
	if err != nil {
		fatal("fatal: %v", err)
	}

	fmt.Fprintf(os.Stderr, "warden-enforcer listening on %s\n", cfg.SocketPath)

	// http.Serve accepts in a loop, serving each connection on its own
	// goroutine and retrying temporary accept errors — the Go equivalent of
	// main.rs:82-100.
	//nolint:gosec // G114: no server timeouts mirrors main.rs:82-100 (hyper serve loop sets none) — parity-preserving
	if err := http.Serve(listener, api.Router(state)); err != nil {
		fatal("fatal: serve: %v", err)
	}
}

// listen prepares the unix socket exactly as main.rs:51-78 does: lock the
// socket directory to the owner, clear any stale socket left by a previous
// crash, bind, then open the socket to owner and group.
func listen(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dir, err)
	}
	// The socket is the entire authentication boundary (E2): any process
	// that can connect can create or destroy sessions. Lock the directory
	// to the owner so only the warden user/group can even reach the socket.
	//nolint:gosec // G302: dir mode 0700 mirrors main.rs:59 — parity-preserving
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot secure %s: %w", dir, err)
	}

	// Remove a stale socket left by a previous crash.
	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot bind %s: %w", socketPath, err)
	}

	// 0660: owner (warden) and group (warden) may connect; everyone else
	// gets EACCES. Ownership is set by the systemd unit running as
	// warden:warden.
	//nolint:gosec // G306: socket mode 0660 mirrors main.rs:75 — parity-preserving
	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("cannot secure %s: %w", socketPath, err)
	}

	return listener, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
