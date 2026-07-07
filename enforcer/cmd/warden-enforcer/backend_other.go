//go:build !linux

package main

import "github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"

// newBackend mirrors main.rs:39-40: the no-op backend on non-Linux hosts,
// used for local development and the smoke test. The no-op backend starts
// no listeners, so drops stays silent.
func newBackend(chan<- sandbox.Drop) sandbox.Backend {
	return sandbox.NoopBackend{}
}
