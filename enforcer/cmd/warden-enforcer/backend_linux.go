//go:build linux

package main

import "github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"

// newBackend mirrors main.rs:37-38: the production Linux backend. drops
// carries packet facts from the per-session nflog listeners to the single
// consumer goroutine.
func newBackend(drops chan<- sandbox.Drop) sandbox.Backend {
	return sandbox.NewLinuxSandbox(drops)
}
