package main

import (
	"os"
	"path/filepath"
	"testing"
)

func socketPath(t *testing.T) string {
	t.Helper()
	// Not t.TempDir(): unix socket paths are capped at 104 bytes on macOS
	// (sun_path), and t.TempDir() embeds the test name and exceeds that.
	dir, err := os.MkdirTemp("/tmp", "wrdn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "warden-enforcer", "api.sock")
}

func TestListenCreatesSocket(t *testing.T) {
	path := socketPath(t)
	listener, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket not created: %v", err)
	}
}

func TestListenRemovesStaleSocket(t *testing.T) {
	path := socketPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// A leftover file at the socket path makes bind fail with "address
	// already in use" unless listen clears it first.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	listener, err := listen(path)
	if err != nil {
		t.Fatalf("listen did not recover from stale socket: %v", err)
	}
	_ = listener.Close()
}

func TestListenSetsDirMode0700(t *testing.T) {
	path := socketPath(t)
	listener, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", perm)
	}
}

func TestListenSetsSocketMode0660(t *testing.T) {
	path := socketPath(t)
	listener, err := listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket mode = %o, want 0660", perm)
	}
}
