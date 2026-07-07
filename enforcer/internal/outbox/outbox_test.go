package outbox

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/canonical"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/signingkey"
)

func testEntry(t *testing.T, violation string) Entry {
	t.Helper()
	rec, err := signingkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ev := breachevent.New("sess-outbox", "agent-outbox", violation, rec.KeyID())
	if err := ev.Sign(rec.SigningKey()); err != nil {
		t.Fatal(err)
	}
	reduced, err := canonical.ToCanonicalBytes(ev.RekorPayload())
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(rec.SigningKey(), reduced)
	return Entry{
		Event:        *ev,
		SecondSig:    base64.RawURLEncoding.EncodeToString(sig),
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
	}
}

func openTestSpool(t *testing.T) *Spool {
	t.Helper()
	sp, err := Open(filepath.Join(t.TempDir(), "outbox.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	return sp
}

func TestAppendReadFromRoundTripsWithOffsets(t *testing.T) {
	sp := openTestSpool(t)
	e1, e2 := testEntry(t, "first"), testEntry(t, "second")
	if err := sp.Append(e1); err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(e2); err != nil {
		t.Fatal(err)
	}

	recs, err := sp.ReadFrom(0)
	if err != nil || len(recs) != 2 {
		t.Fatalf("got %d records (err=%v), want 2", len(recs), err)
	}
	if recs[0].Entry.Event.Violation != "first" || recs[1].Entry.Event.Violation != "second" {
		t.Fatal("entries must round-trip in order")
	}

	// Reading from the first record's NextOff yields only the second.
	tail, err := sp.ReadFrom(recs[0].NextOff)
	if err != nil || len(tail) != 1 || tail[0].Entry.Event.Violation != "second" {
		t.Fatalf("offset read broken: %d records (err=%v)", len(tail), err)
	}
}

func TestCheckpointRoundTripsAndDefaultsToZero(t *testing.T) {
	sp := openTestSpool(t)
	if off, err := sp.Checkpoint(); err != nil || off != 0 {
		t.Fatalf("fresh checkpoint = %d (err=%v), want 0", off, err)
	}
	if err := sp.SetCheckpoint(1234); err != nil {
		t.Fatal(err)
	}
	if off, err := sp.Checkpoint(); err != nil || off != 1234 {
		t.Fatalf("checkpoint = %d (err=%v), want 1234", off, err)
	}
}

func TestOpenTruncatesTornTailLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.jsonl")
	sp, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(testEntry(t, "complete")); err != nil {
		t.Fatal(err)
	}
	_ = sp.Close()

	// Simulate a crash mid-append: a partial line without trailing newline.
	//nolint:gosec // G304: t.TempDir()-derived path in a test
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"event":{"agent`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	sp, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()

	recs, err := sp.ReadFrom(0)
	if err != nil {
		t.Fatalf("torn tail must be truncated at open, got read error: %v", err)
	}
	if len(recs) != 1 || recs[0].Entry.Event.Violation != "complete" {
		t.Fatalf("expected the 1 complete entry to survive, got %d", len(recs))
	}
	// And the spool must be appendable again on a clean boundary.
	if err := sp.Append(testEntry(t, "after-recovery")); err != nil {
		t.Fatal(err)
	}
	recs, _ = sp.ReadFrom(0)
	if len(recs) != 2 {
		t.Fatalf("append after recovery: got %d entries, want 2", len(recs))
	}
}

func TestDrainOnceSubmitsAllAndCheckpointsEach(t *testing.T) {
	sp := openTestSpool(t)
	for _, v := range []string{"a", "b", "c"} {
		if err := sp.Append(testEntry(t, v)); err != nil {
			t.Fatal(err)
		}
	}

	var submitted int
	off, ok := drainOnce(sp, func(content, sig, pem []byte) (string, error) {
		submitted++
		return "uuid", nil
	}, 0)
	if !ok || submitted != 3 {
		t.Fatalf("drainOnce ok=%v submitted=%d, want true/3", ok, submitted)
	}
	if cp, _ := sp.Checkpoint(); cp != off || cp == 0 {
		t.Fatalf("checkpoint %d must equal returned offset %d (non-zero)", cp, off)
	}

	// Replay from the checkpoint submits nothing — restart is idempotent.
	submitted = 0
	if _, ok := drainOnce(sp, func(_, _, _ []byte) (string, error) {
		submitted++
		return "uuid", nil
	}, off); !ok || submitted != 0 {
		t.Fatalf("replay after checkpoint: ok=%v submitted=%d, want true/0", ok, submitted)
	}
}

func TestDrainOnceStopsAtFailureAndKeepsWatermark(t *testing.T) {
	sp := openTestSpool(t)
	for _, v := range []string{"a", "b"} {
		if err := sp.Append(testEntry(t, v)); err != nil {
			t.Fatal(err)
		}
	}

	calls := 0
	off, ok := drainOnce(sp, func(_, _, _ []byte) (string, error) {
		calls++
		if calls == 2 {
			return "", os.ErrDeadlineExceeded // any error: Rekor down
		}
		return "uuid", nil
	}, 0)
	if ok {
		t.Fatal("failed submission must report not-ok")
	}
	// First entry accepted and checkpointed; second stays pending.
	recs, _ := sp.ReadFrom(off)
	if len(recs) != 1 || recs[0].Entry.Event.Violation != "b" {
		t.Fatalf("expected exactly the failed entry pending, got %d", len(recs))
	}
}

func TestRunDrainsOnKickAndStopsOnCancel(t *testing.T) {
	sp := openTestSpool(t)
	if err := sp.Append(testEntry(t, "kicked")); err != nil {
		t.Fatal(err)
	}

	submitted := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(context.Background())
	kick := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Run(ctx, sp, func(_, _, _ []byte) (string, error) {
			submitted <- struct{}{}
			return "uuid", nil
		}, kick)
	}()

	select { // initial drain, no kick needed
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must drain pending entries at startup")
	}

	if err := sp.Append(testEntry(t, "second")); err != nil {
		t.Fatal(err)
	}
	kick <- struct{}{}
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must drain after a kick")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run must return on ctx cancel")
	}
}
