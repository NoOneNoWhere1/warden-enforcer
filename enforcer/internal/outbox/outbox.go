// Package outbox is the enforcer's durable attestation record: an
// append-only JSONL spool written (and fsync'd) BEFORE any Rekor attempt,
// plus a submitter that drains it into Rekor behind an fsync'd checkpoint
// watermark. The enforcer writes only this JSONL spool; a separate
// DB-speaking component is expected to ingest it into attestation_outbox —
// the enforcer stays DB-free.
package outbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/canonical"
)

// Entry is one spool line. Self-contained on purpose: the second signature
// and public key are captured at sign time under the AppState lock, so the
// submitter can replay entries signed under since-retired keys without ever
// touching a private key.
type Entry struct {
	Event breachevent.Event `json:"event"`
	// SecondSig is base64url Ed25519 over canonical(RekorPayload()). The
	// primary event signature (Event.Signature) and the conformance vector
	// are untouched; SecondSig is a separate signature over the Rekor payload.
	SecondSig string `json:"second_sig"`
	// PublicKeyPEM is the PKIX PEM of the key that made SecondSig.
	PublicKeyPEM string `json:"public_key_pem"`
	// PayloadSHA256 is the content-addressed idempotency key: hex
	// sha256(canonical(RekorPayload())), identical to the data hash Rekor
	// stores for the entry.
	PayloadSHA256 string `json:"payload_sha256"`
}

// ReducedPayload recomputes the canonical Rekor content for this entry —
// deterministic from the event, no key required.
func (e *Entry) ReducedPayload() ([]byte, error) {
	return canonical.ToCanonicalBytes(e.Event.RekorPayload())
}

type Spool struct {
	f    *os.File
	path string
}

// Open creates (0700 dir, 0600 file) or opens the spool for appending. A
// torn tail line from a crash mid-append is truncated away: it was never
// fsync-acknowledged, so dropping it is the write-ahead contract, and
// leaving it would corrupt every later append.
func Open(path string) (*Spool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := truncateTornTail(path); err != nil {
		return nil, err
	}
	//nolint:gosec // G304: path is operator-configured (ENFORCER_OUTBOX), not request-derived
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Spool{f: f, path: path}, nil
}

// Append writes one entry line and fsyncs before returning — the caller may
// only attempt Rekor submission after Append succeeds (write-ahead).
func (s *Spool) Append(e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return err
	}
	return s.f.Sync()
}

func (s *Spool) Close() error { return s.f.Close() }

// Record is an Entry plus the offset of the line after it — the checkpoint
// value once this entry is submitted.
type Record struct {
	Entry   Entry
	NextOff int64
}

// ReadFrom returns all complete entries starting at byte offset off. An
// unparseable line stops the read at that line (never skips past it) so a
// corrupt entry is investigated, not silently dropped.
func (s *Spool) ReadFrom(off int64) ([]Record, error) {
	//nolint:gosec // G304: same operator-configured spool path as Open
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}

	var recs []Record
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil { // io.EOF with a partial line = torn tail; not readable yet
			return recs, nil
		}
		var e Entry
		if jerr := json.Unmarshal(line, &e); jerr != nil {
			return recs, fmt.Errorf("corrupt spool line at offset %d: %w", off, jerr)
		}
		off += int64(len(line))
		recs = append(recs, Record{Entry: e, NextOff: off})
	}
}

func (s *Spool) checkpointPath() string { return s.path + ".checkpoint" }

// Checkpoint returns the byte offset up to which every entry has been
// accepted by Rekor. Missing file = 0 (nothing submitted).
func (s *Spool) Checkpoint() (int64, error) {
	//nolint:gosec // G304: same operator-configured spool path as Open
	raw, err := os.ReadFile(s.checkpointPath())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	off, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("corrupt checkpoint %q: %w", raw, err)
	}
	return off, nil
}

// SetCheckpoint durably records the watermark: write temp, fsync, rename.
// A crash between fsync'd spool append and checkpoint advance replays the
// entry on restart — Rekor's 409-on-duplicate makes that a no-op.
func (s *Spool) SetCheckpoint(off int64) error {
	tmp := s.checkpointPath() + ".tmp"
	//nolint:gosec // G304: same operator-configured spool path as Open
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strconv.FormatInt(off, 10)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.checkpointPath())
}

// truncateTornTail cuts the spool back to its last complete line.
// Reads the whole file; the spool never rotates in v1 — add
// rotation + a tail-window scan when ops needs it.
func truncateTornTail(path string) error {
	//nolint:gosec // G304: same operator-configured spool path as Open
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		return nil
	}
	last := bytes.LastIndexByte(raw, '\n')
	return os.Truncate(path, int64(last+1))
}

// SubmitFunc posts one entry's reduced payload + second signature + public
// key to the transparency log, returning the log's entry ID. rekor.Client
// satisfies this; tests use httptest-backed stubs.
type SubmitFunc func(content, signature, publicKeyPEM []byte) (string, error)

// Run drains the spool into the log from the checkpoint watermark until ctx
// is done. kick (cap-1, non-blocking senders) wakes it when the consumer
// appends; after a failure it retries with capped exponential backoff. The
// watermark advances (fsync'd) after every accepted entry, so a restart
// resumes exactly where acceptance stopped.
func Run(ctx context.Context, sp *Spool, submit SubmitFunc, kick <-chan struct{}) {
	const (
		backoffMin = time.Second
		backoffMax = 30 * time.Second
	)
	backoff := backoffMin

	off, err := sp.Checkpoint()
	if err != nil {
		fmt.Fprintf(os.Stderr, "outbox: %v — replaying from 0 (duplicates are 409-safe)\n", err)
	}

	for {
		newOff, ok := drainOnce(sp, submit, off)
		off = newOff
		if ok {
			backoff = backoffMin
			select {
			case <-ctx.Done():
				return
			case <-kick:
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			backoff = min(backoff*2, backoffMax)
		}
	}
}

// drainOnce submits every pending entry, checkpointing after each. Returns
// the new watermark and false if a submission failed (caller backs off).
func drainOnce(sp *Spool, submit SubmitFunc, off int64) (int64, bool) {
	recs, err := sp.ReadFrom(off)
	if err != nil {
		fmt.Fprintf(os.Stderr, "outbox: read: %v\n", err)
		return off, false
	}
	for _, r := range recs {
		reduced, err := r.Entry.ReducedPayload()
		if err != nil {
			fmt.Fprintf(os.Stderr, "outbox: entry at %d unrenderable: %v\n", r.NextOff, err)
			return off, false
		}
		sig, err := base64.RawURLEncoding.DecodeString(r.Entry.SecondSig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "outbox: entry at %d bad signature encoding: %v\n", r.NextOff, err)
			return off, false
		}
		if _, err := submit(reduced, sig, []byte(r.Entry.PublicKeyPEM)); err != nil {
			fmt.Fprintf(os.Stderr, "outbox: submit: %v\n", err)
			return off, false
		}
		off = r.NextOff
		if err := sp.SetCheckpoint(off); err != nil {
			fmt.Fprintf(os.Stderr, "outbox: checkpoint: %v\n", err)
			return off, false
		}
	}
	return off, true
}
