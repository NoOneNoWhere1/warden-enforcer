package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/outbox"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"
)

// fastClock advances one second per reading — each drop arrives with a full
// token-bucket refill, so tests exercising the ring (not admission) are
// never rate-limited.
func fastClock() func() time.Time {
	t := time.Now()
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func testDrop(sessionID string, dstPort uint16) sandbox.Drop {
	return sandbox.Drop{
		SessionID: sessionID,
		SrcIP:     netip.MustParseAddr("192.168.250.2"),
		DstIP:     netip.MustParseAddr("10.99.88.1"),
		DstPort:   dstPort,
		Proto:     "tcp",
		At:        time.Now().UTC(),
	}
}

func createTestSession(t *testing.T, state *AppState, sessionID string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/sessions", strings.NewReader(validCredential(sessionID)))
	w := httptest.NewRecorder()
	state.createSession(w, req)
	if w.Code != 201 {
		t.Fatalf("session create failed: %d %s", w.Code, w.Body.String())
	}
}

func TestRecordDropStoresOneVerifiableEvent(t *testing.T) {
	state := testState(t)
	createTestSession(t, state, "sess-e32")

	state.recordDrop(testDrop("sess-e32", 443))

	evs := state.Events["sess-e32"]
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.SessionID != "sess-e32" || ev.AgentID != "test-agent-001" || ev.Layer != "network" {
		t.Fatalf("wrong event identity: %+v", ev)
	}
	if ev.Violation != "attempted connection to 10.99.88.1:443" {
		t.Fatalf("wrong violation: %q", ev.Violation)
	}
	if !ev.Verify(state.ActiveKey.VerifyingKey()) {
		t.Fatal("stored event must verify against the active key")
	}
}

func TestRecordDropPortlessProtocolNamesProto(t *testing.T) {
	state := testState(t)
	createTestSession(t, state, "sess-e32-icmp")

	d := testDrop("sess-e32-icmp", 0)
	d.Proto = "icmp"
	state.recordDrop(d)

	if v := state.Events["sess-e32-icmp"][0].Violation; v != "attempted connection to 10.99.88.1 (icmp)" {
		t.Fatalf("wrong violation: %q", v)
	}
}

func TestRecordDropForUnknownSessionIsIgnored(t *testing.T) {
	state := testState(t)
	state.recordDrop(testDrop("never-created", 443))
	if len(state.Events["never-created"]) != 0 {
		t.Fatal("drop for unknown session must not create events")
	}
}

func TestEventsRingEvictsOldestAndCountsLoss(t *testing.T) {
	state := testState(t)
	state.Now = fastClock()
	createTestSession(t, state, "sess-ring")

	for port := 1; port <= eventsCap+3; port++ {
		state.recordDrop(testDrop("sess-ring", uint16(port)))
	}

	evs := state.Events["sess-ring"]
	if len(evs) != eventsCap {
		t.Fatalf("ring must cap at %d, got %d", eventsCap, len(evs))
	}
	if state.EventLosses["sess-ring"] != 3 {
		t.Fatalf("expected 3 counted losses, got %d", state.EventLosses["sess-ring"])
	}
	if got := evs[0].Violation; got != "attempted connection to 10.99.88.1:4" {
		t.Fatalf("oldest events must be evicted first; head is %q", got)
	}
	if got := evs[len(evs)-1].Violation; got != fmt.Sprintf("attempted connection to 10.99.88.1:%d", eventsCap+3) {
		t.Fatalf("newest event must be tail; tail is %q", got)
	}
}

func TestDeleteSessionClearsLossCounter(t *testing.T) {
	state := testState(t)
	state.Now = fastClock()
	createTestSession(t, state, "sess-clear")
	for port := 1; port <= eventsCap+1; port++ {
		state.recordDrop(testDrop("sess-clear", uint16(port)))
	}
	if state.EventLosses["sess-clear"] == 0 {
		t.Fatal("precondition: loss counted")
	}

	req := httptest.NewRequest("DELETE", "/sessions/sess-clear", nil)
	req.SetPathValue("id", "sess-clear")
	w := httptest.NewRecorder()
	state.deleteSession(w, req)
	if w.Code != 204 {
		t.Fatalf("delete failed: %d", w.Code)
	}
	if _, ok := state.EventLosses["sess-clear"]; ok {
		t.Fatal("loss counter must be cleared with the session")
	}
}

func TestConsumeDrainsChannelUntilClose(t *testing.T) {
	state := testState(t)
	createTestSession(t, state, "sess-chan")

	drops := make(chan sandbox.Drop, 4)
	drops <- testDrop("sess-chan", 80)
	drops <- testDrop("sess-chan", 8443)
	close(drops)

	state.ConsumeDrops(drops) // returns on close

	if len(state.Events["sess-chan"]) != 2 {
		t.Fatalf("expected 2 events, got %d", len(state.Events["sess-chan"]))
	}
}

// ── E3.3: admission control, loss surfacing, spool write-ahead ───────────────

func TestTokenBucketAdmitsBurstThenCountsLoss(t *testing.T) {
	state := testState(t) // real clock: instant drops get no meaningful refill
	createTestSession(t, state, "sess-burst")

	for port := 1; port <= int(bucketBurst)+1; port++ {
		state.recordDrop(testDrop("sess-burst", uint16(port))) //nolint:gosec // port ≤ 21
	}

	if got := len(state.Events["sess-burst"]); got != int(bucketBurst) {
		t.Fatalf("expected %d admitted events, got %d", int(bucketBurst), got)
	}
	if state.EventLosses["sess-burst"] == 0 {
		t.Fatal("over-burst drop must be counted as a loss")
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	state := testState(t)
	state.Now = fastClock() // +1s per drop → refill outpaces spend
	createTestSession(t, state, "sess-refill")

	for port := 1; port <= 40; port++ {
		state.recordDrop(testDrop("sess-refill", uint16(port))) //nolint:gosec // port ≤ 40
	}
	if got := len(state.Events["sess-refill"]); got != 40 {
		t.Fatalf("refilled bucket must admit all 40 spaced drops, got %d", got)
	}
}

func TestLostEventsHeaderSurfacesLosses(t *testing.T) {
	state := testState(t)
	createTestSession(t, state, "sess-hdr")

	for port := 1; port <= int(bucketBurst)+3; port++ {
		state.recordDrop(testDrop("sess-hdr", uint16(port))) //nolint:gosec // port ≤ 23
	}

	rec := do(state, http.MethodGet, "/sessions/sess-hdr/events", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	want := strconv.FormatUint(state.EventLosses["sess-hdr"], 10)
	if got := rec.Header().Get("X-Warden-Lost-Events"); got != want || got == "0" {
		t.Fatalf("X-Warden-Lost-Events = %q, want %q (non-zero)", got, want)
	}
}

func TestConsumeDropsWritesSpoolEntryWithVerifiableSecondSignature(t *testing.T) {
	state := testState(t)
	sp, err := outbox.Open(filepath.Join(t.TempDir(), "outbox.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	state.Outbox = sp
	createTestSession(t, state, "sess-spool")

	drops := make(chan sandbox.Drop, 1)
	drops <- testDrop("sess-spool", 443)
	close(drops)
	state.ConsumeDrops(drops)

	recs, err := sp.ReadFrom(0)
	if err != nil || len(recs) != 1 {
		t.Fatalf("expected 1 spool record, got %d (err=%v)", len(recs), err)
	}
	e := recs[0].Entry
	reduced, err := e.ReducedPayload()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(reduced)
	if e.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("payload_sha256 must be the content-addressed hash of the reduced payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.SecondSig)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(e.PublicKeyPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub.(ed25519.PublicKey), reduced, sig) {
		t.Fatal("second signature must verify over the reduced payload under the stored key")
	}
	if !e.Event.Verify(state.ActiveKey.VerifyingKey()) {
		t.Fatal("primary event signature must still verify")
	}
}
