package breachevent

import (
	"strings"
	"testing"
	"time"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/signingkey"
)

func makeKey(t *testing.T) *signingkey.Record {
	t.Helper()
	key, err := signingkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func makeEvent(key *signingkey.Record) *Event {
	return New(
		"sess-test-001",
		"agent-test-001",
		"attempted connection to 1.2.3.4:443 not in targets allowlist",
		key.KeyID(),
	)
}

func mustSign(t *testing.T, event *Event, key *signingkey.Record) {
	t.Helper()
	if err := event.Sign(key.SigningKey()); err != nil {
		t.Fatal(err)
	}
}

// ── Construction (ledger: breach_event::*) ──────────────────────────────────

func TestNewEventSetsLayerToNetwork(t *testing.T) {
	if event := makeEvent(makeKey(t)); event.Layer != "network" {
		t.Fatalf("layer = %q, want %q", event.Layer, "network")
	}
}

func TestNewEventSetsAttesterToWardenEnforcer(t *testing.T) {
	if event := makeEvent(makeKey(t)); event.Attester != "warden-enforcer" {
		t.Fatalf("attester = %q, want %q", event.Attester, "warden-enforcer")
	}
}

func TestNewEventSetsTokenClaimToTargets(t *testing.T) {
	if event := makeEvent(makeKey(t)); event.TokenClaim != "targets" {
		t.Fatalf("token_claim = %q, want %q", event.TokenClaim, "targets")
	}
}

func TestNewEventGeneratesNonEmptyBreachID(t *testing.T) {
	if event := makeEvent(makeKey(t)); event.BreachID == "" {
		t.Fatal("breach_id must not be empty")
	}
}

func TestTwoNewEventsHaveDistinctBreachIDs(t *testing.T) {
	key := makeKey(t)
	e1, e2 := makeEvent(key), makeEvent(key)
	if e1.BreachID == e2.BreachID {
		t.Fatal("breach_ids must be distinct")
	}
}

func TestNewEventHasEmptySignatureBeforeSigning(t *testing.T) {
	if event := makeEvent(makeKey(t)); event.Signature != "" {
		t.Fatal("signature must be empty before signing")
	}
}

// ── Signing and verification ─────────────────────────────────────────────────

func TestSigningPopulatesNonEmptySignature(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)
	if event.Signature == "" {
		t.Fatal("signature must be populated after signing")
	}
}

func TestSignedEventVerifiesWithCorrectKey(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)
	if !event.Verify(key.VerifyingKey()) {
		t.Fatal("signed event must verify with the signing key")
	}
}

func TestTamperedViolationFailsVerification(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)

	event.Violation = "tampered violation text"

	if event.Verify(key.VerifyingKey()) {
		t.Fatal("tampered violation must fail verification")
	}
}

func TestTamperedSessionIDFailsVerification(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)

	event.SessionID = "attacker-controlled-session"

	if event.Verify(key.VerifyingKey()) {
		t.Fatal("tampered session_id must fail verification")
	}
}

func TestWrongKeyFailsVerification(t *testing.T) {
	key := makeKey(t)
	otherKey := makeKey(t)

	event := makeEvent(key)
	mustSign(t, event, key)

	if event.Verify(otherKey.VerifyingKey()) {
		t.Fatal("event must not verify under a different key")
	}
}

// ── Rekor payload ────────────────────────────────────────────────────────────

func TestRekorPayloadExcludesViolation(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)
	if _, ok := event.RekorPayload()["violation"]; ok {
		t.Fatal("rekor payload must not contain violation")
	}
}

func TestRekorPayloadExcludesTokenClaim(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)
	if _, ok := event.RekorPayload()["token_claim"]; ok {
		t.Fatal("rekor payload must not contain token_claim")
	}
}

func TestRekorPayloadIncludesBreachID(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)
	if got := event.RekorPayload()["breach_id"]; got != event.BreachID {
		t.Fatalf("rekor payload breach_id = %v, want %q", got, event.BreachID)
	}
}

func TestRekorPayloadIncludesSignature(t *testing.T) {
	key := makeKey(t)
	event := makeEvent(key)
	mustSign(t, event, key)
	if got := event.RekorPayload()["signature"]; got != event.Signature {
		t.Fatalf("rekor payload signature = %v, want %q", got, event.Signature)
	}
}

func TestFullEventIncludesViolation(t *testing.T) {
	event := makeEvent(makeKey(t))
	if event.Violation == "" {
		t.Fatal("violation must not be empty")
	}
	if !strings.Contains(event.Violation, "1.2.3.4") {
		t.Fatalf("violation %q must contain the target address", event.Violation)
	}
}

// ── Timestamp format (not a ledger row — pins the fixture rendering) ─────────

func TestTimestampLayoutRendersFixtureInstant(t *testing.T) {
	instant := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	if got := instant.Format(timestampLayout); got != "2026-06-30T00:00:00+00:00" {
		t.Fatalf("timestamp layout rendered %q, want %q", got, "2026-06-30T00:00:00+00:00")
	}
}
