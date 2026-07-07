// Cross-language conformance test for breach-event signing.
//
// Pins the canonicalization (RFC 8785 / JCS) and the resulting Ed25519
// signature against a frozen vector. The Python MCP server and .NET API ship
// the same vector in their own test suites; if any runtime drifts on key
// ordering, escaping, or number formatting, this test (and its siblings) fail
// before a signed event can become unverifiable in production.
//
// External test package on purpose: like Rust's tests/conformance.rs it
// exercises only the public API, exactly as a downstream verifier would.
package breachevent_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/canonical"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/signingkey"
)

type vector struct {
	PrivateKeySeedHex string            `json:"private_key_seed_hex"`
	PublicKeyB64URL   string            `json:"public_key_b64url"`
	Event             breachevent.Event `json:"event"`
	CanonicalJSON     string            `json:"canonical_json"`
	SignatureB64URL   string            `json:"signature_b64url"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile("../../tests/conformance/breach_event_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func seedFromHex(t *testing.T, hexSeed string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(hexSeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Fatalf("seed is %d bytes, want 32", len(raw))
	}
	var seed [32]byte
	copy(seed[:], raw)
	return seed
}

// Ledger: conformance::canonical_json_matches_frozen_vector
func TestCanonicalJSONMatchesFrozenVector(t *testing.T) {
	v := loadVector(t)

	raw, err := json.Marshal(v.Event)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "signature")

	canon, err := canonical.ToCanonicalBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	if string(canon) != v.CanonicalJSON {
		t.Fatalf("canonical bytes diverge from frozen vector\n got: %s\nwant: %s", canon, v.CanonicalJSON)
	}
}

// Ledger: conformance::signature_matches_frozen_vector
func TestSignatureMatchesFrozenVector(t *testing.T) {
	v := loadVector(t)
	seed := seedFromHex(t, v.PrivateKeySeedHex)
	key, err := signingkey.Load(v.Event.AttesterKeyID, &seed)
	if err != nil {
		t.Fatal(err)
	}

	event := v.Event
	event.Signature = ""
	if err := event.Sign(key.SigningKey()); err != nil {
		t.Fatal(err)
	}

	if event.Signature != v.SignatureB64URL {
		t.Fatalf("signature diverges from frozen vector\n got: %s\nwant: %s", event.Signature, v.SignatureB64URL)
	}
}

// Ledger: conformance::frozen_public_key_matches_seed
func TestFrozenPublicKeyMatchesSeed(t *testing.T) {
	v := loadVector(t)
	seed := seedFromHex(t, v.PrivateKeySeedHex)
	key, err := signingkey.Load("k", &seed)
	if err != nil {
		t.Fatal(err)
	}

	pubk := base64.RawURLEncoding.EncodeToString(key.VerifyingKey())
	if pubk != v.PublicKeyB64URL {
		t.Fatalf("public key diverges from frozen vector\n got: %s\nwant: %s", pubk, v.PublicKeyB64URL)
	}
}

// Ledger: conformance::frozen_signature_verifies_against_frozen_event
func TestFrozenSignatureVerifiesAgainstFrozenEvent(t *testing.T) {
	// The exact bytes a downstream verifier receives: deserialize the event
	// (with its signature) and confirm it verifies under the published key.
	v := loadVector(t)
	seed := seedFromHex(t, v.PrivateKeySeedHex)
	key, err := signingkey.Load("k", &seed)
	if err != nil {
		t.Fatal(err)
	}

	if !v.Event.Verify(key.VerifyingKey()) {
		t.Fatal("frozen signature must verify against the frozen event")
	}
}
