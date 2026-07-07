package signingkey

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func mustGenerate(t *testing.T) *Record {
	t.Helper()
	r, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ── Key generation (ledger: signing_key::*) ─────────────────────────────────

func TestGeneratedKeyHasNonEmptyKeyID(t *testing.T) {
	if mustGenerate(t).KeyID() == "" {
		t.Fatal("key_id must not be empty")
	}
}

func TestTwoGeneratedKeysHaveDistinctKeyIDs(t *testing.T) {
	k1, k2 := mustGenerate(t), mustGenerate(t)
	if k1.KeyID() == k2.KeyID() {
		t.Fatal("key_ids must be distinct")
	}
}

func TestTwoGeneratedKeysHaveDistinctPublicKeys(t *testing.T) {
	k1, k2 := mustGenerate(t), mustGenerate(t)
	if bytes.Equal(k1.VerifyingKey(), k2.VerifyingKey()) {
		t.Fatal("public keys must be distinct")
	}
}

func TestNewKeyIsNotRetired(t *testing.T) {
	key := mustGenerate(t)
	if key.RetiredAt() != "" {
		t.Fatal("new key must have no retired_at")
	}
	if !key.IsActive() {
		t.Fatal("new key must be active")
	}
}

// ── Key lifecycle ────────────────────────────────────────────────────────────

func TestRetiringKeySetsRetiredAt(t *testing.T) {
	key := mustGenerate(t)
	if !key.IsActive() {
		t.Fatal("expected active before retire")
	}
	key.Retire("2026-06-29T00:00:00Z")
	if key.RetiredAt() == "" {
		t.Fatal("retired_at must be set")
	}
	if key.IsActive() {
		t.Fatal("retired key must not be active")
	}
}

func TestPrivateKeyBytesRoundtripPreservesPublicKey(t *testing.T) {
	original := mustGenerate(t)
	seed := original.PrivateKeyBytes()

	loaded, err := Load(original.KeyID(), &seed)
	if err != nil {
		t.Fatalf("load must succeed with valid key bytes: %v", err)
	}
	if !bytes.Equal(original.VerifyingKey(), loaded.VerifyingKey()) {
		t.Fatal("public key must survive the byte roundtrip")
	}
}

func TestKeyIDPreservedThroughByteRoundtrip(t *testing.T) {
	original := mustGenerate(t)
	seed := original.PrivateKeyBytes()

	loaded, err := Load(original.KeyID(), &seed)
	if err != nil {
		t.Fatal(err)
	}
	if original.KeyID() != loaded.KeyID() {
		t.Fatal("key_id must be preserved")
	}
}

// ── JWK serialization ────────────────────────────────────────────────────────

func TestJWKKtyIsOKP(t *testing.T) {
	if mustGenerate(t).PublicKeyJWK()["kty"] != "OKP" {
		t.Fatal("kty must be OKP")
	}
}

func TestJWKCrvIsEd25519(t *testing.T) {
	if mustGenerate(t).PublicKeyJWK()["crv"] != "Ed25519" {
		t.Fatal("crv must be Ed25519")
	}
}

func TestJWKXDecodesToMatchingPublicKeyBytes(t *testing.T) {
	key := mustGenerate(t)
	jwk := key.PublicKeyJWK()

	x, ok := jwk["x"].(string)
	if !ok {
		t.Fatal("x must be a string")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		t.Fatalf("x must be valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("Ed25519 public key is always 32 bytes, got %d", len(decoded))
	}
	if !bytes.Equal(decoded, key.VerifyingKey()) {
		t.Fatal("decoded x must match the raw public key bytes")
	}
}

// ── Go-only parity guards ────────────────────────────────────────────────────

func TestJWKByteGoldenForFixedSeed(t *testing.T) {
	// Wire bytes captured from the Rust implementation for the conformance
	// fixture seed: key order is alphabetical (serde_json without
	// preserve_order). A struct in declaration order would diverge.
	seedHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	golden := `{"crv":"Ed25519","kty":"OKP","x":"ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"}`

	raw, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	var seed [32]byte
	copy(seed[:], raw)

	key, err := Load("key-conformance-001", &seed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(key.PublicKeyJWK())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != golden {
		t.Fatalf("JWK wire bytes diverge from Rust:\n got: %s\nwant: %s", got, golden)
	}
}
