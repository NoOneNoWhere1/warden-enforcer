// Package signingkey mirrors enforcer/src/signing_key.rs: a single enforcer
// signing key with its full lifecycle state.
//
// Keys are never deleted. When rotated, retiredAt is set on the old record
// so breach events signed under it remain verifiable indefinitely.
package signingkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
)

type Record struct {
	keyID string
	priv  ed25519.PrivateKey
	// PARITY: signing_key.rs sets created_at to now even in load() (a load
	// quirk carried verbatim). The field is used when persisting to the
	// signing_key table and is never serialized in any API response.
	createdAt string //nolint:unused // parity with Rust #[allow(dead_code)]
	retiredAt string // empty = active
}

// Generate creates a new Ed25519 keypair with a fresh key_id.
// The private key bytes must be persisted to the operator-managed
// secret store immediately after this call.
func Generate() (*Record, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Record{
		keyID:     uuid.NewString(),
		priv:      priv,
		createdAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Load reconstructs a key record from a persisted private key seed.
// Used on enforcer restart — does NOT generate a new key.
func Load(keyID string, privateKeyBytes *[32]byte) (*Record, error) {
	return &Record{
		keyID:     keyID,
		priv:      ed25519.NewKeyFromSeed(privateKeyBytes[:]),
		createdAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Retire marks this key as retired at the given timestamp.
// The record is kept so historical breach events remain verifiable.
func (r *Record) Retire(retiredAt string) {
	r.retiredAt = retiredAt
}

func (r *Record) KeyID() string {
	return r.keyID
}

func (r *Record) IsActive() bool {
	return r.retiredAt == ""
}

// RetiredAt returns the retirement timestamp, or "" if the key is active.
func (r *Record) RetiredAt() string {
	return r.retiredAt
}

// PrivateKeyBytes returns the raw 32-byte private key scalar — persist
// this to the secret store.
func (r *Record) PrivateKeyBytes() [32]byte {
	var out [32]byte
	copy(out[:], r.priv.Seed())
	return out
}

// PublicKeyJWK returns the public key in JWK format (OKP / Ed25519),
// suitable for the GET /enforcer/keys/active response. Marshaled from a
// map so keys serialize alphabetically (crv, kty, x) — matching serde_json
// wire order; pinned by a byte-golden test.
func (r *Record) PublicKeyJWK() map[string]any {
	x := base64.RawURLEncoding.EncodeToString(r.VerifyingKey())
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x}
}

func (r *Record) VerifyingKey() ed25519.PublicKey {
	return r.priv.Public().(ed25519.PublicKey)
}

func (r *Record) SigningKey() ed25519.PrivateKey {
	return r.priv
}
