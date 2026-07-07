// Package breachevent mirrors enforcer/src/breach_event.rs: a signed
// attestation that an agent attempted an action outside its OAuth scope.
//
// The Signature field is base64url-encoded Ed25519 over the canonical JSON
// of all other fields (RFC 8785 — alphabetical key order). The full event,
// including Violation, is stored in attestation_outbox only; RekorPayload
// returns the reduced form safe for the public Rekor log.
package breachevent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/canonical"
)

// timestampLayout renders a UTC instant with a "+00:00" offset (not "Z"),
// matching the frozen conformance vector.
// PARITY: chrono's to_rfc3339 also emits fractional seconds for live
// events; that formatting is out-of-scope for the parity window (see
// PARITY.md) — only the fixed fixture string is ever signed or compared.
const timestampLayout = "2006-01-02T15:04:05-07:00"

type Event struct {
	AgentID       string `json:"agent_id"`
	Attester      string `json:"attester"` // "warden-enforcer"
	AttesterKeyID string `json:"attester_key_id"`
	BreachID      string `json:"breach_id"` // UUID v4
	Layer         string `json:"layer"`     // "network" for the enforcer
	SessionID     string `json:"session_id"`
	Signature     string `json:"signature"`   // base64url; empty until Sign is called
	Timestamp     string `json:"timestamp"`   // ISO 8601
	TokenClaim    string `json:"token_claim"` // "targets" for network breach
	Violation     string `json:"violation"`   // NOT included in Rekor payload
}

// New constructs an unsigned breach event for a network-layer violation.
// Call Sign before storing or submitting to Rekor.
func New(sessionID, agentID, violation, attesterKeyID string) *Event {
	return &Event{
		AgentID:       agentID,
		Attester:      "warden-enforcer",
		AttesterKeyID: attesterKeyID,
		BreachID:      uuid.NewString(),
		Layer:         "network",
		SessionID:     sessionID,
		Timestamp:     time.Now().UTC().Format(timestampLayout),
		TokenClaim:    "targets",
		Violation:     violation,
	}
}

// Sign signs this event with the enforcer's active Ed25519 key, populating
// e.Signature with a base64url-encoded Ed25519 signature over the canonical
// JSON of all fields except signature.
func (e *Event) Sign(signingKey ed25519.PrivateKey) error {
	msg, err := e.signableBytes()
	if err != nil {
		return err
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signingKey, msg))
	return nil
}

// Verify checks the signature against the provided public key.
// Returns false if the signature is missing, malformed, or invalid.
func (e *Event) Verify(verifyingKey ed25519.PublicKey) bool {
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := e.signableBytes()
	if err != nil {
		return false
	}
	return ed25519.Verify(verifyingKey, msg, sig)
}

// RekorPayload is the reduced payload for public Rekor submission.
// It omits violation and token_claim — those are retained in
// attestation_outbox only and must not appear in the public log.
func (e *Event) RekorPayload() map[string]any {
	return map[string]any{
		"agent_id":        e.AgentID,
		"attester":        e.Attester,
		"attester_key_id": e.AttesterKeyID,
		"breach_id":       e.BreachID,
		"layer":           e.Layer,
		"session_id":      e.SessionID,
		"signature":       e.Signature,
		"timestamp":       e.Timestamp,
	}
}

// signableBytes is the canonical JSON (RFC 8785) over which the signature
// is computed. The signature field is excluded (it does not exist yet at
// signing time). See tests/conformance/breach_event_v1.json for the frozen
// cross-language vector that pins this output.
func (e *Event) signableBytes() ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "signature")
	return canonical.ToCanonicalBytes(fields)
}
