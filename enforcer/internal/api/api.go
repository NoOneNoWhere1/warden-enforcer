// Package api mirrors enforcer/src/api.rs: the HTTP API served over the
// enforcer's unix socket.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/outbox"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/signingkey"
)

// Credential received in POST /sessions.
// The enforcer extracts Targets to program nftables rules;
// all other claims are validated by their respective layers.
type Credential struct {
	SessionID string   `json:"session_id"`
	AgentID   string   `json:"agent_id"`
	Targets   []string `json:"targets"`
	Tools     []string `json:"tools"`
	Resources []string `json:"resources"`
	Intent    string   `json:"intent"`
	TTLSecs   uint64   `json:"ttl_secs"`
}

// credentialWire is the decode target for POST /sessions. All fields are
// pointers so a missing required field surfaces as nil — the Go equivalent
// of serde rejecting a Credential with a missing field (422).
type credentialWire struct {
	SessionID *string   `json:"session_id"`
	AgentID   *string   `json:"agent_id"`
	Targets   *[]string `json:"targets"`
	Tools     *[]string `json:"tools"`
	Resources *[]string `json:"resources"`
	Intent    *string   `json:"intent"`
	TTLSecs   *uint64   `json:"ttl_secs"`
}

func (w *credentialWire) credential() (Credential, bool) {
	if w.SessionID == nil || w.AgentID == nil || w.Targets == nil ||
		w.Tools == nil || w.Resources == nil || w.Intent == nil || w.TTLSecs == nil {
		return Credential{}, false
	}
	return Credential{
		SessionID: *w.SessionID,
		AgentID:   *w.AgentID,
		Targets:   *w.Targets,
		Tools:     *w.Tools,
		Resources: *w.Resources,
		Intent:    *w.Intent,
		TTLSecs:   *w.TTLSecs,
	}, true
}

// AppState is the shared state across all handlers (api.rs:39-48).
//
// PARITY: mu is the single lock over everything nested here,
// mirroring Rust's Arc<Mutex<AppState>>. Handlers lock once at entry; no
// second lock exists anywhere (the sandbox Controller has none by design).
type AppState struct {
	mu sync.Mutex
	// ActiveKey is the current signing key.
	ActiveKey *signingkey.Record
	// ArchivedKeys are retired keys, kept so breach events signed under
	// them remain verifiable.
	ArchivedKeys []*signingkey.Record
	Sessions     map[string]Credential
	Events       map[string][]breachevent.Event
	// EventLosses counts breach events lost per session: ring-buffer
	// evictions, token-bucket rejections, failed spool appends. Surfaced —
	// together with the sandbox layer's channel-overflow count — as the
	// X-Warden-Lost-Events header on GET /sessions/{id}/events.
	EventLosses map[string]uint64
	Sandbox     *sandbox.Controller
	// Outbox is the durable spool ConsumeDrops appends to (write-ahead of
	// Rekor). Nil = no durable record (unit tests only; main always sets it).
	Outbox *outbox.Spool
	// OutboxKick wakes the Rekor submitter after an append (cap 1,
	// non-blocking send).
	OutboxKick chan struct{}
	// Now overrides the token-bucket clock in tests. Nil = time.Now.
	Now func() time.Time

	buckets map[string]*tokenBucket
}

// Router mirrors api.rs router(): five routes, Go 1.22 method patterns.
func Router(state *AppState) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", state.createSession)
	mux.HandleFunc("DELETE /sessions/{id}", state.deleteSession)
	mux.HandleFunc("GET /sessions/{id}/events", state.getSessionEvents)
	mux.HandleFunc("GET /enforcer/keys/active", state.getActiveKey)
	mux.HandleFunc("GET /enforcer/keys/{key_id}", state.getKeyByID)
	return mux
}

// createSession handles POST /sessions.
// Stores the session and programs nftables rules for the listed CIDRs.
// Returns 201 with {"session_id": "..."}, 409 if the session already exists,
// 422 if the credential is malformed or any target CIDR is invalid, 500 on
// sandbox backend failure.
//
// PARITY: check order is contract — 409 duplicate precedes
// 422 bad CIDR precedes 500 backend (api.rs:73 → :79 → :94).
func (s *AppState) createSession(w http.ResponseWriter, r *http.Request) {
	var wire credentialWire
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid credential: "+err.Error())
		return
	}
	cred, ok := wire.credential()
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, "credential is missing a required field")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Sessions[cred.SessionID]; exists {
		w.WriteHeader(http.StatusConflict)
		return
	}

	cidrs := make([]cidr.Cidr, 0, len(cred.Targets))
	for _, t := range cred.Targets {
		c, err := cidr.Parse(t)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		cidrs = append(cidrs, c)
	}

	if err := s.Sandbox.CreateSandbox(cred.SessionID, cidrs); err != nil {
		var exists *sandbox.AlreadyExistsError
		if errors.As(err, &exists) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.Sessions[cred.SessionID] = cred
	s.Events[cred.SessionID] = []breachevent.Event{}
	writeJSON(w, http.StatusCreated, map[string]any{"session_id": cred.SessionID})
}

// deleteSession handles DELETE /sessions/{id}.
// Tears down the sandbox and removes the session record.
// Returns 204 on success, 404 if the session does not exist, 500 on sandbox
// backend failure — the session record is preserved so the operator can
// retry (api.rs:113-136).
func (s *AppState) deleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Sessions[id]; !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := s.Sandbox.DestroySandbox(id); err != nil {
		// A sandbox the controller never tracked counts as destroyed
		// (Rust: Ok(()) | Err(SandboxError::NotFound(_)) => {}).
		var notFound *sandbox.NotFoundError
		if !errors.As(err, &notFound) {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	delete(s.Sessions, id)
	delete(s.Events, id)
	delete(s.EventLosses, id)
	delete(s.buckets, id)
	w.WriteHeader(http.StatusNoContent)
}

// getSessionEvents handles GET /sessions/{id}/events.
// Returns 200 with a (possibly empty) JSON array of signed breach events,
// 404 if the session does not exist.
func (s *AppState) getSessionEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Sessions[id]; !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	events := s.Events[id]
	if events == nil {
		events = []breachevent.Event{} // nil marshals to null; the contract is []
	}
	// Visible loss counter — "every breach attested" is best-effort, and
	// this is where the effort's shortfall shows. A header keeps the
	// response body (a bare array) contract-intact.
	lost := s.EventLosses[id] + s.Sandbox.LostDrops(id)
	w.Header().Set("X-Warden-Lost-Events", strconv.FormatUint(lost, 10))
	writeJSON(w, http.StatusOK, events)
}

// getActiveKey handles GET /enforcer/keys/active.
// Returns the active public key as a JWK with an added key_id field.
func (s *AppState) getActiveKey(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jwk := s.ActiveKey.PublicKeyJWK()
	jwk["key_id"] = s.ActiveKey.KeyID()
	writeJSON(w, http.StatusOK, jwk)
}

// getKeyByID handles GET /enforcer/keys/{key_id}.
// Looks up any key (active or retired) by its stable key_id. Retired keys
// include a retired_at field in the response.
// Returns 200 with JWK, 404 if the key_id is unknown.
func (s *AppState) getKeyByID(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("key_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ActiveKey.KeyID() == keyID {
		jwk := s.ActiveKey.PublicKeyJWK()
		jwk["key_id"] = s.ActiveKey.KeyID()
		writeJSON(w, http.StatusOK, jwk)
		return
	}

	for _, key := range s.ArchivedKeys {
		if key.KeyID() != keyID {
			continue
		}
		jwk := key.PublicKeyJWK()
		jwk["key_id"] = key.KeyID()
		if retiredAt := key.RetiredAt(); retiredAt != "" {
			jwk["retired_at"] = retiredAt
		}
		writeJSON(w, http.StatusOK, jwk)
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
