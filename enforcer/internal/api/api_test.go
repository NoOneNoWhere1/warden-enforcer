package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/breachevent"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/sandbox"
	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/signingkey"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

func testState(t *testing.T) *AppState {
	t.Helper()
	return testStateWithBackend(t, sandbox.NoopBackend{})
}

func testStateWithBackend(t *testing.T, backend sandbox.Backend) *AppState {
	t.Helper()
	key, err := signingkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &AppState{
		ActiveKey: key,
		Sessions:  map[string]Credential{},
		Events:    map[string][]breachevent.Event{},
		Sandbox:   sandbox.NewController(backend),
	}
}

func validCredential(sessionID string) string {
	return fmt.Sprintf(`{
		"session_id": %q,
		"agent_id":   "test-agent-001",
		"targets":    ["10.99.0.0/24"],
		"tools":      ["nmap_scan"],
		"resources":  ["db:vuln_kb"],
		"intent":     "recon",
		"ttl_secs":   3600
	}`, sessionID)
}

func seedSession(t *testing.T, s *AppState, sessionID string) {
	t.Helper()
	var cred Credential
	if err := json.Unmarshal([]byte(validCredential(sessionID)), &cred); err != nil {
		t.Fatal(err)
	}
	s.Sessions[sessionID] = cred
}

func do(s *AppState, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	Router(s).ServeHTTP(rec, req)
	return rec
}

func bodyJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not a JSON object: %v (body: %s)", err, rec.Body.String())
	}
	return out
}

// ── POST /sessions ───────────────────────────────────────────────────────────

func TestPostSessionsValidCredentialReturns201(t *testing.T) {
	rec := do(testState(t), http.MethodPost, "/sessions", validCredential("sess-001"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
}

func TestPostSessionsResponseBodyContainsSessionID(t *testing.T) {
	rec := do(testState(t), http.MethodPost, "/sessions", validCredential("sess-002"))
	if got := bodyJSON(t, rec)["session_id"]; got != "sess-002" {
		t.Fatalf("session_id = %v, want sess-002", got)
	}
}

func TestPostSessionsMissingRequiredFieldReturns422(t *testing.T) {
	body := `{"agent_id": "x", "targets": [], "intent": "recon", "ttl_secs": 60}`
	rec := do(testState(t), http.MethodPost, "/sessions", body)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
}

func TestPostSessionsDuplicateSessionIDReturns409(t *testing.T) {
	s := testState(t)
	seedSession(t, s, "sess-003")
	rec := do(s, http.MethodPost, "/sessions", validCredential("sess-003"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

// The duplicate check precedes CIDR validation, so a request
// that is both a duplicate and has a bad CIDR returns 409, not 422.
func TestPostSessionsDuplicateSessionIDWithBadCIDRReturns409(t *testing.T) {
	s := testState(t)
	seedSession(t, s, "sess-dup-bad")
	body := `{
		"session_id": "sess-dup-bad",
		"agent_id":   "test-agent",
		"targets":    ["not-a-cidr"],
		"tools":      [],
		"resources":  [],
		"intent":     "recon",
		"ttl_secs":   3600
	}`
	rec := do(s, http.MethodPost, "/sessions", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

// ── DELETE /sessions/{id} ────────────────────────────────────────────────────

func TestDeleteExistingSessionReturns204(t *testing.T) {
	s := testState(t)
	seedSession(t, s, "sess-del-001")
	rec := do(s, http.MethodDelete, "/sessions/sess-del-001", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestDeleteUnknownSessionReturns404(t *testing.T) {
	rec := do(testState(t), http.MethodDelete, "/sessions/does-not-exist", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ── GET /sessions/{id}/events ────────────────────────────────────────────────

func TestGetEventsForExistingSessionReturns200WithArray(t *testing.T) {
	s := testState(t)
	seedSession(t, s, "sess-ev-001")
	s.Events["sess-ev-001"] = []breachevent.Event{}

	rec := do(s, http.MethodGet, "/sessions/sess-ev-001/events", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var arr []any
	if err := json.Unmarshal(rec.Body.Bytes(), &arr); err != nil {
		t.Fatalf("body is not a JSON array: %v (body: %s)", err, rec.Body.String())
	}
}

func TestGetEventsForUnknownSessionReturns404(t *testing.T) {
	rec := do(testState(t), http.MethodGet, "/sessions/unknown-session/events", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ── GET /enforcer/keys/active ────────────────────────────────────────────────

func TestGetActiveKeyReturns200(t *testing.T) {
	rec := do(testState(t), http.MethodGet, "/enforcer/keys/active", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestGetActiveKeyBodyIsOKPJWK(t *testing.T) {
	rec := do(testState(t), http.MethodGet, "/enforcer/keys/active", "")
	body := bodyJSON(t, rec)
	if body["kty"] != "OKP" {
		t.Errorf("kty = %v, want OKP", body["kty"])
	}
	if body["crv"] != "Ed25519" {
		t.Errorf("crv = %v, want Ed25519", body["crv"])
	}
	if x, ok := body["x"].(string); !ok || x == "" {
		t.Errorf("x = %v, want non-empty string", body["x"])
	}
}

func TestGetActiveKeyBodyIncludesKeyID(t *testing.T) {
	rec := do(testState(t), http.MethodGet, "/enforcer/keys/active", "")
	if keyID, ok := bodyJSON(t, rec)["key_id"].(string); !ok || keyID == "" {
		t.Fatalf("key_id missing or empty in %s", rec.Body.String())
	}
}

// ── GET /enforcer/keys/{key_id} ──────────────────────────────────────────────

func TestGetKeyByIDReturns200ForActiveKey(t *testing.T) {
	s := testState(t)
	rec := do(s, http.MethodGet, "/enforcer/keys/"+s.ActiveKey.KeyID(), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func retireKey(t *testing.T, s *AppState) string {
	t.Helper()
	oldKey, err := signingkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey.Retire("2026-06-29T00:00:00Z")
	s.ArchivedKeys = append(s.ArchivedKeys, oldKey)
	return oldKey.KeyID()
}

func TestGetKeyByIDReturns200ForRetiredKey(t *testing.T) {
	s := testState(t)
	retiredID := retireKey(t, s)
	rec := do(s, http.MethodGet, "/enforcer/keys/"+retiredID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestGetKeyByIDRetiredKeyBodyIncludesRetiredAt(t *testing.T) {
	s := testState(t)
	retiredID := retireKey(t, s)
	rec := do(s, http.MethodGet, "/enforcer/keys/"+retiredID, "")
	if got := bodyJSON(t, rec)["retired_at"]; got != "2026-06-29T00:00:00Z" {
		t.Fatalf("retired_at = %v, want 2026-06-29T00:00:00Z", got)
	}
}

func TestGetKeyByIDReturns404ForUnknownKey(t *testing.T) {
	rec := do(testState(t), http.MethodGet, "/enforcer/keys/unknown-key-id-xyz", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ── Sandbox wiring ───────────────────────────────────────────────────────────

func TestPostSessionsInvalidCIDRTargetReturns422(t *testing.T) {
	body := `{
		"session_id": "sess-bad-cidr",
		"agent_id":   "test-agent",
		"targets":    ["not-a-cidr"],
		"tools":      [],
		"resources":  [],
		"intent":     "recon",
		"ttl_secs":   3600
	}`
	rec := do(testState(t), http.MethodPost, "/sessions", body)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
}

type failCreate struct{ sandbox.NoopBackend }

func (failCreate) Create(string, []cidr.Cidr) error {
	return &sandbox.BackendError{Msg: "kernel error"}
}

func TestPostSessionsSandboxBackendFailureReturns500(t *testing.T) {
	s := testStateWithBackend(t, failCreate{})
	rec := do(s, http.MethodPost, "/sessions", validCredential("sess-500-create"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

type failDestroy struct{ sandbox.NoopBackend }

func (failDestroy) Destroy(string) error {
	return &sandbox.BackendError{Msg: "teardown failed"}
}

func TestDeleteSessionSandboxBackendFailureReturns500(t *testing.T) {
	s := testStateWithBackend(t, failDestroy{})
	// Create the session so the sandbox controller tracks it.
	create := do(s, http.MethodPost, "/sessions", validCredential("sess-500-destroy"))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", create.Code)
	}

	rec := do(s, http.MethodDelete, "/sessions/sess-500-destroy", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	// The session record must survive a failed teardown so the operator
	// can retry the delete.
	if _, exists := s.Sessions["sess-500-destroy"]; !exists {
		t.Fatal("session record was removed despite backend failure")
	}
}
