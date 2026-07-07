package rekor

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitPostsWellFormedRekordAndParsesUUID(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"abc123def": {"logIndex": 7}}`))
	}))
	defer srv.Close()

	uuid, err := New(srv.URL).Submit([]byte("content"), []byte("sig"), []byte("PEM"))
	if err != nil || uuid != "abc123def" {
		t.Fatalf("uuid=%q err=%v", uuid, err)
	}

	if got["kind"] != "rekord" || got["apiVersion"] != "0.0.1" {
		t.Fatalf("wrong envelope: %v", got)
	}
	spec := got["spec"].(map[string]any)
	sig := spec["signature"].(map[string]any)
	if sig["format"] != "x509" {
		t.Fatalf("format = %v, want x509", sig["format"])
	}
	if c, _ := base64.StdEncoding.DecodeString(sig["content"].(string)); string(c) != "sig" {
		t.Fatal("signature content must be std-base64 of the raw signature")
	}
	pk := sig["publicKey"].(map[string]any)
	if c, _ := base64.StdEncoding.DecodeString(pk["content"].(string)); string(c) != "PEM" {
		t.Fatal("publicKey content must be std-base64 of the PEM")
	}
	data := spec["data"].(map[string]any)
	if c, _ := base64.StdEncoding.DecodeString(data["content"].(string)); string(c) != "content" {
		t.Fatal("data content must be std-base64 of the reduced payload")
	}
}

func TestSubmitTreats409DuplicateAsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/api/v1/log/entries/existing-uuid")
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	uuid, err := New(srv.URL).Submit([]byte("c"), []byte("s"), []byte("p"))
	if err != nil || uuid != "existing-uuid" {
		t.Fatalf("409 must be success with the existing uuid; got %q, %v", uuid, err)
	}
}

func TestSubmitReturnsErrorOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "trillian unavailable", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := New(srv.URL).Submit([]byte("c"), []byte("s"), []byte("p")); err == nil {
		t.Fatal("5xx must surface as an error for the submitter to retry")
	}
}

func TestSubmitReturnsErrorWhenUnreachable(t *testing.T) {
	srv := httptest.NewServer(nil)
	srv.Close() // now refusing connections

	if _, err := New(srv.URL).Submit([]byte("c"), []byte("s"), []byte("p")); err == nil {
		t.Fatal("connection failure must surface as an error")
	}
}
