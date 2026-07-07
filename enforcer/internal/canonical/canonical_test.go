package canonical

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gowebpki/jcs"
)

// ── Ledger: canonical::* ─────────────────────────────────────────────────────

func TestKeysAreSortedRegardlessOfInputOrder(t *testing.T) {
	a, err := ToCanonicalBytes(map[string]any{"b": 1, "a": 2, "c": 3})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ToCanonicalBytes(map[string]any{"c": 3, "a": 2, "b": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("orderings differ: %s vs %s", a, b)
	}
	if string(a) != `{"a":2,"b":1,"c":3}` {
		t.Fatalf("got %s", a)
	}
}

func TestNestedObjectsAreCanonicalizedRecursively(t *testing.T) {
	out, err := ToCanonicalBytes(map[string]any{"z": map[string]any{"y": 1, "x": 2}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"z":{"x":2,"y":1}}` {
		t.Fatalf("got %s", out)
	}
}

func TestNoInsignificantWhitespace(t *testing.T) {
	out, err := ToCanonicalBytes(map[string]any{"a": "b", "c": "d"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":"b","c":"d"}` {
		t.Fatalf("got %s", out)
	}
}

// ── Go-only parity guards ────────────────────────────────────────────────────

func TestHTMLCharsAreNotEscaped(t *testing.T) {
	// json.Marshal HTML-escapes < > & by default; jcs.Transform must undo
	// that back to RFC 8785 minimal escaping or signatures diverge from Rust.
	out, err := ToCanonicalBytes(map[string]any{"violation": "<script> & co"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"violation":"<script> & co"}` {
		t.Fatalf("HTML chars must stay literal, got %s", out)
	}
}

func TestJCSDifferentialCorpusMatchesRust(t *testing.T) {
	// testdata captured from serde_jcs via a temporary Rust scratch
	// (deleted in the same commit). Weighted toward violation-field string
	// escaping — the live divergence surface (risk R1).
	raw, err := os.ReadFile("testdata/jcs_differential.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 20 {
		t.Fatalf("expected >=20 differential cases, got %d", len(cases))
	}
	for _, tc := range cases {
		got, err := jcs.Transform([]byte(tc.Input))
		if err != nil {
			t.Errorf("%s: Transform error: %v", tc.Name, err)
			continue
		}
		if string(got) != tc.Canonical {
			t.Errorf("%s: gowebpki/jcs = %q, serde_jcs = %q", tc.Name, got, tc.Canonical)
		}
	}
}
