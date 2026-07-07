// Package canonical mirrors enforcer/src/canonical.rs: RFC 8785 (JCS)
// canonical JSON for cross-attester signatures. The result is the exact
// byte string over which an Ed25519 signature is computed; every attester
// (Go enforcer, Python MCP server, .NET API) must agree byte for byte.
// Parity with the Rust serde_jcs output is pinned by
// testdata/jcs_differential.json and the frozen conformance vector.
package canonical

import (
	"encoding/json"

	"github.com/gowebpki/jcs"
)

// ToCanonicalBytes serializes value to its RFC 8785 (JCS) canonical UTF-8
// byte form. Two callers that serialize equal data produce identical bytes
// regardless of field declaration order or language.
func ToCanonicalBytes(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
