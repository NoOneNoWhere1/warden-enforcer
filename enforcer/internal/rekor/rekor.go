// Package rekor submits breach-event attestations to a Rekor transparency
// log as `rekord` entries — the one type that verifies pure Ed25519 at
// intake (hashedrekord cannot; sigstore/rekor #851, proven by the pre-E3.3
// spike). Stdlib net/http only: the API surface is a single POST.
package rekor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Submit posts one rekord entry: content is canonical(RekorPayload()),
// signature the dedicated Ed25519 signature over it, publicKeyPEM the PKIX
// PEM of the signing key's public half. Returns the log entry UUID.
//
// Rekor verifies the signature at intake (bad content/signature → 4xx) and
// stores only sha256(content) + signature + key — the reduced payload never
// appears in the public log. A 409 means this exact entry already exists:
// that is success, and what makes spool replay after a restart idempotent.
func (c *Client) Submit(content, signature, publicKeyPEM []byte) (string, error) {
	entry := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "rekord",
		"spec": map[string]any{
			"signature": map[string]any{
				"format":  "x509",
				"content": base64.StdEncoding.EncodeToString(signature),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(publicKeyPEM),
				},
			},
			"data": map[string]any{
				"content": base64.StdEncoding.EncodeToString(content),
			},
		},
	}
	body, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}

	resp, err := c.http.Post(c.baseURL+"/api/v1/log/entries", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusCreated:
		// Response shape: {"<uuid>": {...entry...}}
		var created map[string]json.RawMessage
		if err := json.Unmarshal(raw, &created); err != nil || len(created) != 1 {
			return "", fmt.Errorf("rekor 201 with unparseable body: %.200s", raw)
		}
		for uuid := range created {
			return uuid, nil
		}
		return "", fmt.Errorf("unreachable")
	case http.StatusConflict:
		// Location: /api/v1/log/entries/<uuid>
		if loc := resp.Header.Get("Location"); loc != "" {
			return path.Base(loc), nil
		}
		return "", nil // duplicate confirmed even without a location
	default:
		return "", fmt.Errorf("rekor %d: %.200s", resp.StatusCode, raw)
	}
}
