package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func validKeyB64() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
}

func baseEnv(keyID string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return keyID, true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		}
		return "", false
	}
}

func mustLoad(t *testing.T, lookup func(string) (string, bool)) *Config {
	t.Helper()
	cfg, err := FromLookup(lookup)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func assertMissing(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var missing *MissingError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want MissingError", err)
	}
}

func assertInvalid(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var invalid *InvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want InvalidError", err)
	}
}

// ── Loading (ledger: config::*) ──────────────────────────────────────────────

func TestConfigLoadsValidSigningKeyFromEnv(t *testing.T) {
	cfg := mustLoad(t, baseEnv("test-key-001"))
	if cfg.SigningKey.KeyID() != "test-key-001" {
		t.Fatalf("key_id = %q, want %q", cfg.SigningKey.KeyID(), "test-key-001")
	}
}

func TestConfigDefaultPortIs9090(t *testing.T) {
	if cfg := mustLoad(t, baseEnv("k")); cfg.Port != 9090 {
		t.Fatalf("port = %d, want 9090", cfg.Port)
	}
}

func TestConfigCustomPortIsParsed(t *testing.T) {
	cfg := mustLoad(t, func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		case "ENFORCER_PORT":
			return "8443", true
		}
		return "", false
	})
	if cfg.Port != 8443 {
		t.Fatalf("port = %d, want 8443", cfg.Port)
	}
}

func TestConfigDefaultSocketPathIsRunWardenEnforcer(t *testing.T) {
	cfg := mustLoad(t, baseEnv("k"))
	if cfg.SocketPath != "/run/warden-enforcer/api.sock" {
		t.Fatalf("socket_path = %q, want %q", cfg.SocketPath, "/run/warden-enforcer/api.sock")
	}
}

func TestConfigCustomSocketPathIsUsed(t *testing.T) {
	cfg := mustLoad(t, func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		case "ENFORCER_SOCKET":
			return "/tmp/test.sock", true
		}
		return "", false
	})
	if cfg.SocketPath != "/tmp/test.sock" {
		t.Fatalf("socket_path = %q, want %q", cfg.SocketPath, "/tmp/test.sock")
	}
}

// ── Error kinds ──────────────────────────────────────────────────────────────

func TestConfigMissingSigningKeyReturnsMissingError(t *testing.T) {
	_, err := FromLookup(func(k string) (string, bool) {
		if k == "ENFORCER_KEY_ID" {
			return "k", true
		}
		return "", false
	})
	assertMissing(t, err)
}

func TestConfigMissingKeyIDReturnsMissingError(t *testing.T) {
	_, err := FromLookup(func(k string) (string, bool) {
		if k == "ENFORCER_SIGNING_KEY" {
			return validKeyB64(), true
		}
		return "", false
	})
	assertMissing(t, err)
}

func TestConfigMalformedBase64KeyReturnsInvalidError(t *testing.T) {
	_, err := FromLookup(func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return "not-valid-base64!!!", true
		}
		return "", false
	})
	assertInvalid(t, err)
}

func TestConfigSigningKeyWrongLengthReturnsInvalidError(t *testing.T) {
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
	_, err := FromLookup(func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return short, true
		}
		return "", false
	})
	assertInvalid(t, err)
}

func TestConfigNonNumericPortReturnsInvalidError(t *testing.T) {
	_, err := FromLookup(func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		case "ENFORCER_PORT":
			return "not-a-port", true
		}
		return "", false
	})
	assertInvalid(t, err)
}

func TestConfigOutOfRangePortReturnsInvalidError(t *testing.T) {
	_, err := FromLookup(func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		case "ENFORCER_PORT":
			return "99999", true
		}
		return "", false
	})
	assertInvalid(t, err)
}

// ── Outbox + Rekor configuration ─────────────────────────────────────────────

func TestConfigOutboxDefaultsToVarLib(t *testing.T) {
	cfg := mustLoad(t, baseEnv("k"))
	if cfg.OutboxPath != "/var/lib/warden-enforcer/outbox.jsonl" {
		t.Fatalf("outbox_path = %q", cfg.OutboxPath)
	}
}

func TestConfigRekorURLDefaultsToDisabled(t *testing.T) {
	cfg := mustLoad(t, baseEnv("k"))
	if cfg.RekorURL != "" {
		t.Fatalf("rekor_url = %q, want empty (disabled)", cfg.RekorURL)
	}
}

func TestConfigOutboxAndRekorOverridesAreUsed(t *testing.T) {
	cfg := mustLoad(t, func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		case "ENFORCER_OUTBOX":
			return "/tmp/outbox.jsonl", true
		case "ENFORCER_REKOR_URL":
			return "http://rekor:3000", true
		}
		return "", false
	})
	if cfg.OutboxPath != "/tmp/outbox.jsonl" || cfg.RekorURL != "http://rekor:3000" {
		t.Fatalf("overrides not applied: %q %q", cfg.OutboxPath, cfg.RekorURL)
	}
}

func TestConfigEmptyOutboxPathIsInvalid(t *testing.T) {
	_, err := FromLookup(func(k string) (string, bool) {
		switch k {
		case "ENFORCER_KEY_ID":
			return "k", true
		case "ENFORCER_SIGNING_KEY":
			return validKeyB64(), true
		case "ENFORCER_OUTBOX":
			return "", true
		}
		return "", false
	})
	var invalid *InvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("explicit empty outbox must be InvalidError, got %v", err)
	}
}
