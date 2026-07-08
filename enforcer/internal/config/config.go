// Package config mirrors enforcer/src/config.rs: enforcer configuration
// loaded from environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/signingkey"
)

// MissingError reports a required env var that is not set
// (mirrors ConfigError::Missing).
type MissingError struct{ Key string }

func (e *MissingError) Error() string { return "required env var not set: " + e.Key }

// InvalidError reports an env var whose value cannot be used
// (mirrors ConfigError::Invalid).
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return "invalid configuration: " + e.Msg }

type Config struct {
	SigningKey *signingkey.Record
	// PARITY: config.rs validates ENFORCER_PORT but main never binds a TCP
	// port — the API listens on the unix socket only. Field carried verbatim.
	Port       uint16
	SocketPath string
	// OutboxPath is the durable attestation spool. Always on:
	// main fails closed if it cannot be opened.
	OutboxPath string
	// RekorURL is the transparency-log base URL. Empty = Rekor submission
	// disabled (dev Mac / smoke.sh); the spool is still written.
	RekorURL string
}

// FromEnv loads config from the real environment.
func FromEnv() (*Config, error) {
	return FromLookup(os.LookupEnv)
}

// FromLookup loads config from an injectable key-value lookup.
// Tests pass a func; production calls FromEnv.
func FromLookup(lookup func(string) (string, bool)) (*Config, error) {
	keyID, ok := lookup("ENFORCER_KEY_ID")
	if !ok {
		return nil, &MissingError{Key: "ENFORCER_KEY_ID"}
	}

	keyB64, ok := lookup("ENFORCER_SIGNING_KEY")
	if !ok {
		return nil, &MissingError{Key: "ENFORCER_SIGNING_KEY"}
	}

	keyBytes, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, &InvalidError{Msg: fmt.Sprintf("ENFORCER_SIGNING_KEY is not valid base64url: %v", err)}
	}
	if len(keyBytes) != 32 {
		return nil, &InvalidError{Msg: fmt.Sprintf("ENFORCER_SIGNING_KEY must be exactly 32 bytes, got %d", len(keyBytes))}
	}
	var seed [32]byte
	copy(seed[:], keyBytes)

	signingKey, err := signingkey.Load(keyID, &seed)
	if err != nil {
		return nil, &InvalidError{Msg: fmt.Sprintf("invalid signing key: %v", err)}
	}

	port := uint16(9090)
	if s, ok := lookup("ENFORCER_PORT"); ok {
		port, err = parsePort(s)
		if err != nil {
			return nil, err
		}
	}

	socketPath := "/run/warden-enforcer/api.sock"
	if s, ok := lookup("ENFORCER_SOCKET"); ok {
		socketPath = s
	}

	outboxPath := "/var/lib/warden-enforcer/outbox.jsonl"
	if s, ok := lookup("ENFORCER_OUTBOX"); ok {
		if s == "" {
			return nil, &InvalidError{Msg: "ENFORCER_OUTBOX must not be empty — the spool is the durable attestation record"}
		}
		outboxPath = s
	}

	rekorURL := ""
	if s, ok := lookup("ENFORCER_REKOR_URL"); ok {
		rekorURL = s
	}

	return &Config{
		SigningKey: signingKey,
		Port:       port,
		SocketPath: socketPath,
		OutboxPath: outboxPath,
		RekorURL:   rekorURL,
	}, nil
}

// parsePort mirrors config.rs: parse as u32 (PARITY: Rust's u32::from_str
// accepts one leading '+', which strconv.ParseUint rejects — same quirk as
// cidr prefix parsing), then require ≤ 65535.
func parsePort(s string) (uint16, error) {
	digits := strings.TrimPrefix(s, "+")
	p, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || p > 65535 {
		return 0, &InvalidError{Msg: fmt.Sprintf("ENFORCER_PORT must be a number 0–65535, got %q", s)}
	}
	return uint16(p), nil
}
