package cidr

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

// ── Parsing (ledger: cidr::*) ────────────────────────────────────────────────

func TestValidIPv4CidrParses(t *testing.T) {
	if _, err := Parse("10.0.0.0/24"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestValidIPv6CidrParses(t *testing.T) {
	if _, err := Parse("fd00::/48"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestHostAddressWithoutPrefixIsError(t *testing.T) {
	// A bare IP address is not a valid CIDR
	if _, err := Parse("10.0.0.1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEmptyStringIsError(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestIPv4PrefixExceeding32IsError(t *testing.T) {
	if _, err := Parse("10.0.0.0/33"); err == nil {
		t.Fatal("expected error")
	}
}

func TestIPv6PrefixExceeding128IsError(t *testing.T) {
	if _, err := Parse("fd00::/129"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSlashOnlyIsError(t *testing.T) {
	if _, err := Parse("/24"); err == nil {
		t.Fatal("expected error")
	}
}

// ── Containment ─────────────────────────────────────────────────────────────

func TestIPInsideCidrIsContained(t *testing.T) {
	c, _ := Parse("10.0.0.0/24")
	if !c.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("expected contained")
	}
}

func TestIPOutsideCidrIsNotContained(t *testing.T) {
	c, _ := Parse("10.0.0.0/24")
	if c.Contains(netip.MustParseAddr("10.0.1.1")) {
		t.Fatal("expected not contained")
	}
}

func TestNetworkAddressIsContained(t *testing.T) {
	c, _ := Parse("10.0.0.0/24")
	if !c.Contains(netip.MustParseAddr("10.0.0.0")) {
		t.Fatal("expected contained")
	}
}

func TestBroadcastAddressIsContained(t *testing.T) {
	c, _ := Parse("10.0.0.0/24")
	if !c.Contains(netip.MustParseAddr("10.0.0.255")) {
		t.Fatal("expected contained")
	}
}

func TestIPv6AddressNotContainedInIPv4Cidr(t *testing.T) {
	c, _ := Parse("10.0.0.0/24")
	if c.Contains(netip.MustParseAddr("::1")) {
		t.Fatal("expected not contained")
	}
}

func TestSlash32ContainsOnlyThatHost(t *testing.T) {
	c, _ := Parse("10.0.0.5/32")
	if !c.Contains(netip.MustParseAddr("10.0.0.5")) {
		t.Fatal("expected 10.0.0.5 contained")
	}
	if c.Contains(netip.MustParseAddr("10.0.0.4")) {
		t.Fatal("expected 10.0.0.4 not contained")
	}
	if c.Contains(netip.MustParseAddr("10.0.0.6")) {
		t.Fatal("expected 10.0.0.6 not contained")
	}
}

// ── Go-only parity guards (no Rust counterpart) ─────────────────────────────

func TestZoneIDIsRejected(t *testing.T) {
	// Rust's IpAddr::parse rejects zone IDs; netip.ParseAddr accepts them,
	// so Parse must reject explicitly (acceptance semantics are contract).
	if _, err := Parse("fe80::1%eth0/64"); err == nil {
		t.Fatal("expected error for zone ID")
	}
}

func TestReserializationMatchesRustDisplay(t *testing.T) {
	// testdata captured from the Rust implementation (Display output);
	// String() feeds nft daddr tokens, so bytes must match exactly.
	raw, err := os.ReadFile("testdata/reserialization.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no differential cases loaded")
	}
	for _, tc := range cases {
		c, err := Parse(tc.Input)
		if err != nil {
			t.Errorf("Parse(%q): unexpected error %v", tc.Input, err)
			continue
		}
		if got := c.String(); got != tc.Expected {
			t.Errorf("String() of %q = %q, want %q (Rust Display)", tc.Input, got, tc.Expected)
		}
	}
}
