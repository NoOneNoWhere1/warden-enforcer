package ruleset

import (
	"os"
	"strings"
	"testing"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
)

func mustParse(t *testing.T, s string) cidr.Cidr {
	t.Helper()
	c, err := cidr.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func emptyRuleset() string {
	return New("test-session", nil).Render()
}

// ── Table structure (ledger: ruleset::*) ─────────────────────────────────────

func TestRenderedScriptContainsIPv4Table(t *testing.T) {
	if !strings.Contains(emptyRuleset(), "table ip ") {
		t.Fatal("script must contain an ipv4 table")
	}
}

func TestRenderedScriptContainsIPv6Table(t *testing.T) {
	// IPv6 table is always present even when all targets are IPv4
	if !strings.Contains(emptyRuleset(), "table ip6 ") {
		t.Fatal("script must contain an ipv6 table")
	}
}

func TestDefaultChainPolicyIsDrop(t *testing.T) {
	if !strings.Contains(emptyRuleset(), "policy drop") {
		t.Fatal("default chain policy must be drop")
	}
}

func TestTableNameIsSanitizedForNft(t *testing.T) {
	// nftables identifiers cannot contain hyphens. Since E3.1 the raw
	// session ID legitimately appears inside the quoted log prefix, where
	// hyphens are legal — strip those before asserting no identifier
	// carries a hyphen.
	script := New("sess-abc-123", nil).Render()
	if !strings.Contains(script, "sess_abc_123") {
		t.Fatal("hyphens must become underscores")
	}
	stripped := strings.ReplaceAll(script, `log prefix "warden:sess-abc-123:" group 1`, "")
	if strings.Contains(stripped, "sess-abc-123") {
		t.Fatal("hyphenated name must be sanitized everywhere outside the log prefix")
	}
}

func TestEachSessionGetsADistinctTableName(t *testing.T) {
	s1 := New("sess-aaa", nil).Render()
	s2 := New("sess-bbb", nil).Render()
	// A table from one session must not appear in the other's output
	if strings.Contains(s1, "sess_bbb") {
		t.Fatal("s1 must not contain s2's table name")
	}
	if strings.Contains(s2, "sess_aaa") {
		t.Fatal("s2 must not contain s1's table name")
	}
}

// ── Unconditional deny rules ─────────────────────────────────────────────────

func TestCloudMetadataIPv4IsBlocked(t *testing.T) {
	if !strings.Contains(emptyRuleset(), "169.254.169.254") {
		t.Fatal("ipv4 metadata endpoint must be blocked")
	}
}

func TestCloudMetadataIPv6IsBlocked(t *testing.T) {
	if !strings.Contains(emptyRuleset(), "fd00:ec2::254") {
		t.Fatal("ipv6 metadata endpoint must be blocked")
	}
}

func TestLoopbackIPv4IsBlocked(t *testing.T) {
	if !strings.Contains(emptyRuleset(), "127.0.0.0/8") {
		t.Fatal("ipv4 loopback must be blocked")
	}
}

func TestLoopbackIPv6IsBlocked(t *testing.T) {
	script := emptyRuleset()
	if !strings.Contains(script, "::1/128") && !strings.Contains(script, "::1 ") {
		t.Fatal("ipv6 loopback must be blocked")
	}
}

func TestLinkLocalIPv6IsBlocked(t *testing.T) {
	if !strings.Contains(emptyRuleset(), "fe80::/10") {
		t.Fatal("ipv6 link-local must be blocked")
	}
}

// ── Targets claim ────────────────────────────────────────────────────────────

func TestTargetCidrAppearsAsAcceptRule(t *testing.T) {
	targets := []cidr.Cidr{mustParse(t, "10.0.0.0/24")}
	script := New("test-session", targets).Render()
	if !strings.Contains(script, "10.0.0.0/24") {
		t.Fatal("target CIDR must appear in the script")
	}
}

func TestIPv6TableAlwaysPresentForIPv4OnlyTargets(t *testing.T) {
	targets := []cidr.Cidr{mustParse(t, "10.0.0.0/24")}
	script := New("test-session", targets).Render()
	if !strings.Contains(script, "table ip6 ") {
		t.Fatal("ipv6 table must be present even for ipv4-only targets")
	}
}

// ── Ordering guarantee ───────────────────────────────────────────────────────

func TestUnconditionalDenyPrecedesAcceptRules(t *testing.T) {
	// The metadata block must appear before any accept rule so it cannot
	// be shadowed by a targets claim that overlaps with the metadata range.
	targets := []cidr.Cidr{mustParse(t, "169.254.0.0/16")}
	script := New("test-session", targets).Render()

	denyPos := strings.Index(script, "169.254.169.254")
	if denyPos < 0 {
		t.Fatal("metadata unconditional deny must be present")
	}
	acceptPos := strings.Index(script, "accept")
	if acceptPos < 0 {
		t.Fatal("at least one accept rule must be present when targets is non-empty")
	}

	if denyPos >= acceptPos {
		t.Fatalf("unconditional deny (%d) must appear before accept (%d)", denyPos, acceptPos)
	}
}

// ── Forward-model / Firecracker substrate ────────────────────────────────────

func TestEgressFilterUsesForwardHookNotOutput(t *testing.T) {
	// Guest egress transits the namespace (forwarded), so an output hook
	// would never see it. This is the load-bearing fix for the E1 substrate.
	script := emptyRuleset()
	if !strings.Contains(script, "hook forward") {
		t.Fatal("filter must hook forward")
	}
	if strings.Contains(script, "hook output") {
		t.Fatal("output hook does not see forwarded guest traffic")
	}
}

func TestIPv4TableHasSourceNatMasquerade(t *testing.T) {
	script := emptyRuleset()
	if !strings.Contains(script, "type nat hook postrouting") {
		t.Fatal("NAT postrouting chain required for routable egress")
	}
	if !strings.Contains(script, "masquerade") {
		t.Fatal("masquerade rule required")
	}
}

func TestEstablishedRelatedReturnTrafficIsAccepted(t *testing.T) {
	// Default-drop forward policy would otherwise discard every reply.
	if !strings.Contains(emptyRuleset(), "ct state established,related accept") {
		t.Fatal("established/related return traffic must be accepted")
	}
}

func TestTablesAreReplacedAtomically(t *testing.T) {
	// add; delete; add under one nft -f transaction — no unfiltered window
	// during a credential update.
	script := emptyRuleset()
	if !strings.Contains(script, "delete table ip ") {
		t.Fatal("ip table must use the atomic-replace idiom")
	}
	if !strings.Contains(script, "delete table ip6 ") {
		t.Fatal("ip6 table must use the atomic-replace idiom")
	}
}

func TestDeletePrecedesRedefinitionForEachFamily(t *testing.T) {
	script := New("sess-atomic", nil).Render()
	delIP := strings.Index(script, "delete table ip warden_sess_atomic")
	if delIP < 0 {
		t.Fatal("ip delete present")
	}
	defIP := strings.LastIndex(script, "table ip warden_sess_atomic {\n")
	if defIP < 0 {
		t.Fatal("ip redefinition present")
	}
	if delIP >= defIP {
		t.Fatal("delete must precede the full table definition")
	}
}

func TestMetadataIPIsBlockedEvenWhenInsideAllowedCidr(t *testing.T) {
	// Supplying a target CIDR that contains 169.254.169.254 must not open
	// the metadata endpoint.
	targets := []cidr.Cidr{mustParse(t, "169.254.0.0/16")}
	script := New("test-session", targets).Render()
	// Unconditional block must be present
	if !strings.Contains(script, "169.254.169.254") {
		t.Fatal("metadata IP must appear as a deny rule regardless of targets")
	}
}

// ── Rust byte-goldens + gate tokens (not ledger rows) ────────────────────────

// TestRenderMatchesRustGoldens byte-compares against scripts rendered by the
// Rust implementation (captured via a temporary examples/ scratch, deleted in
// the same commit). Any divergence in table naming, rule order, whitespace,
// or CIDR re-serialization fails here before it can reach the live gate.
// Goldens re-captured from the Go renderer at E3.1 (E3 log rules +
// uplink-pool deny) — third re-capture, Go-owned; see PARITY.md.
func TestRenderMatchesRustGoldens(t *testing.T) {
	cases := []struct {
		name      string
		sessionID string
		targets   []string
	}{
		{"empty", "test-session", nil},
		{"mixed", "sess-golden-001", []string{"10.0.0.0/24", "203.0.113.7/32", "2001:db8::/32"}},
		{"overlap", "sess-overlap", []string{"169.254.0.0/16"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile("testdata/" + tc.name + ".nft")
			if err != nil {
				t.Fatal(err)
			}
			var targets []cidr.Cidr
			for _, s := range tc.targets {
				targets = append(targets, mustParse(t, s))
			}
			got := New(tc.sessionID, targets).Render()
			if got != string(want) {
				t.Fatalf("render diverges from Rust golden %s.nft\n got:\n%s\nwant:\n%s", tc.name, got, want)
			}
		})
	}
}

// TestGateTokensPresent pins the literal strings the phase-1 linux gate
// (tests/phase1/test_nftables.py) greps for in `nft list ruleset` output.
func TestGateTokensPresent(t *testing.T) {
	script := emptyRuleset()
	for _, token := range []string{"table ip6", "hook forward", "169.254.169.254", "fd00:ec2::254", "fe80::/10"} {
		if !strings.Contains(script, token) {
			t.Fatalf("gate token %q missing from rendered script", token)
		}
	}
}

// ── E3.1 (E3): breach logging + uplink-pool deny ──────────────────────────────

func TestUplinkPoolIsUnconditionallyDenied(t *testing.T) {
	// Session A's guest must not reach session B's uplink even when the
	// targets claim covers the pool.
	targets := []cidr.Cidr{mustParse(t, "10.200.0.0/16")}
	script := New("test-session", targets).Render()

	denyPos := strings.Index(script, "ip daddr 10.200.0.0/16 log")
	if denyPos < 0 {
		t.Fatal("uplink pool must appear as an unconditional deny")
	}
	acceptPos := strings.Index(script, "accept")
	if acceptPos < 0 || denyPos >= acceptPos {
		t.Fatal("uplink-pool deny must precede accept rules")
	}
}

func TestExplicitDeniesLogBeforeDropping(t *testing.T) {
	// Every deny rule must log to NFLOG group 1 so a metadata/loopback/
	// uplink-pool probe produces a breach signal, not a silent drop.
	denies := 0
	for _, line := range strings.Split(emptyRuleset(), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, " drop") { // excludes "policy drop;"
			continue
		}
		denies++
		if !strings.Contains(trimmed, `log prefix "warden:test-session:" group 1 drop`) {
			t.Fatalf("deny rule must log before dropping: %q", trimmed)
		}
	}
	if want := len(unconditionalDenyIPv4) + len(unconditionalDenyIPv6); denies != want {
		t.Fatalf("expected %d logged deny rules, found %d", want, denies)
	}
}

func TestCatchAllLogIsLastRuleInEachForwardChain(t *testing.T) {
	// Off-scope packets fall through to the chain policy, which cannot log.
	// The catch-all (log + counter, no verdict) must be the final rule of
	// both forward chains so every dropped packet is a breach signal.
	targets := []cidr.Cidr{mustParse(t, "10.0.0.0/24"), mustParse(t, "2001:db8::/32")}
	script := New("sess-catch", targets).Render()
	want := `log prefix "warden:sess-catch:" group 1 counter`

	lines := strings.Split(script, "\n")
	chains := 0
	for i, line := range lines {
		if !strings.Contains(line, "chain forward {") {
			continue
		}
		chains++
		last := ""
		for _, inner := range lines[i+1:] {
			if strings.TrimSpace(inner) == "}" {
				break
			}
			last = strings.TrimSpace(inner)
		}
		if last != want {
			t.Fatalf("last forward-chain rule must be the catch-all log, got %q", last)
		}
	}
	if chains != 2 {
		t.Fatalf("expected 2 forward chains, found %d", chains)
	}
}

func TestLogPrefixCarriesSessionID(t *testing.T) {
	// The prefix identifies the session so a breach event does not depend
	// on which nflog socket heard the packet (E3.2 listener contract).
	script := New("sess-prefix-42", nil).Render()
	if !strings.Contains(script, `log prefix "warden:sess-prefix-42:" group 1`) {
		t.Fatal("log prefix must carry the raw session id")
	}
}
