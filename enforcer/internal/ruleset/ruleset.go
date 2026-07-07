// Package ruleset mirrors enforcer/src/ruleset.rs: a complete nftables
// ruleset for one session.
//
// Render produces an nft script suitable for `nft -f`. The script creates
// two named tables (`table ip` and `table ip6`) whose names embed the
// session ID, allowing multiple sessions to coexist without collision.
// Output was byte-identical to the Rust renderer through M13; E3.1
// added NFLOG breach logging and the uplink-pool deny, and the
// testdata/*.nft goldens are Go-owned from that point (see PARITY.md).
package ruleset

import (
	"fmt"
	"strings"

	"github.com/NoOneNoWhere1/warden-enforcer/enforcer/internal/cidr"
)

// unconditionalDenyIPv4 lists IPv4 addresses unconditionally blocked in
// every session ruleset. Inserted before any targets-derived accept rules;
// cannot be overridden by the targets claim in the credential.
var unconditionalDenyIPv4 = []string{
	"169.254.169.254/32", // AWS / GCP / Azure instance metadata endpoint
	"127.0.0.0/8",        // loopback
	"10.200.0.0/16",      // uplink veth pool — a targets claim must not reach another session's uplink
}

// unconditionalDenyIPv6 lists IPv6 addresses unconditionally blocked in
// every session ruleset.
var unconditionalDenyIPv6 = []string{
	"fd00:ec2::254/128", // AWS EC2 instance metadata over IPv6
	"::1/128",           // loopback
	"fe80::/10",         // link-local
}

type Ruleset struct {
	sessionID string
	targets   []cidr.Cidr
}

func New(sessionID string, targets []cidr.Cidr) *Ruleset {
	return &Ruleset{sessionID: sessionID, targets: targets}
}

// Render renders the complete nft script for this session.
//
// The script is applied inside the session's network namespace with
// `nft -f`. The agent runs in a guest (Firecracker microVM or gVisor
// netstack) whose egress *transits* the namespace across a tap/veth —
// it is forwarded (prerouting → forward → postrouting), never locally
// generated. The filter therefore hooks `forward`, not `output`: an
// `output` filter would only see host-local sockets and would silently
// fail to contain (or log) the guest's off-scope packets.
//
// Guarantees:
//   - Unconditional deny rules always precede any targets-derived accept
//     rules, so a `targets` claim can never unblock metadata/loopback.
//   - Each table is replaced atomically (`add; delete; add` under one
//     `nft -f` transaction) — there is no window where the old rules are
//     gone but the new ones are not yet active during a credential update.
func (r *Ruleset) Render() string {
	table := r.tableName()
	var out strings.Builder

	// E3 breach signal: every denied packet logs to NFLOG group 1. The
	// prefix carries the session ID so an event does not depend on which
	// nflog socket heard it. Injection-safe without validation: the same
	// session ID is rendered (hyphen-sanitized only) as the table
	// identifier above any log rule, and every character that could escape
	// this quoted string is invalid in an nft identifier — a hostile ID
	// fails the whole-script parse before a single rule is applied.
	logStmt := fmt.Sprintf("log prefix \"warden:%s:\" group 1", r.sessionID)

	// ── IPv4 table ────────────────────────────────────────────────────
	// Atomic replace idiom: ensure the table exists, delete it, recreate.
	// The leading create makes the delete safe on first apply.
	fmt.Fprintf(&out, "table ip %s { }\n", table)
	fmt.Fprintf(&out, "delete table ip %s\n", table)
	fmt.Fprintf(&out, "table ip %s {\n", table)
	out.WriteString("    chain forward {\n")
	out.WriteString("        type filter hook forward priority 0; policy drop;\n")

	for _, deny := range unconditionalDenyIPv4 {
		fmt.Fprintf(&out, "        ip daddr %s %s drop\n", deny, logStmt)
	}
	// Return traffic for connections that were already permitted. Without
	// this the default-drop forward policy discards every reply packet
	// (its daddr is the guest, not a target), so no connection completes.
	out.WriteString("        ct state established,related accept\n")
	for _, target := range r.targets {
		if target.Addr().Is4() {
			fmt.Fprintf(&out, "        ip daddr %s accept\n", target)
		}
	}
	// Catch-all breach log (B1): off-scope packets otherwise fall through
	// to the chain policy, which cannot log — this rule is E3's signal
	// source for genuine off-scope access. No verdict: the packet continues
	// to the policy drop. The counter is the gate-test observable.
	fmt.Fprintf(&out, "        %s counter\n", logStmt)
	out.WriteString("    }\n")

	// Source NAT: rewrite the guest's private source address to the
	// namespace uplink address so accepted egress is routable and replies
	// return. Forwarding without NAT leaves accepted packets unanswerable.
	out.WriteString("    chain postrouting {\n")
	out.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
	out.WriteString("        masquerade\n")
	out.WriteString("    }\n")
	out.WriteString("}\n")

	// ── IPv6 table (always present) ───────────────────────────────────
	// Filter-only. The v1 session namespace has no IPv6 uplink, so this
	// table exists purely to contain (default-deny forward) — a CIDR
	// expressed as IPv4 must not be reachable over IPv6. No NAT.
	fmt.Fprintf(&out, "table ip6 %s { }\n", table)
	fmt.Fprintf(&out, "delete table ip6 %s\n", table)
	fmt.Fprintf(&out, "table ip6 %s {\n", table)
	out.WriteString("    chain forward {\n")
	out.WriteString("        type filter hook forward priority 0; policy drop;\n")

	for _, deny := range unconditionalDenyIPv6 {
		fmt.Fprintf(&out, "        ip6 daddr %s %s drop\n", deny, logStmt)
	}
	out.WriteString("        ct state established,related accept\n")
	for _, target := range r.targets {
		if !target.Addr().Is4() {
			fmt.Fprintf(&out, "        ip6 daddr %s accept\n", target)
		}
	}
	fmt.Fprintf(&out, "        %s counter\n", logStmt)
	out.WriteString("    }\n}\n")

	return out.String()
}

// tableName sanitizes the session ID for use as an nftables table name.
// nftables identifiers cannot contain hyphens; replace with underscores.
func (r *Ruleset) tableName() string {
	return "warden_" + strings.ReplaceAll(r.sessionID, "-", "_")
}
