"""
Phase 1b gate tests — nftables rule enforcement.

These tests drive the real enforcer binary over its Unix socket and assert that
the Linux kernel firewall is programmed correctly on session create/destroy.
They require a Linux kernel with nftables, root, and a built enforcer binary
(all provided by the `enforcer` fixture in conftest.py).

LinuxSandbox programs rules inside a per-session network namespace named
warden_<session_id> (hyphens replaced by underscores). Assertions read rules
from inside that namespace via `ip netns exec`.
"""

import subprocess

import pytest

pytestmark = pytest.mark.linux_only


def _netns_name(session_id: str) -> str:
    return "warden_" + session_id.replace("-", "_")


def _nft_ruleset(session_id: str) -> str:
    """Return the nftables ruleset inside the session's network namespace."""
    ns = _netns_name(session_id)
    return subprocess.check_output(
        ["ip", "netns", "exec", ns, "nft", "list", "ruleset"], text=True
    )


def _netns_exists(session_id: str) -> bool:
    ns = _netns_name(session_id)
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    return ns in result.stdout


def _credential(session_id: str, targets: list[str]) -> dict:
    return {
        "session_id": session_id,
        "agent_id": "test-agent",
        "targets": targets,
        "tools": [],
        "resources": [],
        "intent": "recon",
        "ttl_secs": 60,
    }


# ── Phase 1b: nftables rule programming ──────────────────────────────────────


def test_session_create_programs_ipv4_rules(enforcer):
    """POST /sessions writes allow rules for the credential's targets into the ip table."""
    status, _ = enforcer.client.post("/sessions", _credential("gate-1b-001", ["10.99.0.0/24"]))
    assert status == 201

    ruleset = _nft_ruleset("gate-1b-001")
    assert "10.99.0.0/24" in ruleset, "target CIDR must appear in nftables ruleset"


def test_session_create_programs_ipv6_table(enforcer):
    """POST /sessions always creates an ip6 table alongside the ip table."""
    status, _ = enforcer.client.post("/sessions", _credential("gate-1b-002", ["10.99.1.0/24"]))
    assert status == 201

    ruleset = _nft_ruleset("gate-1b-002")
    assert "table ip6" in ruleset, "ip6 table must be present even for IPv4-only targets"


def test_unconditional_blocks_present_for_any_targets(enforcer):
    """
    Metadata IPs, loopback, and link-local are blocked in both ip and ip6 tables
    regardless of what is in the targets claim — even if the targets CIDR overlaps.
    """
    status, _ = enforcer.client.post("/sessions", _credential("gate-1b-003", ["169.254.0.0/16"]))
    assert status == 201

    ruleset = _nft_ruleset("gate-1b-003")
    assert "169.254.169.254" in ruleset, "AWS metadata IPv4 must be blocked unconditionally"
    assert "fd00:ec2::254" in ruleset, "AWS metadata IPv6 must be blocked unconditionally"
    assert "fe80::/10" in ruleset, "IPv6 link-local must be blocked unconditionally"


def test_egress_filter_uses_forward_hook(enforcer):
    """The filter must hook forward (transit traffic), not output (host-local only)."""
    status, _ = enforcer.client.post("/sessions", _credential("gate-1b-fwd", ["10.99.9.0/24"]))
    assert status == 201

    ruleset = _nft_ruleset("gate-1b-fwd")
    assert "hook forward" in ruleset, "guest egress is forwarded; an output hook would not see it"


def test_session_delete_removes_rules(enforcer):
    """DELETE /sessions/{id} removes the network namespace (and its nftables tables)."""
    enforcer.client.post("/sessions", _credential("gate-1b-004", ["10.99.2.0/24"]))

    status, _ = enforcer.client.delete("/sessions/gate-1b-004")
    assert status == 204

    assert not _netns_exists("gate-1b-004"), "network namespace must be gone after session teardown"


def test_multiple_sessions_have_isolated_tables(enforcer):
    """Each session gets its own namespace; deleting one does not affect the other."""
    enforcer.client.post("/sessions", _credential("gate-1b-005", ["10.99.5.0/24"]))
    enforcer.client.post("/sessions", _credential("gate-1b-006", ["10.99.6.0/24"]))

    enforcer.client.delete("/sessions/gate-1b-005")

    assert not _netns_exists("gate-1b-005"), "deleted session's namespace must be gone"
    ruleset = _nft_ruleset("gate-1b-006")
    assert "10.99.6.0/24" in ruleset, "surviving session's CIDR must still be present"


def test_nonexistent_session_delete_returns_404(enforcer):
    """DELETE /sessions/{id} for an unknown session returns 404, not 500."""
    status, _ = enforcer.client.delete("/sessions/does-not-exist")
    assert status == 404
