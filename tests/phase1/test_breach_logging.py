"""
Breach logging and cross-session uplink deny gate tests.

The session ruleset must (a) unconditionally deny the 10.200.0.0/16 uplink
pool so one session's guest cannot reach another session's uplink even when
its targets claim covers the pool, and (b) log every off-scope forwarded
packet to NFLOG group 1 via the trailing catch-all rule — the breach signal
source. The catch-all carries a counter so this gate can assert exactly-one
at the kernel level, independent of the nflog listener.
"""

import re
import subprocess

import pytest

from test_uplink import _credential, _netns_name, _uplink_cidr

pytestmark = pytest.mark.linux_only


def _catch_all_packets(session_id: str) -> int:
    """Packet count on the catch-all log rule in the session's ip forward chain."""
    ns = _netns_name(session_id)
    table = "warden_" + session_id.replace("-", "_")
    chain = subprocess.check_output(
        ["ip", "netns", "exec", ns, "nft", "list", "chain", "ip", table, "forward"],
        text=True,
    )
    for line in chain.splitlines():
        if f'prefix "warden:{session_id}:"' in line and "counter" in line:
            m = re.search(r"counter packets (\d+)", line)
            assert m, f"catch-all rule has no counter: {line!r}"
            return int(m.group(1))
    pytest.fail(f"catch-all log rule not found in forward chain:\n{chain}")


def test_cross_session_uplink_unreachable(enforcer, transit_guest, dummy_targets):
    """Session A's guest cannot reach session B's uplink address even though
    A's targets claim covers the whole 10.200.0.0/16 pool. The allowed-IP
    check runs first so the deny assertion cannot pass vacuously."""
    status, body = enforcer.client.post(
        "/sessions",
        _credential("gate-e31-a", [f"{dummy_targets.allowed}/32", "10.200.0.0/16"]),
    )
    assert status == 201, f"create A failed: {body}"
    status, body = enforcer.client.post("/sessions", _credential("gate-e31-b", ["10.99.4.0/24"]))
    assert status == 201, f"create B failed: {body}"

    ping = transit_guest(_netns_name("gate-e31-a"))
    b_uplink = _uplink_cidr("gate-e31-b").split("/")[0]

    assert ping(dummy_targets.allowed), "allowlisted IP must be reachable (plumbing proof)"
    assert not ping(b_uplink), "another session's uplink must be denied despite the targets claim"


def test_off_scope_packet_logs_exactly_once(enforcer, transit_guest, dummy_targets):
    """One packet to an unlisted daddr increments the catch-all counter by
    exactly 1 — kernel-level proof the E3 log path fires, and only for
    off-scope traffic (the preceding allowed ping must not touch it)."""
    status, body = enforcer.client.post(
        "/sessions", _credential("gate-e31-log", [f"{dummy_targets.allowed}/32"])
    )
    assert status == 201, f"create failed: {body}"

    ping = transit_guest(_netns_name("gate-e31-log"))

    assert ping(dummy_targets.allowed), "allowlisted IP must be reachable (plumbing proof)"
    assert _catch_all_packets("gate-e31-log") == 0, "accepted traffic must not hit the catch-all"

    assert not ping(dummy_targets.blocked), "unlisted daddr must be dropped"
    assert _catch_all_packets("gate-e31-log") == 1, "one off-scope packet must log exactly once"
