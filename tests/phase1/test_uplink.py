"""
Veth/uplink provisioning and transit-traffic containment gate tests.

Session create must leave the namespace with a working uplink to the root
namespace (veth pair, /30 from 10.200.0.0/16, default route, ip_forward=1),
and the already-programmed forward-hook rules must contain transit traffic:
allowlisted IPs reachable, everything else — including the metadata IP even
when the targets claim overlaps it — provably not.
"""

import subprocess
import time

import pytest

pytestmark = pytest.mark.linux_only


def _netns_name(session_id: str) -> str:
    return "warden_" + session_id.replace("-", "_")


def _ns_exec(session_id: str, *args: str) -> str:
    ns = _netns_name(session_id)
    return subprocess.check_output(["ip", "netns", "exec", ns, *args], text=True)


def _uplink_cidr(session_id: str) -> str:
    """The namespace-side uplink address, e.g. '10.200.0.2/30'."""
    out = _ns_exec(session_id, "ip", "-o", "-4", "addr", "show", "dev", "uplink")
    return out.split()[3]


def _host_veth(session_id: str) -> str:
    """Derive the host-side interface name wdn<idx> from the ns-side address."""
    addr = _uplink_cidr(session_id).split("/")[0]
    _, _, oct3, oct4 = (int(o) for o in addr.split("."))
    idx = ((oct3 << 8) + oct4 - 2) // 4
    return f"wdn{idx}"


def _host_veth_exists(name: str) -> bool:
    return subprocess.run(["ip", "link", "show", name], capture_output=True).returncode == 0


def _host_veth_gone(name: str, timeout_s: float = 3.0) -> bool:
    """Kernel netns teardown is asynchronous (the cleanup_net workqueue runs
    after `ip netns del` returns), so the host veth unregisters shortly after
    session delete — poll rather than assert instantaneously. A genuine
    reference leak (e.g. a listener socket left open) still holds the veth
    past the deadline and fails."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not _host_veth_exists(name):
            return True
        time.sleep(0.05)
    return False


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


# ── Uplink provisioning ──────────────────────────────────────────────────────


def test_session_create_provisions_uplink(enforcer):
    """POST /sessions leaves the ns with an addressed uplink, default route,
    forwarding enabled, and the host-side veth present."""
    status, body = enforcer.client.post("/sessions", _credential("gate-m13-001", ["10.99.0.0/24"]))
    assert status == 201, f"create failed: {body}"

    cidr = _uplink_cidr("gate-m13-001")
    assert cidr.startswith("10.200.") and cidr.endswith("/30"), f"unexpected uplink addr {cidr}"

    routes = _ns_exec("gate-m13-001", "ip", "route")
    assert "default via 10.200." in routes, "namespace must default-route via the host veth"

    forwarding = _ns_exec("gate-m13-001", "sysctl", "-n", "net.ipv4.ip_forward").strip()
    assert forwarding == "1", "ip_forward must be enabled inside the namespace"

    assert _host_veth_exists(_host_veth("gate-m13-001")), "host-side veth must exist"


def test_sessions_get_distinct_subnets(enforcer):
    """Two live sessions must not share an uplink /30."""
    for sid, target in (("gate-m13-002", "10.99.1.0/24"), ("gate-m13-003", "10.99.2.0/24")):
        status, body = enforcer.client.post("/sessions", _credential(sid, [target]))
        assert status == 201, f"create {sid} failed: {body}"

    assert _uplink_cidr("gate-m13-002") != _uplink_cidr("gate-m13-003")


def test_session_delete_removes_host_veth(enforcer):
    """Deleting the session (its netns) must take the host-side veth with it."""
    status, body = enforcer.client.post("/sessions", _credential("gate-m13-004", ["10.99.3.0/24"]))
    assert status == 201, f"create failed: {body}"
    host_if = _host_veth("gate-m13-004")
    assert _host_veth_exists(host_if)

    status, _ = enforcer.client.delete("/sessions/gate-m13-004")
    assert status == 204
    assert _host_veth_gone(host_if), "host-side veth must be gone after teardown"


# ── Transit traffic containment ──────────────────────────────────────────────


def test_guest_egress_contained(enforcer, transit_guest, dummy_targets):
    """
    Traffic transiting the session ns reaches allowlisted IPs and nothing
    else. The targets claim deliberately overlaps the metadata range to prove
    the unconditional deny cannot be overridden. The allowed-IP check runs
    first: it proves the packet path works, so the blocked assertions cannot
    pass vacuously on broken plumbing.
    """
    status, body = enforcer.client.post(
        "/sessions",
        _credential("gate-m13-e2", [f"{dummy_targets.allowed}/32", "169.254.0.0/16"]),
    )
    assert status == 201, f"create failed: {body}"

    ping = transit_guest(_netns_name("gate-m13-e2"))

    assert ping(dummy_targets.allowed), "allowlisted IP must be reachable through the uplink"
    assert not ping(dummy_targets.blocked), "off-allowlist IP must be dropped by the forward chain"
    assert not ping(dummy_targets.metadata), (
        "metadata IP must stay blocked even when the targets claim covers it"
    )
