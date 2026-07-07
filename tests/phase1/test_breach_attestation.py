"""
E3.4 gate — the E3 milestone end to end.

An off-scope egress attempt must become: (1) a signed breach event served by
the API, (2) a durable, fsync'd entry in the outbox spool, and (3) an entry
accepted into a REAL Rekor transparency log — the council made a real Rekor
mandatory here (a stub is exactly what would have hidden B3). The loss
counter must read zero on the clean path.

Requires ENFORCER_REKOR_URL to point at a running Rekor (the compose `gate`
profile). Skips cleanly when unset so local `pytest tests/phase1` still runs
the rest of the suite without the 5-container Rekor stack.
"""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from test_uplink import _credential, _netns_name

pytestmark = pytest.mark.linux_only


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _canonical_reduced(event: dict) -> bytes:
    """canonical(RekorPayload()): the reduced event (drops violation and
    token_claim), all-string fields → sorted-keys compact JSON is JCS."""
    reduced = {
        k: event[k]
        for k in (
            "agent_id", "attester", "attester_key_id", "breach_id",
            "layer", "session_id", "signature", "timestamp",
        )
    }
    return json.dumps(reduced, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _poll_events(client, session_id: str, deadline_s: float = 3.0):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        status, events = client.get(f"/sessions/{session_id}/events")
        assert status == 200
        if events:
            return events
        time.sleep(0.1)
    return []


def _rekor_has_hash(rekor_url: str, sha256_hex: str, deadline_s: float = 30.0) -> bool:
    """Poll Rekor's index for an entry over sha256(reduced payload). Rekor
    submission is async (spool → submitter goroutine), so allow time."""
    import http.client
    from urllib.parse import urlparse

    u = urlparse(rekor_url)
    body = json.dumps({"hash": f"sha256:{sha256_hex}"})
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
        try:
            conn.request("POST", "/api/v1/index/retrieve", body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status == 200 and json.loads(raw):
                return True
        except (OSError, json.JSONDecodeError):
            pass
        finally:
            conn.close()
        time.sleep(1.0)
    return False


def _spool_has_payload_hash(outbox_path, sha256_hex: str) -> bool:
    if not outbox_path.exists():
        return False
    for line in outbox_path.read_text().splitlines():
        if json.loads(line).get("payload_sha256") == sha256_hex:
            return True
    return False


def test_off_scope_breach_reaches_events_spool_and_rekor(enforcer, transit_guest, dummy_targets):
    if not enforcer.rekor_url:
        pytest.skip("ENFORCER_REKOR_URL unset — start the compose `gate` profile to run the E3 gate")

    status, body = enforcer.client.post(
        "/sessions", _credential("gate-e34-001", [f"{dummy_targets.allowed}/32"])
    )
    assert status == 201, f"create failed: {body}"

    ping = transit_guest(_netns_name("gate-e34-001"))
    assert ping(dummy_targets.allowed), "allowlisted IP must be reachable (plumbing proof)"
    assert not ping(dummy_targets.blocked), "off-scope daddr must be dropped"

    # 1. Signed event at the API, signature verifies against the active key.
    events = _poll_events(enforcer.client, "gate-e34-001")
    assert len(events) == 1, f"expected one event, got {len(events)}: {events}"
    ev = events[0]

    status, jwk = enforcer.client.get("/enforcer/keys/active")
    assert status == 200 and jwk["key_id"] == ev["attester_key_id"]
    reduced = _canonical_reduced(ev)
    Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"])).verify(_b64url(ev["signature"]), _b64url_signable(ev))

    # 2. Durable, content-addressed spool entry.
    payload_hash = hashlib.sha256(reduced).hexdigest()
    assert _spool_has_payload_hash(enforcer.outbox_path, payload_hash), (
        "signed event must be persisted to the fsync'd outbox spool"
    )

    # 3. Accepted into the real Rekor log (async submission).
    assert _rekor_has_hash(enforcer.rekor_url, payload_hash), (
        "reduced payload hash must appear in the Rekor transparency log"
    )

    # 4. Clean path: no losses.
    status, _events = enforcer.client.get("/sessions/gate-e34-001/events")
    # header exposed via the raw client below
    lost = _lost_header(enforcer.socket_path, "/sessions/gate-e34-001/events")
    assert lost == "0", f"X-Warden-Lost-Events must be 0 on the clean path, got {lost}"


def _b64url_signable(event: dict) -> bytes:
    """Canonical bytes of the FULL event minus signature — what the primary
    Ed25519 signature covers (distinct from the reduced Rekor payload)."""
    body = {k: v for k, v in event.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _lost_header(socket_path, path: str) -> str:
    """Read the X-Warden-Lost-Events header (EnforcerClient discards headers)."""
    import http.client
    import socket as _socket

    class _Conn(http.client.HTTPConnection):
        def connect(self):
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.connect(str(socket_path))
            self.sock = s

    conn = _Conn("localhost")
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.getheader("X-Warden-Lost-Events", "")
    finally:
        conn.close()
