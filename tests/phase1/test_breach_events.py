"""
Breach-event emission gate tests: nflog listener → signed events.

An off-scope packet dropped by the session's forward chain must surface as
exactly one signed breach event at GET /sessions/{id}/events, and the
signature must verify against the active key JWK — the kernel-level
assertion running end-to-end through the listener and consumer.
"""

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from test_uplink import _credential, _netns_name

pytestmark = pytest.mark.linux_only


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _signable(event: dict) -> bytes:
    """RFC 8785 canonical bytes of the event minus signature. All fields are
    strings, so sorted-keys compact JSON is JCS-equivalent."""
    body = {k: v for k, v in event.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _poll_events(client, session_id: str, deadline_s: float = 3.0):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        status, events = client.get(f"/sessions/{session_id}/events")
        assert status == 200
        if events:
            return events
        time.sleep(0.1)
    return []


def test_off_scope_attempt_yields_one_verifiable_event(enforcer, transit_guest, dummy_targets):
    status, body = enforcer.client.post(
        "/sessions", _credential("gate-e32-001", [f"{dummy_targets.allowed}/32"])
    )
    assert status == 201, f"create failed: {body}"

    ping = transit_guest(_netns_name("gate-e32-001"))
    assert ping(dummy_targets.allowed), "allowlisted IP must be reachable (plumbing proof)"

    status, events = enforcer.client.get("/sessions/gate-e32-001/events")
    assert status == 200 and events == [], "no events before the off-scope attempt"

    assert not ping(dummy_targets.blocked), "unlisted daddr must be dropped"

    events = _poll_events(enforcer.client, "gate-e32-001")
    assert len(events) == 1, f"expected exactly one event, got {len(events)}: {events}"

    ev = events[0]
    assert ev["session_id"] == "gate-e32-001"
    assert ev["agent_id"] == "test-agent"
    assert ev["layer"] == "network"
    assert ev["attester"] == "warden-enforcer"
    assert ev["token_claim"] == "targets"
    assert dummy_targets.blocked in ev["violation"]

    status, jwk = enforcer.client.get("/enforcer/keys/active")
    assert status == 200 and jwk["key_id"] == ev["attester_key_id"]
    pub = Ed25519PublicKey.from_public_bytes(_b64url(jwk["x"]))
    pub.verify(_b64url(ev["signature"]), _signable(ev))  # raises InvalidSignature on failure


def test_events_gone_after_session_delete(enforcer, transit_guest, dummy_targets):
    """Teardown closes the listener with the session; the events endpoint
    404s once the session record is gone."""
    status, body = enforcer.client.post(
        "/sessions", _credential("gate-e32-002", [f"{dummy_targets.allowed}/32"])
    )
    assert status == 201, f"create failed: {body}"
    ping = transit_guest(_netns_name("gate-e32-002"))
    assert not ping(dummy_targets.blocked)
    assert len(_poll_events(enforcer.client, "gate-e32-002")) == 1

    status, _ = enforcer.client.delete("/sessions/gate-e32-002")
    assert status == 204
    status, _ = enforcer.client.get("/sessions/gate-e32-002/events")
    assert status == 404
