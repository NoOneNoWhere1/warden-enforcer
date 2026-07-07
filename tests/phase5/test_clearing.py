"""Phase 5 clearing service tests — all non-linux_only."""

import base64
import decimal
import hashlib
import http.client as _http_client
import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clearing import service

_VECTOR_PATH = Path(__file__).parents[2] / "enforcer/tests/conformance/breach_event_v1.json"


def _load_vector() -> dict:
    return json.loads(_VECTOR_PATH.read_text())


# ── Conformance ───────────────────────────────────────────────────────────────

def test_conformance_canonical_signable():
    v = _load_vector()
    result = service._canonical_signable(v["event"])
    assert result == v["canonical_json"].encode()


def test_conformance_signature_verifies():
    v = _load_vector()
    pub_bytes = base64.urlsafe_b64decode(
        v["public_key_b64url"] + "=" * (-len(v["public_key_b64url"]) % 4)
    )
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    sig = service._b64url_decode(v["signature_b64url"])
    pub.verify(sig, service._canonical_signable(v["event"]))  # raises InvalidSignature on fail


def test_canonical_reduced_excludes_violation_and_token_claim():
    event = {
        "agent_id": "a", "attester": "b", "attester_key_id": "c",
        "breach_id": "d", "layer": "e", "session_id": "f",
        "signature": "g", "timestamp": "h",
        "token_claim": "SHOULD_NOT_APPEAR",
        "violation": "SHOULD_NOT_APPEAR",
    }
    result = json.loads(service._canonical_reduced(event))
    expected_keys = {
        "agent_id", "attester", "attester_key_id", "breach_id",
        "layer", "session_id", "signature", "timestamp",
    }
    assert set(result.keys()) == expected_keys
    assert "violation" not in result
    assert "token_claim" not in result
    assert result["signature"] == "g"


def test_pem_to_jwk_roundtrip():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    jwk = service._pem_to_jwk(pem)
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    assert raw == pub.public_bytes_raw()


def test_verify_entry_valid(spool_entry):
    entry, _ = spool_entry
    assert service._verify_entry(entry) is True


def test_verify_entry_tampered(spool_entry):
    entry, _ = spool_entry
    tampered = {**entry, "event": {**entry["event"], "breach_id": "tampered-id"}}
    assert service._verify_entry(tampered) is False


# ── Ingest ────────────────────────────────────────────────────────────────────

def test_ingest_inserts_outbox_slash_and_kills(db_tx, spool_entry, monkeypatch, insert_fk_chain):
    entry, outbox = spool_entry
    event = entry["event"]
    insert_fk_chain(db_tx, event["agent_id"], event["session_id"], "op-ingest-001")

    calls = []
    monkeypatch.setattr(service, "enforcer_delete", lambda _sock, sid: calls.append(sid) or 204)

    count = service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))
    assert count == 1

    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT id FROM attestation_outbox WHERE event_json->>'breach_id' = %s",
            (event["breach_id"],),
        )
        assert cur.fetchone() is not None, "outbox row missing"

        cur.execute(
            "SELECT status, breach_id, agent_id, reputation_penalty "
            "FROM slash_event WHERE session_id = %s",
            (event["session_id"],),
        )
        row = cur.fetchone()
        assert row is not None, "slash_event row missing"
        assert row[0] == "pending"
        assert row[1] == event["breach_id"]
        assert row[2] == event["agent_id"]
        assert row[3] == 10

        cur.execute(
            "SELECT terminated_at FROM session WHERE session_id = %s",
            (event["session_id"],),
        )
        sess = cur.fetchone()
        assert sess is not None and sess[0] is not None, "session not terminated"

    assert calls == [event["session_id"]]


def test_ingest_deduplicates(db_tx, spool_entry, monkeypatch):
    entry, outbox = spool_entry
    monkeypatch.setattr(service, "enforcer_delete", lambda *_: 204)

    service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))
    count2 = service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))
    assert count2 == 0

    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM attestation_outbox WHERE event_json->>'breach_id' = %s",
            (entry["event"]["breach_id"],),
        )
        assert cur.fetchone()[0] == 1

        cur.execute(
            "SELECT COUNT(*) FROM slash_event WHERE breach_id = %s",
            (entry["event"]["breach_id"],),
        )
        assert cur.fetchone()[0] == 1


def test_ingest_null_operator_when_no_session_row(db_tx, spool_entry, monkeypatch):
    """No session row → slash_event created with operator_id=NULL, no crash."""
    entry, outbox = spool_entry
    monkeypatch.setattr(service, "enforcer_delete", lambda *_: 204)

    count = service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))
    assert count == 1

    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT operator_id FROM slash_event WHERE breach_id = %s",
            (entry["event"]["breach_id"],),
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] is None


def test_signing_key_mismatch_skips_entry(db_tx, spool_entry, monkeypatch):
    """Pre-existing signing_key with same key_id but different x → entry skipped."""
    entry, outbox = spool_entry
    key_id = entry["event"]["attester_key_id"]

    # Pre-insert a signing key with a DIFFERENT public key
    different_priv = Ed25519PrivateKey.generate()
    different_x = (
        base64.urlsafe_b64encode(different_priv.public_key().public_bytes_raw())
        .rstrip(b"=").decode()
    )
    with db_tx.cursor() as cur:
        cur.execute(
            "INSERT INTO signing_key (key_id, attester, public_key) "
            "VALUES (%s, 'warden-enforcer', %s::jsonb)",
            (key_id, json.dumps({"kty": "OKP", "crv": "Ed25519", "x": different_x})),
        )

    monkeypatch.setattr(service, "enforcer_delete", lambda *_: 204)
    count = service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))
    assert count == 0

    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM attestation_outbox WHERE event_json->>'breach_id' = %s",
            (entry["event"]["breach_id"],),
        )
        assert cur.fetchone()[0] == 0


# ── Confirm ───────────────────────────────────────────────────────────────────

def test_confirm_sets_submitted_and_breach_log_entry_id(
    db_tx, spool_entry, stub_rekor, monkeypatch
):
    entry, outbox = spool_entry
    monkeypatch.setattr(service, "enforcer_delete", lambda *_: 204)
    service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))

    count = service.confirm(db_tx, stub_rekor)
    assert count == 1

    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT submitted_at, rekor_entry_id FROM attestation_outbox "
            "WHERE event_json->>'breach_id' = %s",
            (entry["event"]["breach_id"],),
        )
        outbox_row = cur.fetchone()
        assert outbox_row[0] is not None, "submitted_at not set"
        assert outbox_row[1] == "stub-rekor-uuid-001"

        cur.execute(
            "SELECT breach_log_entry_id FROM slash_event WHERE breach_id = %s",
            (entry["event"]["breach_id"],),
        )
        slash_row = cur.fetchone()
        assert slash_row[0] == "stub-rekor-uuid-001"


def test_confirm_noop_when_rekor_down(db_tx, spool_entry, monkeypatch):
    entry, outbox = spool_entry
    monkeypatch.setattr(service, "enforcer_delete", lambda *_: 204)
    service.ingest_and_kill(db_tx, "/fake.sock", str(outbox))

    count = service.confirm(db_tx, "http://127.0.0.1:1")  # unreachable port
    assert count == 0

    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT submitted_at FROM attestation_outbox WHERE event_json->>'breach_id' = %s",
            (entry["event"]["breach_id"],),
        )
        assert cur.fetchone()[0] is None


# ── Slash helpers ─────────────────────────────────────────────────────────────

def _insert_slash_preconditions(
    conn, *, agent_id: str, operator_id: str, session_id: str, breach_id: str,
    bond_amount: str = "1000.00", reputation_score: int = 100,
    slash_amount: str = "100.00", reputation_penalty: int = 10,
) -> None:
    """Insert a complete slash-ready precondition set: signing_key + FK chain + slash_event."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO signing_key (key_id, attester, public_key) "
            "VALUES ('key-slash-001', 'warden-enforcer', '{\"kty\":\"OKP\"}'::jsonb) "
            "ON CONFLICT DO NOTHING"
        )
        cur.execute(
            "INSERT INTO operator_bond (operator_id, amount_usd, status) "
            "VALUES (%s, %s, 'active')",
            (operator_id, bond_amount),
        )
        cur.execute(
            "INSERT INTO agent_identity "
            "(agent_id, did_web_url, public_key_jwk, operator_id, reputation_score) "
            "VALUES (%s, %s, '{\"kty\":\"OKP\"}'::jsonb, %s, %s)",
            (agent_id, f"https://example.com/{agent_id}", operator_id, reputation_score),
        )
        cur.execute(
            "INSERT INTO session (session_id, agent_id, operator_id, expires_at) "
            "VALUES (%s, %s, %s, now() + INTERVAL '1 hour')",
            (session_id, agent_id, operator_id),
        )
        # slash_event in pending+confirmed state (breach_log_entry_id set → ready for slash)
        cur.execute(
            "INSERT INTO slash_event "
            "(session_id, breach_id, agent_id, attester_key_id, operator_id, "
            " amount_usd, reputation_penalty, status, breach_log_entry_id) "
            "VALUES (%s, %s, %s, 'key-slash-001', %s, %s, %s, 'pending', 'some-rekor-uuid')",
            (session_id, breach_id, agent_id, operator_id, slash_amount, reputation_penalty),
        )


# ── Slash tests ───────────────────────────────────────────────────────────────

def test_slash_decrements_agent_reputation(db_tx):
    _insert_slash_preconditions(
        db_tx, agent_id="agent-s1", operator_id="op-s1",
        session_id="sess-s1", breach_id="breach-s1",
    )
    executed = service.slash(db_tx)
    assert executed == 1
    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT reputation_score FROM agent_identity WHERE agent_id = 'agent-s1'"
        )
        assert cur.fetchone()[0] == 90
        cur.execute("SELECT status FROM slash_event WHERE breach_id = 'breach-s1'")
        assert cur.fetchone()[0] == "executed"


def test_reputation_floors_at_zero(db_tx):
    _insert_slash_preconditions(
        db_tx, agent_id="agent-s2", operator_id="op-s2",
        session_id="sess-s2", breach_id="breach-s2",
        reputation_score=5,
    )
    service.slash(db_tx)
    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT reputation_score FROM agent_identity WHERE agent_id = 'agent-s2'"
        )
        assert cur.fetchone()[0] == 0


def test_slash_unknown_agent_still_executes(db_tx):
    """slash_event.agent_id with no agent_identity row → still executed (warn only)."""
    with db_tx.cursor() as cur:
        cur.execute(
            "INSERT INTO signing_key (key_id, attester, public_key) "
            "VALUES ('key-slash-unk', 'warden-enforcer', '{\"kty\":\"OKP\"}'::jsonb) "
            "ON CONFLICT DO NOTHING"
        )
        cur.execute(
            "INSERT INTO operator_bond (operator_id, amount_usd, status) "
            "VALUES ('op-unk', '1000.00', 'active')"
        )
        # Deliberately NO agent_identity row
        cur.execute(
            "INSERT INTO slash_event "
            "(session_id, breach_id, agent_id, attester_key_id, operator_id, "
            " amount_usd, reputation_penalty, status, breach_log_entry_id) "
            "VALUES ('sess-unk', 'breach-unk', 'agent-nonexistent', "
            "        'key-slash-unk', 'op-unk', '100.00', 10, 'pending', 'some-uuid')"
        )

    executed = service.slash(db_tx)
    assert executed == 1
    with db_tx.cursor() as cur:
        cur.execute("SELECT status FROM slash_event WHERE breach_id = 'breach-unk'")
        assert cur.fetchone()[0] == "executed"


def test_slash_decrements_bond_bookkeeping(db_tx):
    _insert_slash_preconditions(
        db_tx, agent_id="agent-s3", operator_id="op-s3",
        session_id="sess-s3", breach_id="breach-s3",
        bond_amount="1000.00",
    )
    service.slash(db_tx)
    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT amount_usd, status FROM operator_bond WHERE operator_id = 'op-s3'"
        )
        row = cur.fetchone()
        assert row[0] == decimal.Decimal("900.00")
        assert row[1] == "active"


def test_slash_depletes_below_zero(db_tx):
    _insert_slash_preconditions(
        db_tx, agent_id="agent-s4", operator_id="op-s4",
        session_id="sess-s4", breach_id="breach-s4",
        bond_amount="50.00",
    )
    service.slash(db_tx)
    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT amount_usd, status FROM operator_bond WHERE operator_id = 'op-s4'"
        )
        row = cur.fetchone()
        assert row[0] == decimal.Decimal("-50.00")
        assert row[1] == "depleted"


def test_slash_null_operator_skips_bond_only(db_tx):
    """operator_id=NULL in slash_event → reputation decremented, bond untouched, executed."""
    with db_tx.cursor() as cur:
        cur.execute(
            "INSERT INTO signing_key (key_id, attester, public_key) "
            "VALUES ('key-slash-null', 'warden-enforcer', '{\"kty\":\"OKP\"}'::jsonb) "
            "ON CONFLICT DO NOTHING"
        )
        # agent_identity with a dummy operator (no FK check on agent_identity.operator_id)
        cur.execute(
            "INSERT INTO agent_identity "
            "(agent_id, did_web_url, public_key_jwk, operator_id, reputation_score) "
            "VALUES ('agent-null-op', 'https://example.com', "
            "        '{\"kty\":\"OKP\"}'::jsonb, 'op-placeholder', 100)"
        )
        # slash_event with operator_id=NULL
        cur.execute(
            "INSERT INTO slash_event "
            "(session_id, breach_id, agent_id, attester_key_id, operator_id, "
            " amount_usd, reputation_penalty, status, breach_log_entry_id) "
            "VALUES ('sess-null-op', 'breach-null-op', 'agent-null-op', "
            "        'key-slash-null', NULL, '100.00', 10, 'pending', 'some-uuid')"
        )

    executed = service.slash(db_tx)
    assert executed == 1
    with db_tx.cursor() as cur:
        cur.execute(
            "SELECT reputation_score FROM agent_identity WHERE agent_id = 'agent-null-op'"
        )
        assert cur.fetchone()[0] == 90
        cur.execute("SELECT status FROM slash_event WHERE breach_id = 'breach-null-op'")
        assert cur.fetchone()[0] == "executed"


# ── Withdrawal guard tests ────────────────────────────────────────────────────

def _insert_bond_eligible(conn, operator_id: str, hold_days: int = 7, days_ago: int = 8,
                           bond_amount: str = "1000.00") -> None:
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO operator_bond "
            "(operator_id, amount_usd, status, withdrawal_requested_at, withdrawal_hold_days) "
            "VALUES (%s, %s, 'active', now() - %s * INTERVAL '1 day', %s)",
            (operator_id, bond_amount, days_ago, hold_days),
        )


def test_withdrawal_released_after_hold(db_tx):
    _insert_bond_eligible(db_tx, "op-w1", hold_days=7, days_ago=8)
    released = service.withdrawal_guard(db_tx)
    assert released == 1
    with db_tx.cursor() as cur:
        cur.execute("SELECT status FROM operator_bond WHERE operator_id = 'op-w1'")
        assert cur.fetchone()[0] == "withdrawn"


def test_withdrawal_blocked_pending_slash(db_tx):
    _insert_bond_eligible(db_tx, "op-w2")
    with db_tx.cursor() as cur:
        cur.execute(
            "INSERT INTO signing_key (key_id, attester, public_key) "
            "VALUES ('key-w2', 'warden-enforcer', '{\"kty\":\"OKP\"}'::jsonb) "
            "ON CONFLICT DO NOTHING"
        )
        cur.execute(
            "INSERT INTO slash_event "
            "(session_id, breach_id, agent_id, attester_key_id, operator_id, "
            " amount_usd, reputation_penalty, status) "
            "VALUES ('sess-w2', 'breach-w2', 'agent-w2', 'key-w2', 'op-w2', "
            "        '100.00', 10, 'pending')"
        )
    released = service.withdrawal_guard(db_tx)
    assert released == 0
    with db_tx.cursor() as cur:
        cur.execute("SELECT status FROM operator_bond WHERE operator_id = 'op-w2'")
        assert cur.fetchone()[0] == "active"


def test_withdrawal_blocked_unconfirmed_outbox(db_tx):
    _insert_bond_eligible(db_tx, "op-w3")
    with db_tx.cursor() as cur:
        cur.execute(
            "INSERT INTO agent_identity "
            "(agent_id, did_web_url, public_key_jwk, operator_id) "
            "VALUES ('agent-w3', 'https://example.com', '{\"kty\":\"OKP\"}'::jsonb, 'op-w3')"
        )
        cur.execute(
            "INSERT INTO session (session_id, agent_id, operator_id, expires_at) "
            "VALUES ('sess-w3', 'agent-w3', 'op-w3', now() + INTERVAL '1 hour')"
        )
        # Unconfirmed outbox entry referencing the operator's session
        cur.execute(
            "INSERT INTO attestation_outbox (event_json, attester) "
            "VALUES (%s, 'warden-enforcer')",
            (json.dumps({"session_id": "sess-w3", "breach_id": "breach-w3-outbox"}),),
        )
    released = service.withdrawal_guard(db_tx)
    assert released == 0
    with db_tx.cursor() as cur:
        cur.execute("SELECT status FROM operator_bond WHERE operator_id = 'op-w3'")
        assert cur.fetchone()[0] == "active"


def test_withdrawal_blocked_before_hold_expiry(db_tx):
    _insert_bond_eligible(db_tx, "op-w4", hold_days=7, days_ago=1)
    released = service.withdrawal_guard(db_tx)
    assert released == 0
    with db_tx.cursor() as cur:
        cur.execute("SELECT status FROM operator_bond WHERE operator_id = 'op-w4'")
        assert cur.fetchone()[0] == "active"


# ── B1 gate test — linux_only ─────────────────────────────────────────────────

_B1_SESSION = "b1-gate-001"
_B1_AGENT = "b1-agent-001"
_B1_OPERATOR = "b1-op-001"


def _b1_netns(session_id: str) -> str:
    return "warden_" + session_id.replace("-", "_")


def _b1_poll_events(client, session_id: str, deadline_s: float = 5.0) -> list:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        status, events = client.get(f"/sessions/{session_id}/events")
        if status == 200 and events:
            return events
        time.sleep(0.1)
    return []


def _b1_spool_has_hash(outbox_path: Path, sha256_hex: str) -> bool:
    if not outbox_path.exists():
        return False
    for line in outbox_path.read_text().splitlines():
        try:
            if json.loads(line).get("payload_sha256") == sha256_hex:
                return True
        except json.JSONDecodeError:
            pass
    return False


def _b1_rekor_has_hash(rekor_url: str, sha256_hex: str, deadline_s: float = 30.0) -> bool:
    u = urlparse(rekor_url)
    body = json.dumps({"hash": f"sha256:{sha256_hex}"}).encode()
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            conn = _http_client.HTTPConnection(u.hostname, u.port, timeout=5)
            conn.request("POST", "/api/v1/index/retrieve", body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            raw = resp.read()
            conn.close()
            if resp.status == 200 and json.loads(raw):
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


@pytest.mark.linux_only
def test_b1_breach_to_slash_end_to_end(enforcer, transit_guest, dummy_targets):
    """B1 gate: real enforcer + real Rekor + real DB → full clearing pipeline."""
    if not enforcer.rekor_url:
        pytest.skip("ENFORCER_REKOR_URL unset — start compose gate profile")
    if not os.environ.get("POSTGRES_PASSWORD"):
        pytest.skip("POSTGRES_PASSWORD unset — set POSTGRES_PASSWORD and start postgres")

    import psycopg2  # noqa: PLC0415 (lazy: only available when gate runs)

    db_conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5433")),
        dbname=os.getenv("POSTGRES_DB", "warden"),
        user=os.getenv("POSTGRES_USER", "postgres"),
        password=os.environ["POSTGRES_PASSWORD"],
    )
    db_conn.autocommit = False

    try:
        # Insert FK chain committed — run_once commits, so we can't use db_tx.
        with db_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operator_bond (operator_id, amount_usd, status) "
                "VALUES (%s, '1000.00', 'active')",
                (_B1_OPERATOR,),
            )
            cur.execute(
                "INSERT INTO agent_identity "
                "(agent_id, did_web_url, public_key_jwk, operator_id, reputation_score) "
                "VALUES (%s, 'https://example.com/b1', '{\"kty\":\"OKP\"}'::jsonb, %s, 100)",
                (_B1_AGENT, _B1_OPERATOR),
            )
            cur.execute(
                "INSERT INTO session (session_id, agent_id, operator_id, expires_at) "
                "VALUES (%s, %s, %s, now() + INTERVAL '1 hour')",
                (_B1_SESSION, _B1_AGENT, _B1_OPERATOR),
            )
        db_conn.commit()

        # Register the session with the enforcer (programs nftables ruleset).
        cred = {
            "session_id": _B1_SESSION,
            "agent_id": _B1_AGENT,
            "targets": [f"{dummy_targets.allowed}/32"],
            "tools": [],
            "resources": [],
            "intent": "recon",
            "ttl_secs": 60,
        }
        status, body = enforcer.client.post("/sessions", cred)
        assert status == 201, f"POST /sessions failed: {status} {body}"

        # Trigger an off-scope drop via the guest transit namespace.
        session_ns = _b1_netns(_B1_SESSION)
        ping = transit_guest(session_ns)
        assert not ping(dummy_targets.blocked), "off-scope IP must be dropped"

        # 1. Wait for spool entry (enforcer NFLOG → signed event → fsync'd outbox).
        events = _b1_poll_events(enforcer.client, _B1_SESSION, deadline_s=5.0)
        assert len(events) >= 1, f"no breach events seen after 5s: {events}"
        ev = events[0]

        payload_hash = hashlib.sha256(service._canonical_reduced(ev)).hexdigest()
        assert _b1_spool_has_hash(enforcer.outbox_path, payload_hash), \
            "breach event must appear in the fsync'd spool"

        # 2. Wait for Rekor confirmation (async submission by the enforcer).
        assert _b1_rekor_has_hash(enforcer.rekor_url, payload_hash, deadline_s=30.0), \
            "breach event hash must appear in the Rekor transparency log"

        # 3. Run clearing: ingest → confirm → slash → withdrawal_guard + commit.
        service.run_once(
            db_conn,
            str(enforcer.socket_path),
            str(enforcer.outbox_path),
            enforcer.rekor_url,
        )

        # ── Assertions ────────────────────────────────────────────────────────
        with db_conn.cursor() as cur:
            # slash_event executed with Rekor UUID recorded.
            cur.execute(
                "SELECT status, breach_log_entry_id "
                "FROM slash_event WHERE session_id = %s AND status = 'executed' LIMIT 1",
                (_B1_SESSION,),
            )
            row = cur.fetchone()
            assert row is not None, "no executed slash_event found"
            assert row[1] is not None, "slash_event.breach_log_entry_id not set"

            # Agent reputation decremented (100 → 90 for one breach, lower for more).
            cur.execute(
                "SELECT reputation_score FROM agent_identity WHERE agent_id = %s",
                (_B1_AGENT,),
            )
            rep = cur.fetchone()[0]
            assert rep <= 90, f"reputation_score={rep}, expected ≤ 90 (one slash = -10)"

            # Bond decremented (1000.00 → 900.00 for one breach, lower for more).
            cur.execute(
                "SELECT amount_usd FROM operator_bond WHERE operator_id = %s",
                (_B1_OPERATOR,),
            )
            bond_amount = cur.fetchone()[0]
            assert bond_amount <= decimal.Decimal("900.00"), \
                f"bond={bond_amount}, expected ≤ 900.00"

            # Session terminated by the clearing service.
            cur.execute(
                "SELECT terminated_at FROM session WHERE session_id = %s",
                (_B1_SESSION,),
            )
            terminated_at = cur.fetchone()[0]
            assert terminated_at is not None, "session.terminated_at not set after clearing"

        # Enforcer returns 404 for the session (killed by clearing, not by cleanup).
        # GET /sessions/{id} has no route (405) — probe the events endpoint.
        status_check, _ = enforcer.client.get(f"/sessions/{_B1_SESSION}/events")
        assert status_check == 404, \
            f"expected 404 (session killed by clearing), got {status_check}"

        # ── Withdrawal guard: bond stays active while slash pending ───────────
        # Simulate a withdrawal request past the hold period, but block it with
        # a second pending slash_event.
        with db_conn.cursor() as cur:
            cur.execute(
                "UPDATE operator_bond "
                "SET withdrawal_requested_at = now() - INTERVAL '8 days' "
                "WHERE operator_id = %s",
                (_B1_OPERATOR,),
            )
            # ponytail: guard slash inserted directly — avoids a second enforcer trigger
            cur.execute(
                "INSERT INTO slash_event "
                "(session_id, breach_id, agent_id, attester_key_id, operator_id, "
                " amount_usd, reputation_penalty, status) "
                "VALUES ('b1-guard-sess', 'b1-guard-breach', %s, 'b1-gate-key-001', %s, "
                "        '100.00', 10, 'pending')",
                (_B1_AGENT, _B1_OPERATOR),
            )
        db_conn.commit()

        service.withdrawal_guard(db_conn)
        db_conn.commit()

        with db_conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM operator_bond WHERE operator_id = %s",
                (_B1_OPERATOR,),
            )
            bond_status = cur.fetchone()[0]
        assert bond_status == "active", \
            f"bond must stay 'active' while slash pending, got {bond_status!r}"

    finally:
        # Best-effort cleanup so re-runs don't hit unique-constraint errors.
        try:
            with db_conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM slash_event WHERE operator_id = %s",
                    (_B1_OPERATOR,),
                )
                cur.execute(
                    "DELETE FROM attestation_outbox "
                    "WHERE event_json->>'session_id' = %s",
                    (_B1_SESSION,),
                )
                cur.execute(
                    "DELETE FROM signing_key WHERE key_id = 'b1-gate-key-001'",
                )
                cur.execute(
                    "DELETE FROM session WHERE session_id = %s",
                    (_B1_SESSION,),
                )
                cur.execute(
                    "DELETE FROM agent_identity WHERE agent_id = %s",
                    (_B1_AGENT,),
                )
                cur.execute(
                    "DELETE FROM operator_bond WHERE operator_id = %s",
                    (_B1_OPERATOR,),
                )
            db_conn.commit()
        except Exception:
            pass
        finally:
            db_conn.close()
