"""Phase 5 clearing service — spool ingestion, Rekor confirmation, and slashing."""

import argparse
import base64
import decimal
import hashlib
import http.client
import json
import os
import socket
import sys
import time
from typing import Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives.serialization import load_pem_public_key

REPUTATION_PENALTY = 10
SLASH_AMOUNT = decimal.Decimal("100.00")

ENFORCER_SOCKET = os.getenv("ENFORCER_SOCKET", "/run/warden-enforcer/api.sock")
ENFORCER_OUTBOX = os.getenv("ENFORCER_OUTBOX", "/var/lib/warden-enforcer/outbox.jsonl")
ENFORCER_REKOR_URL = os.getenv("ENFORCER_REKOR_URL", "http://localhost:3000")


# ── Canonicalisation ──────────────────────────────────────────────────────────

def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _canonical_signable(event: dict) -> bytes:
    """Canonical bytes of event minus the 'signature' key (what first sig covers)."""
    return _canonical({k: v for k, v in event.items() if k != "signature"})


_REDUCED_KEYS = (
    "agent_id", "attester", "attester_key_id", "breach_id",
    "layer", "session_id", "signature", "timestamp",
)


def _canonical_reduced(event: dict) -> bytes:
    """Canonical bytes of the 8-key reduced payload (Rekor / second-sig coverage)."""
    return _canonical({k: event[k] for k in _REDUCED_KEYS})


# ── Crypto ────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify_entry(entry: dict) -> bool:
    """Verify both Ed25519 signatures in a spool entry. Any error → False."""
    try:
        event = entry["event"]
        pub = load_pem_public_key(entry["public_key_pem"].encode())
        pub.verify(_b64url_decode(event["signature"]), _canonical_signable(event))
        pub.verify(_b64url_decode(entry["second_sig"]), _canonical_reduced(event))
        return True
    except Exception:
        return False


def _pem_to_jwk(pem: str) -> dict:
    """PKIX PEM → {"kty":"OKP","crv":"Ed25519","x":"<base64url nopad>"}."""
    pub = load_pem_public_key(pem.encode())
    x = base64.urlsafe_b64encode(pub.public_bytes_raw()).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


# ── Enforcer API ──────────────────────────────────────────────────────────────

class _UnixHTTPConn(http.client.HTTPConnection):
    def __init__(self, socket_path: str):
        super().__init__("localhost", timeout=5)
        self._socket_path = socket_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._socket_path)
        self.sock = s


def enforcer_delete(socket_path: str, session_id: str) -> int:
    """DELETE /sessions/{id} over Unix socket. Returns HTTP status; 0 on connection error."""
    conn = None
    try:
        conn = _UnixHTTPConn(socket_path)
        conn.request("DELETE", f"/sessions/{session_id}")
        resp = conn.getresponse()
        resp.read()
        return resp.status
    except Exception as exc:
        print(f"enforcer_delete: {exc}", file=sys.stderr)
        return 0
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ── Rekor ─────────────────────────────────────────────────────────────────────

def _rekor_retrieve(rekor_url: str, sha256_hex: str) -> Optional[str]:
    """POST index/retrieve; return first UUID or None (failures are silenced)."""
    try:
        u = urlparse(rekor_url)
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=5)
        body = json.dumps({"hash": f"sha256:{sha256_hex}"}).encode()
        conn.request(
            "POST", "/api/v1/index/retrieve", body=body,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        if resp.status == 200:
            uuids = json.loads(raw)
            return uuids[0] if uuids else None
        return None
    except Exception:
        return None


# ── DB connection ─────────────────────────────────────────────────────────────

def _db_connect():
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5433")),
        dbname=os.getenv("POSTGRES_DB", "warden"),
        user=os.getenv("POSTGRES_USER", "postgres"),
        password=os.environ["POSTGRES_PASSWORD"],
    )


# ── Core service functions ────────────────────────────────────────────────────

def ingest_and_kill(conn, socket_path: str, outbox_path: str) -> int:
    """Read spool JSONL, verify, deduplicate, record, and kill breaching sessions.

    NO COMMIT — caller is responsible (run_once commits).
    Returns count of newly ingested entries.
    """
    from psycopg2.extras import Json

    try:
        with open(outbox_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return 0

    count = 0
    for raw_line in lines:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            print("ingest: invalid JSON in spool, skipping line", file=sys.stderr)
            continue

        if not _verify_entry(entry):
            print("ingest: signature verification failed, skipping entry", file=sys.stderr)
            continue

        event = entry["event"]
        key_id = event["attester_key_id"]
        attester = event["attester"]
        jwk = _pem_to_jwk(entry["public_key_pem"])

        with conn.cursor() as cur:
            # Upsert signing key; compare stored x to detect tampering
            cur.execute(
                "INSERT INTO signing_key (key_id, attester, public_key) "
                "VALUES (%s, %s, %s) ON CONFLICT (key_id) DO NOTHING",
                (key_id, attester, Json(jwk)),
            )
            cur.execute(
                "SELECT public_key FROM signing_key WHERE key_id = %s", (key_id,)
            )
            stored = cur.fetchone()[0]
            if isinstance(stored, str):
                stored = json.loads(stored)
            if stored.get("x") != jwk.get("x"):
                print(
                    f"ingest: signing key mismatch for {key_id} — possible tampering",
                    file=sys.stderr,
                )
                continue

            # Deduplicate via breach_id unique index
            cur.execute(
                "INSERT INTO attestation_outbox (event_json, attester) "
                "VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING id",
                (Json(event), attester),
            )
            row = cur.fetchone()
            if row is None:
                continue  # duplicate breach_id, already processed

            # Resolve operator from session (may not exist)
            cur.execute(
                "SELECT operator_id FROM session WHERE session_id = %s",
                (event["session_id"],),
            )
            sess = cur.fetchone()
            operator_id = sess[0] if sess else None

            cur.execute(
                "INSERT INTO slash_event "
                "(session_id, breach_id, agent_id, attester_key_id, operator_id, "
                " amount_usd, reputation_penalty, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending')",
                (
                    event["session_id"], event["breach_id"], event["agent_id"],
                    key_id, operator_id, SLASH_AMOUNT, REPUTATION_PENALTY,
                ),
            )

            cur.execute(
                "UPDATE session SET terminated_at = now() "
                "WHERE session_id = %s AND terminated_at IS NULL",
                (event["session_id"],),
            )

        enforcer_delete(socket_path, event["session_id"])
        count += 1

    return count


def confirm(conn, rekor_url: str) -> int:
    """Check unsubmitted outbox entries against Rekor; record UUIDs on hit.

    NO COMMIT — caller is responsible.
    Returns count of newly confirmed entries.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, event_json FROM attestation_outbox WHERE submitted_at IS NULL"
        )
        rows = cur.fetchall()

    count = 0
    for outbox_id, event_json in rows:
        if isinstance(event_json, str):
            event_json = json.loads(event_json)

        sha256_hex = hashlib.sha256(_canonical_reduced(event_json)).hexdigest()
        uuid = _rekor_retrieve(rekor_url, sha256_hex)
        if uuid is None:
            continue

        breach_id = event_json.get("breach_id")
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE attestation_outbox "
                "SET submitted_at = now(), rekor_entry_id = %s "
                "WHERE id = %s",
                (uuid, outbox_id),
            )
            if breach_id:
                cur.execute(
                    "UPDATE slash_event SET breach_log_entry_id = %s "
                    "WHERE breach_id = %s AND breach_log_entry_id IS NULL",
                    (uuid, breach_id),
                )
        count += 1

    return count


def slash(conn) -> int:
    """Execute confirmed pending slashes: decrement reputation + bond bookkeeping.

    NO COMMIT — caller is responsible.
    Returns count of executed slash_events.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, agent_id, operator_id, amount_usd, reputation_penalty "
            "FROM slash_event "
            "WHERE status = 'pending' AND breach_log_entry_id IS NOT NULL"
        )
        rows = cur.fetchall()

    count = 0
    for slash_id, agent_id, operator_id, slash_amount, rep_penalty in rows:
        with conn.cursor() as cur:
            # Primary: decrement agent reputation, floored at 0
            cur.execute(
                "UPDATE agent_identity "
                "SET reputation_score = GREATEST(reputation_score - %s, 0) "
                "WHERE agent_id = %s",
                (rep_penalty, agent_id),
            )
            if cur.rowcount == 0:
                print(
                    f"slash: no agent_identity row for agent_id={agent_id!r}",
                    file=sys.stderr,
                )

            # Bookkeeping: decrement operator bond if present
            if operator_id is not None:
                cur.execute(
                    "SELECT amount_usd FROM operator_bond "
                    "WHERE operator_id = %s FOR UPDATE",
                    (operator_id,),
                )
                bond = cur.fetchone()
                if bond is not None:
                    new_balance = bond[0] - slash_amount
                    # Preserve current status unless depleting — a late slash
                    # must not resurrect a withdrawn bond to 'active'.
                    cur.execute(
                        "UPDATE operator_bond SET amount_usd = %s, "
                        "status = CASE WHEN %s <= 0 THEN 'depleted' ELSE status END "
                        "WHERE operator_id = %s",
                        (new_balance, new_balance, operator_id),
                    )

            cur.execute(
                "UPDATE slash_event SET status = 'executed' WHERE id = %s",
                (slash_id,),
            )
        count += 1

    return count


def withdrawal_guard(conn) -> int:
    """Release operator bonds whose hold period has expired and have no open liabilities.

    Blocks on: pending slashes, disputed slashes, unconfirmed outbox for operator sessions.
    NO COMMIT — caller is responsible.
    Returns count of bonds released.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT operator_id FROM operator_bond "
            "WHERE status = 'active' "
            "  AND withdrawal_requested_at IS NOT NULL "
            "  AND withdrawal_requested_at + withdrawal_hold_days * INTERVAL '1 day' <= now()"
        )
        candidates = [r[0] for r in cur.fetchall()]

    count = 0
    for operator_id in candidates:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM slash_event "
                "WHERE operator_id = %s AND status = 'pending' LIMIT 1",
                (operator_id,),
            )
            if cur.fetchone():
                continue

            cur.execute(
                "SELECT 1 FROM slash_event "
                "WHERE operator_id = %s AND status = 'disputed' LIMIT 1",
                (operator_id,),
            )
            if cur.fetchone():
                continue

            cur.execute(
                "SELECT 1 FROM attestation_outbox "
                "WHERE submitted_at IS NULL "
                "  AND event_json->>'session_id' IN ("
                "      SELECT session_id FROM session WHERE operator_id = %s"
                "  ) LIMIT 1",
                (operator_id,),
            )
            if cur.fetchone():
                continue

            cur.execute(
                "UPDATE operator_bond SET status = 'withdrawn' WHERE operator_id = %s",
                (operator_id,),
            )
            count += 1

    return count


# ── Orchestration ─────────────────────────────────────────────────────────────

def run_once(conn, socket_path: str, outbox_path: str, rekor_url: str) -> None:
    ingest_and_kill(conn, socket_path, outbox_path)
    confirm(conn, rekor_url)
    slash(conn)
    withdrawal_guard(conn)
    conn.commit()


def run_daemon(interval_s: float, socket_path: str, outbox_path: str, rekor_url: str) -> None:
    # ponytail: 2s poll; switch to inotify when sub-second latency matters
    conn = _db_connect()
    while True:
        try:
            run_once(conn, socket_path, outbox_path, rekor_url)
        except Exception as exc:
            print(f"run_daemon error: {exc}", file=sys.stderr)
            try:
                conn.rollback()
            except Exception:
                conn = _db_connect()
        time.sleep(interval_s)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Warden Phase 5 clearing service")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--interval", type=float, default=2.0, help="daemon poll interval (s)")
    args = parser.parse_args()

    if args.once:
        c = _db_connect()
        run_once(c, ENFORCER_SOCKET, ENFORCER_OUTBOX, ENFORCER_REKOR_URL)
    else:
        run_daemon(args.interval, ENFORCER_SOCKET, ENFORCER_OUTBOX, ENFORCER_REKOR_URL)
