"""Clearing service test fixtures and helpers."""

import base64
import hashlib
import http.client as _http_client
import http.server
import json
import os
import platform
import socket as _socket_mod
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

# Bootstrap: add repo root so `from clearing import service` works
sys.path.insert(0, str(Path(__file__).parents[2]))

from clearing import service  # noqa: E402 (after sys.path fix)


@pytest.fixture
def spool_entry(tmp_path):
    """Ephemeral Ed25519 key + fully-signed spool entry written to tmp_path/outbox.jsonl.

    Returns (entry_dict, outbox_path).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = Ed25519PrivateKey.generate()
    pub = private_key.public_key()
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    event = {
        "agent_id": "agent-test-001",
        "attester": "warden-enforcer",
        "attester_key_id": "key-test-001",
        "breach_id": "breach-test-001",
        "layer": "network",
        "session_id": "sess-test-001",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "token_claim": "targets",
        "violation": "test violation",
    }

    # First signature: Ed25519 over canonical(event minus signature)
    sig1 = private_key.sign(service._canonical_signable(event))
    event["signature"] = base64.urlsafe_b64encode(sig1).rstrip(b"=").decode()

    # Second signature: Ed25519 over canonical of the 8 reduced keys
    reduced = service._canonical_reduced(event)
    sig2 = private_key.sign(reduced)

    entry = {
        "event": event,
        "second_sig": base64.urlsafe_b64encode(sig2).rstrip(b"=").decode(),
        "public_key_pem": pem,
        "payload_sha256": hashlib.sha256(reduced).hexdigest(),
    }

    outbox = tmp_path / "outbox.jsonl"
    outbox.write_text(json.dumps(entry) + "\n")

    return entry, outbox


@pytest.fixture
def stub_rekor():
    """Minimal HTTP server that returns ["stub-rekor-uuid-001"] for any POST."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps(["stub-rekor-uuid-001"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass  # silence

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def insert_fk_chain():
    """Return a callable that inserts operator_bond → agent_identity → session."""

    def _insert(conn, agent_id: str, session_id: str, operator_id: str,
                 bond_amount: str = "1000.00") -> None:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO operator_bond (operator_id, amount_usd, status) "
                "VALUES (%s, %s, 'active')",
                (operator_id, bond_amount),
            )
            cur.execute(
                "INSERT INTO agent_identity "
                "(agent_id, did_web_url, public_key_jwk, operator_id) "
                "VALUES (%s, %s, '{\"kty\":\"OKP\"}'::jsonb, %s)",
                (agent_id, f"https://example.com/{agent_id}", operator_id),
            )
            cur.execute(
                "INSERT INTO session (session_id, agent_id, operator_id, expires_at) "
                "VALUES (%s, %s, %s, now() + INTERVAL '1 hour')",
                (session_id, agent_id, operator_id),
            )

    return _insert


# ── linux-only gate fixtures ──────────────────────────────────────────────────
# Duplicated from tests/phase1/conftest.py + tests/phase1/enforcer_client.py
# (duplication over cross-package import; keep it to what the one gate test needs).


class _EnforcerClient:
    """Minimal Unix-socket HTTP client (inlined from tests/phase1/enforcer_client.py)."""

    class _Conn(_http_client.HTTPConnection):
        def __init__(self, path, timeout=5.0):
            super().__init__("localhost", timeout=timeout)
            self._path = path

        def connect(self):
            s = _socket_mod.socket(_socket_mod.AF_UNIX, _socket_mod.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self._path)
            self.sock = s

    def __init__(self, socket_path):
        self._sock = socket_path

    def _req(self, method, path, body=None):
        conn = self._Conn(self._sock)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        finally:
            conn.close()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = None
        return status, parsed

    def post(self, path, body):
        return self._req("POST", path, body)

    def get(self, path):
        return self._req("GET", path)

    def delete(self, path):
        return self._req("DELETE", path)


def _is_linux():
    return platform.system() == "Linux"


def _has_root():
    return os.geteuid() == 0


def _gate_enforcer_binary():
    override = os.environ.get("ENFORCER_BIN")
    if override:
        return Path(override)
    candidate = Path(__file__).parents[2] / "enforcer" / "bin" / "warden-enforcer"
    return candidate if candidate.exists() else None


@pytest.fixture
def enforcer(tmp_path):
    """Launch the real enforcer binary — linux_only gate fixture.
    Duplicated (function-scoped) from tests/phase1/conftest.py.
    """
    if not _is_linux():
        pytest.skip("requires Linux kernel")
    if not _has_root():
        pytest.skip("requires root (nftables/namespace operations)")

    bin_path = _gate_enforcer_binary()
    if bin_path is None:
        pytest.fail(
            "enforcer binary not found at enforcer/bin/warden-enforcer — build it before the gate"
        )

    socket_path = tmp_path / "api.sock"
    outbox_path = tmp_path / "outbox.jsonl"

    env = dict(os.environ)
    env["ENFORCER_KEY_ID"] = "b1-gate-key-001"
    env["ENFORCER_SIGNING_KEY"] = (
        base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    )
    env["ENFORCER_SOCKET"] = str(socket_path)
    env["ENFORCER_OUTBOX"] = str(outbox_path)

    proc = subprocess.Popen(
        [str(bin_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if socket_path.exists():
            break
        if proc.poll() is not None:
            out, err = proc.communicate()
            pytest.fail(
                f"enforcer exited before binding its socket\n"
                f"stdout: {out.decode()}\nstderr: {err.decode()}"
            )
        time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("enforcer did not create its socket within 5s")

    yield SimpleNamespace(
        process=proc,
        socket_path=socket_path,
        outbox_path=outbox_path,
        rekor_url=os.environ.get("ENFORCER_REKOR_URL", ""),
        client=_EnforcerClient(str(socket_path)),
    )

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    # Sweep orphaned warden_* netns (mirrors phase1 conftest teardown).
    netns_out = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    for line in netns_out.splitlines():
        name = line.split()[0]
        if name.startswith("warden_"):
            subprocess.run(["ip", "netns", "del", name], capture_output=True)


@pytest.fixture
def transit_guest():
    """Attach a throwaway guest namespace — duplicated from tests/phase1/conftest.py."""
    guests = []

    def _attach(session_ns: str):
        guest_ns = session_ns + "_guest"
        subprocess.check_call(["ip", "netns", "add", guest_ns])
        guests.append(guest_ns)
        subprocess.check_call(
            ["ip", "link", "add", "gdown", "netns", session_ns,
             "type", "veth", "peer", "name", "geth", "netns", guest_ns]
        )
        for cmd in (
            ["ip", "-n", session_ns, "addr", "add", "192.168.250.1/30", "dev", "gdown"],
            ["ip", "-n", session_ns, "link", "set", "gdown", "up"],
            ["ip", "-n", guest_ns, "addr", "add", "192.168.250.2/30", "dev", "geth"],
            ["ip", "-n", guest_ns, "link", "set", "geth", "up"],
            ["ip", "-n", guest_ns, "route", "add", "default", "via", "192.168.250.1"],
        ):
            subprocess.check_call(cmd)

        def ping(ip: str) -> bool:
            return subprocess.run(
                ["ip", "netns", "exec", guest_ns, "ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
            ).returncode == 0

        return ping

    yield _attach

    for guest_ns in guests:
        subprocess.run(["ip", "netns", "del", guest_ns], capture_output=True)


@pytest.fixture
def dummy_targets():
    """Host-side dummy interface — duplicated from tests/phase1/conftest.py."""
    subprocess.check_call(["ip", "link", "add", "wdummy0", "type", "dummy"])
    for ip in ("10.99.77.1/32", "10.99.88.1/32", "169.254.169.254/32"):
        subprocess.check_call(["ip", "addr", "add", ip, "dev", "wdummy0"])
    subprocess.check_call(["ip", "link", "set", "wdummy0", "up"])

    yield SimpleNamespace(
        allowed="10.99.77.1", blocked="10.99.88.1", metadata="169.254.169.254"
    )

    subprocess.run(["ip", "link", "del", "wdummy0"], capture_output=True)
