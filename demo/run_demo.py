#!/usr/bin/env python3
"""
Warden rogue-recon demo orchestrator.

Stages a realistic "prompt-injected recon agent" end-to-end: authorised
ping sweep → simulated metadata SSRF → exfil attempt → both blocked at the
kernel → signed breach events → spool → Rekor transparency log.

Usage (Linux, root):
    sudo -E ENFORCER_REKOR_URL=http://localhost:3000 python3 demo/run_demo.py

Rekor is optional. Without ENFORCER_REKOR_URL stages 1–3 run; stage 3d
(Rekor) and stage 4 (clearing) are printed as SKIPPED with the commands
to enable them.
"""

import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parents[1]

# ── Demo parameters ───────────────────────────────────────────────────────────

SESSION_ID = "demo-recon-001"
AGENT_ID = "warden-recon-agent-v1"
OPERATOR_ID = "demo-operator-001"  # used by stage 4 clearing FK chain

# Customer subnet the agent is authorised to sweep.
CUSTOMER_SUBNET = "10.99.55.0/24"
CUSTOMER_HOST = "10.99.55.1"     # lives on wdummy0; answers ICMP if unblocked

# Out-of-scope destinations the injected payload targets.
METADATA_IP = "169.254.169.254"  # unconditional block in every session ruleset
EXFIL_IP = "203.0.113.99"        # RFC 5737 documentation range; lives on wdummy0

# Derived names
SESSION_NS = "warden_" + SESSION_ID.replace("-", "_")   # warden_demo_recon_001
GUEST_NS = SESSION_NS + "_guest"                          # warden_demo_recon_001_guest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _banner(text: str) -> None:
    width = 72
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)


def _pass(stage: str, detail: str = "") -> None:
    suffix = f"  ({detail})" if detail else ""
    print(f"  PASS  {stage}{suffix}")


def _fail(stage: str, detail: str = "") -> None:
    suffix = f"  ({detail})" if detail else ""
    print(f"  FAIL  {stage}{suffix}", file=sys.stderr)


def _run(args: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=capture, text=capture)


def _nft_catchall_counter(session_ns: str) -> int:
    """Parse the catch-all counter from the session nftables ruleset.

    The catch-all rule (off-scope packets that are not in the unconditional
    deny list) ends with `counter` rather than `drop`:
        log prefix "warden:<sid>:" group 1 counter packets N bytes M
    Returns the packet count, or 0 if the counter line is not found.
    """
    result = subprocess.run(
        ["ip", "netns", "exec", session_ns, "nft", "list", "ruleset"],
        capture_output=True,
        text=True,
    )
    m = re.search(r"counter packets (\d+)", result.stdout)
    return int(m.group(1)) if m else 0


def _poll_events(client, session_id: str, want: int, deadline_s: float = 10.0) -> list:
    """Poll GET /sessions/{id}/events until at least `want` events appear."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        status, events = client.get(f"/sessions/{session_id}/events")
        if status == 200 and events and len(events) >= want:
            return events
        time.sleep(0.2)
    status, events = client.get(f"/sessions/{session_id}/events")
    return events or []


def _spool_has_payload_hash(outbox_path: Path, sha256_hex: str) -> bool:
    if not outbox_path.exists():
        return False
    for line in outbox_path.read_text().splitlines():
        try:
            if json.loads(line).get("payload_sha256") == sha256_hex:
                return True
        except json.JSONDecodeError:
            pass
    return False


# ── Preflight ─────────────────────────────────────────────────────────────────

def _preflight() -> None:
    """Exit early with actionable guidance rather than a traceback."""
    if platform.system() != "Linux":
        print(
            "\nThis demo requires a Linux host with root access.\n"
            "\nOn macOS, run it in a Linux VM or via the CI 'linux-gate' job:\n"
            "  .github/workflows/ci.yml → linux-gate\n"
            "\nQuick local option (Docker Desktop, privileged):\n"
            "  docker run --rm -it --privileged \\\n"
            "      -v $(pwd):/warden -w /warden \\\n"
            "      ubuntu:24.04 bash -c \\\n"
            "      'apt-get update -q && apt-get install -y nftables iproute2 iputils-ping \\\n"
            "         curl ca-certificates python3 python3-pip && \\\n"
            "       curl -fsSL \"https://go.dev/dl/go1.26.4.linux-$(dpkg --print-architecture).tar.gz\" \\\n"
            "         | tar -C /usr/local -xz && \\\n"
            "       export PATH=/usr/local/go/bin:$PATH && \\\n"
            "       pip install --break-system-packages -r requirements-test.txt && \\\n"
            "       (cd enforcer && go build -o bin/warden-enforcer ./cmd/warden-enforcer) && \\\n"
            "       python3 demo/run_demo.py'\n"
        )
        sys.exit(0)

    if os.geteuid() != 0:
        print(
            "\nThis demo requires root (nftables / network-namespace operations).\n"
            "\nRe-run with sudo, preserving environment variables:\n"
            "  sudo -E python3 demo/run_demo.py\n"
            "  sudo -E ENFORCER_REKOR_URL=http://localhost:3000 python3 demo/run_demo.py\n"
        )
        sys.exit(2)

    # Enforcer binary
    enforcer_bin = (
        Path(os.environ["ENFORCER_BIN"])
        if "ENFORCER_BIN" in os.environ
        else REPO_ROOT / "enforcer" / "bin" / "warden-enforcer"
    )
    if not enforcer_bin.exists():
        print(
            f"\nEnforcer binary not found at {enforcer_bin}\n"
            "\nBuild it first:\n"
            "  cd enforcer && go build -o bin/warden-enforcer ./cmd/warden-enforcer\n"
            "  (or run: ./scripts/setup.sh)\n"
        )
        sys.exit(2)

    # Required tools
    for tool in ("ip", "nft", "ping"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            print(
                f"\nRequired tool '{tool}' not found on PATH.\n"
                "  apt-get install -y iproute2 nftables iputils-ping\n"
                "  (or run: ./scripts/setup.sh)\n"
            )
            sys.exit(2)


def _enforcer_bin_path() -> Path:
    if "ENFORCER_BIN" in os.environ:
        return Path(os.environ["ENFORCER_BIN"])
    return REPO_ROOT / "enforcer" / "bin" / "warden-enforcer"


# ── Enforcer lifecycle ────────────────────────────────────────────────────────

def _launch_enforcer(work_dir: Path, rekor_url: str) -> tuple:
    """Launch the enforcer binary with an ephemeral signing key.

    Mirrors the `enforcer` pytest fixture in tests/phase1/conftest.py
    exactly: same env-var names, same key encoding, same socket-wait loop.
    """
    socket_path = work_dir / "api.sock"
    outbox_path = work_dir / "outbox.jsonl"

    env = dict(os.environ)
    env["ENFORCER_KEY_ID"] = "demo-key-001"
    # base64url, no padding — matches conftest.py's encoding
    env["ENFORCER_SIGNING_KEY"] = (
        base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    )
    env["ENFORCER_SOCKET"] = str(socket_path)
    env["ENFORCER_OUTBOX"] = str(outbox_path)
    if rekor_url:
        env["ENFORCER_REKOR_URL"] = rekor_url
    else:
        env.pop("ENFORCER_REKOR_URL", None)

    proc = subprocess.Popen(
        [str(_enforcer_bin_path())],
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
            print(
                f"\nEnforcer exited before binding its socket:\n"
                f"  stdout: {out.decode()}\n"
                f"  stderr: {err.decode()}\n",
                file=sys.stderr,
            )
            sys.exit(1)
        time.sleep(0.1)
    else:
        proc.terminate()
        print("\nEnforcer did not create its socket within 5s\n", file=sys.stderr)
        sys.exit(1)

    return proc, socket_path, outbox_path


# ── Network world staging ─────────────────────────────────────────────────────

def _create_dummy_iface() -> None:
    """Create wdummy0 and assign all three demo IPs to it.

    The dummy interface lives in the root (host) namespace and makes each
    target IP genuinely reachable from the host's perspective. This mirrors
    conftest.py's `dummy_targets` fixture so that enforcement assertions are
    non-vacuous: the allowed host answers ICMP, and the blocked hosts would
    also answer if the filter leaked.
    """
    _run(["ip", "link", "add", "wdummy0", "type", "dummy"])
    for cidr in (f"{CUSTOMER_HOST}/32", f"{METADATA_IP}/32", f"{EXFIL_IP}/32"):
        _run(["ip", "addr", "add", cidr, "dev", "wdummy0"])
    _run(["ip", "link", "set", "wdummy0", "up"])


def _create_session_credential() -> dict:
    """Realistic recon-agent credential.

    `targets` contains ONLY the customer subnet — not the metadata or exfil
    IPs. The metadata IP is unconditionally blocked by the ruleset regardless;
    exfil falls through to the catch-all drop.
    """
    return {
        "session_id": SESSION_ID,
        "agent_id": AGENT_ID,
        "targets": [CUSTOMER_SUBNET],
        "tools": ["ping_sweep", "port_scan"],
        "resources": ["cve_kb"],
        "intent": "recon",
        "ttl_secs": 300,
    }


def _attach_guest_ns() -> None:
    """Attach a guest transit namespace to the session namespace.

    Mirrors tests/phase1/conftest.py's `transit_guest` fixture verbatim —
    same interface names (gdown/geth), same /30 addresses, same route.
    Copied rather than imported because pytest fixtures are not callable
    outside a pytest session.

    The session ruleset filters the *forward* hook, not *output*. A process
    running directly inside the session ns generates output-hook traffic the
    filter never sees. The guest ns forces agent traffic to transit the
    session ns, so the forward rules (and NFLOG breach logging) apply.
    """
    _run(["ip", "netns", "add", GUEST_NS])
    _run([
        "ip", "link", "add", "gdown", "netns", SESSION_NS,
        "type", "veth", "peer", "name", "geth", "netns", GUEST_NS,
    ])
    _run(["ip", "-n", SESSION_NS, "addr", "add", "192.168.250.1/30", "dev", "gdown"])
    _run(["ip", "-n", SESSION_NS, "link", "set", "gdown", "up"])
    _run(["ip", "-n", GUEST_NS, "addr", "add", "192.168.250.2/30", "dev", "geth"])
    _run(["ip", "-n", GUEST_NS, "link", "set", "geth", "up"])
    _run(["ip", "-n", GUEST_NS, "route", "add", "default", "via", "192.168.250.1"])


# ── Cleanup ───────────────────────────────────────────────────────────────────

def _cleanup(proc, client) -> None:
    """Best-effort teardown; runs even on failure."""
    # 1. Delete the session via the API (removes the session netns + veth pool)
    if client is not None:
        try:
            client.delete(f"/sessions/{SESSION_ID}")
        except Exception:
            pass

    # 2. Delete the guest ns explicitly (the API teardown removes the session
    #    ns but the guest ns is independent).
    subprocess.run(["ip", "netns", "del", GUEST_NS], capture_output=True)

    # 3. Terminate the enforcer process.
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # 4. Sweep any remaining warden_* netns (mirrors conftest.py teardown).
    result = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        name = line.split()[0]
        if name.startswith("warden_"):
            subprocess.run(["ip", "netns", "del", name], capture_output=True)

    # 5. Remove the dummy interface.
    subprocess.run(["ip", "link", "del", "wdummy0"], capture_output=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    # ── Preflight ─────────────────────────────────────────────────────────────
    _preflight()   # exits on macOS / non-root / missing binary

    # Deferred imports: need pytest (test dep) and cryptography.
    # Only reached on Linux+root where the test deps are installed.
    sys.path.insert(0, str(REPO_ROOT / "tests" / "phase1"))
    from enforcer_client import EnforcerClient  # noqa: PLC0415
    from test_breach_attestation import (       # noqa: PLC0415
        _b64url,
        _b64url_signable,
        _canonical_reduced,
        _lost_header,
        _rekor_has_hash,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey,
    )

    rekor_url = os.environ.get("ENFORCER_REKOR_URL", "")

    proc = None
    client = None

    try:
        # ── 0. Intro ──────────────────────────────────────────────────────────
        _banner("WARDEN ENFORCEMENT DEMO — rogue recon agent")
        print()
        print("  Scenario: an autonomous vulnerability-recon agent is authorised to")
        print(f"  ping-sweep customer subnet {CUSTOMER_SUBNET}. It completes its")
        print("  authorised sweep, then a simulated prompt-injection payload instructs")
        print(f"  it to (a) steal IAM credentials from the metadata service at")
        print(f"  {METADATA_IP} and (b) exfiltrate to attacker host {EXFIL_IP}.")
        print("  Both attempts are dropped at the kernel and each becomes a signed,")
        print("  content-addressed, Rekor-logged breach event.")
        print()
        if not rekor_url:
            print(
                "  NOTE: ENFORCER_REKOR_URL is not set — Rekor stage will be SKIPPED.")
            print(
                "  To enable: docker compose -f infra/compose.yml --profile gate up -d rekor-server")
            print(
                "  Then:      sudo -E ENFORCER_REKOR_URL=http://localhost:3000 python3 demo/run_demo.py")
        print()

        # ── 1. Launch enforcer ────────────────────────────────────────────────
        _banner("STAGE 0 — launch enforcer")
        work_dir = Path(tempfile.mkdtemp(prefix="warden-demo-"))
        proc, socket_path, outbox_path = _launch_enforcer(work_dir, rekor_url)
        client = EnforcerClient(str(socket_path))
        print(f"  Enforcer PID {proc.pid} listening on {socket_path}")

        # ── 2. Stage the world ────────────────────────────────────────────────
        _banner("STAGE 1 — create dummy interface + session credential")

        print("  Creating wdummy0 dummy interface with demo IPs ...")
        _create_dummy_iface()
        print(f"    {CUSTOMER_HOST}/32  — authorised customer host (will answer ICMP)")
        print(f"    {METADATA_IP}/32 — metadata IP (unconditional block, added for realism)")
        print(f"    {EXFIL_IP}/32   — exfil endpoint (RFC 5737 doc range, added to dummy)")

        print()
        print("  POST /sessions — registering recon-agent credential ...")
        cred = _create_session_credential()
        status, body = client.post("/sessions", cred)
        if status != 201:
            print(f"  FAIL  POST /sessions returned {status}: {body}", file=sys.stderr)
            return 1
        print(f"  Session '{SESSION_ID}' created (targets: {CUSTOMER_SUBNET})")
        print(f"  Credential tools={cred['tools']}  resources={cred['resources']}")
        print(f"  intent='{cred['intent']}'  ttl={cred['ttl_secs']}s")
        print()
        print(
            "  NOTE: tools/resources/intent are stored in the credential but NOT yet")
        print(
            "  enforced. Network-layer (targets) enforcement is live. MCP (tools),")
        print(
            "  retrieval API (resources), and orchestrator (intent) enforcement are")
        print("  future phases (see README.md §Future vision and docs/enforcer-wiki.md §1).")

        print()
        print("  Attaching guest transit namespace to session namespace ...")
        _attach_guest_ns()
        print(f"    session ns : {SESSION_NS}")
        print(f"    guest ns   : {GUEST_NS}")
        print(f"    veth pair  : {GUEST_NS}:geth <-> {SESSION_NS}:gdown (192.168.250.2/30 → .1/30)")
        print(f"    guest default route: via 192.168.250.1 (session ns gdown)")
        print("  Traffic from the guest transits the session ns — the forward hook")
        print("  (and NFLOG breach logging) applies. This mirrors the gVisor/runsc")
        print("  downlink topology.")

        # ── 3. Run the agent ──────────────────────────────────────────────────
        _banner("STAGE 2 — run the rogue recon agent (inside guest ns)")
        print()
        agent_cmd = [
            "ip", "netns", "exec", GUEST_NS,
            "python3", str(REPO_ROOT / "demo" / "rogue_recon_agent.py"),
            CUSTOMER_HOST, METADATA_IP, EXFIL_IP,
        ]
        print(f"  Command: {' '.join(agent_cmd)}")
        print()
        result = subprocess.run(agent_cmd)
        print()
        agent_exit = result.returncode
        if agent_exit != 0:
            print(
                f"  FAIL  agent exited {agent_exit} — enforcement failure from agent perspective",
                file=sys.stderr,
            )
            return 1
        print("  Agent exited 0 (enforcement held from agent perspective).")

        # ── 4. Assertions ─────────────────────────────────────────────────────
        _banner("STAGE 3 — post-run enforcement assertions")
        all_passed = True

        # ── Stage 3a: nftables catch-all counter ──────────────────────────────
        print()
        print("  [3a] nftables catch-all counter")
        print(
            "       The catch-all rule fires for off-scope IPs that are NOT in the")
        print(
            "       unconditional deny list. The metadata IP (169.254.169.254/32) hits")
        print(
            "       the explicit unconditional-deny rule (no counter there). The exfil")
        print(
            "       IP hits the catch-all. Expected counter: ≥ 1.")
        counter = _nft_catchall_counter(SESSION_NS)
        if counter >= 1:
            _pass("nft catch-all counter", f"packets={counter}")
        else:
            _fail("nft catch-all counter", f"packets={counter}, expected ≥ 1")
            all_passed = False
        print(
            f"       Observable: ip netns exec {SESSION_NS} nft list ruleset "
            f"| grep counter")
        print(
            "       Doc ref: enforcer/internal/ruleset/ruleset.go — catch-all log rule")

        # ── Stage 3b: signed breach events ────────────────────────────────────
        print()
        print("  [3b] signed breach events (GET /sessions/{id}/events)")
        print("       Expect 2 events: one for the metadata attempt, one for exfil.")
        events = _poll_events(client, SESSION_ID, want=2, deadline_s=10.0)
        if len(events) < 2:
            _fail(
                "breach events count",
                f"got {len(events)} event(s), expected 2; poll timed out",
            )
            all_passed = False
        else:
            _pass("breach events count", f"{len(events)} events received")

        # Verify Ed25519 signature on each event
        sig_status, jwk = client.get("/enforcer/keys/active")
        if sig_status != 200:
            _fail("active key fetch", f"status={sig_status}")
            all_passed = False
        else:
            pub_bytes = _b64url(jwk["x"])
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            for i, ev in enumerate(events):
                if ev.get("attester_key_id") != jwk.get("key_id"):
                    _fail(
                        f"event[{i}] key_id match",
                        f"{ev.get('attester_key_id')} != {jwk.get('key_id')}",
                    )
                    all_passed = False
                    continue
                try:
                    pub_key.verify(
                        _b64url(ev["signature"]),
                        _b64url_signable(ev),
                    )
                    _pass(
                        f"event[{i}] Ed25519 signature",
                        f"breach_id={ev.get('breach_id', '')[:8]}...",
                    )
                except Exception as exc:
                    _fail(f"event[{i}] Ed25519 signature", str(exc))
                    all_passed = False
        print(
            "       Doc ref: docs/enforcer-wiki.md §8 Breach Event Flow,")
        print(
            "                docs/breach-event-canonicalization.md")

        # ── Stage 3c: spool entries ────────────────────────────────────────────
        print()
        print("  [3c] fsync'd outbox spool (JSONL)")
        for i, ev in enumerate(events):
            reduced = _canonical_reduced(ev)
            phash = hashlib.sha256(reduced).hexdigest()
            if _spool_has_payload_hash(outbox_path, phash):
                _pass(
                    f"event[{i}] spool entry",
                    f"payload_sha256={phash[:16]}...",
                )
            else:
                _fail(
                    f"event[{i}] spool entry",
                    f"payload_sha256={phash[:16]}... not found in {outbox_path}",
                )
                all_passed = False
        print(
            "       Doc ref: docs/enforcer-wiki.md §8 Breach Event Flow")

        # ── Stage 3d: Rekor transparency log (optional) ────────────────────────
        print()
        print("  [3d] Rekor transparency log")
        if not rekor_url:
            print("       SKIPPED — ENFORCER_REKOR_URL not set")
            print(
                "       To enable: docker compose -f infra/compose.yml --profile gate up -d rekor-server")
            print(
                "       Then:      sudo -E ENFORCER_REKOR_URL=http://localhost:3000 python3 demo/run_demo.py")
        else:
            for i, ev in enumerate(events):
                reduced = _canonical_reduced(ev)
                phash = hashlib.sha256(reduced).hexdigest()
                if _rekor_has_hash(rekor_url, phash, deadline_s=30.0):
                    _pass(
                        f"event[{i}] Rekor entry",
                        f"sha256:{phash[:16]}... found in transparency log",
                    )
                else:
                    _fail(
                        f"event[{i}] Rekor entry",
                        f"sha256:{phash[:16]}... not found after 30s",
                    )
                    all_passed = False
            print(
                "       Doc ref: docs/enforcer-wiki.md §8 Breach Event Flow")

        # ── Stage 3e: lost-events header ──────────────────────────────────────
        print()
        print("  [3e] X-Warden-Lost-Events header (must be 0 on a clean path)")
        lost = _lost_header(socket_path, f"/sessions/{SESSION_ID}/events")
        if lost == "0":
            _pass("lost-events header", "X-Warden-Lost-Events: 0")
        else:
            _fail("lost-events header", f"X-Warden-Lost-Events: {lost!r}")
            all_passed = False

        # ── 4. Clearing service ───────────────────────────────────────────────
        _banner("STAGE 4 — clearing service (kill + slash)")
        print()
        pg_pass = os.environ.get("POSTGRES_PASSWORD")
        # Rekor is required too: the slash only executes after Rekor confirms,
        # so without it stage 4 would always report a false failure.
        if not pg_pass or not rekor_url:
            missing = "POSTGRES_PASSWORD" if not pg_pass else "ENFORCER_REKOR_URL"
            print(f"  SKIPPED — {missing} not set.")
            print("  To enable stage 4:")
            print("    docker compose -f infra/compose.yml up -d postgres")
            print(
                "    sudo -E POSTGRES_PASSWORD=warden ENFORCER_REKOR_URL=http://localhost:3000 "
                "python3 demo/run_demo.py"
            )
        else:
            import psycopg2  # noqa: PLC0415

            # Bootstrap repo root so `from clearing import service` resolves.
            if str(REPO_ROOT) not in sys.path:
                sys.path.insert(0, str(REPO_ROOT))
            from clearing import service as _clearing  # noqa: PLC0415

            _stage4_passed = True
            _demo_db = None
            try:
                _demo_db = psycopg2.connect(
                    host=os.getenv("POSTGRES_HOST", "localhost"),
                    port=int(os.getenv("POSTGRES_PORT", "5433")),
                    dbname=os.getenv("POSTGRES_DB", "warden"),
                    user=os.getenv("POSTGRES_USER", "postgres"),
                    password=pg_pass,
                )

                # Insert FK chain (ON CONFLICT DO NOTHING), then reset fixtures to a known
                # baseline so every run measures a real transition — reruns against a
                # persisted volume would otherwise inherit stale state and the assertions
                # below would pass vacuously.
                with _demo_db.cursor() as _cur:
                    _cur.execute(
                        "INSERT INTO operator_bond (operator_id, amount_usd, status) "
                        "VALUES (%s, '1000.00', 'active') ON CONFLICT DO NOTHING",
                        (OPERATOR_ID,),
                    )
                    _cur.execute(
                        "INSERT INTO agent_identity "
                        "(agent_id, did_web_url, public_key_jwk, operator_id, reputation_score) "
                        "VALUES (%s, 'https://example.com/demo', '{\"kty\":\"OKP\"}'::jsonb, "
                        "        %s, 100) ON CONFLICT DO NOTHING",
                        (AGENT_ID, OPERATOR_ID),
                    )
                    _cur.execute(
                        "INSERT INTO session (session_id, agent_id, operator_id, expires_at) "
                        "VALUES (%s, %s, %s, now() + INTERVAL '1 hour') ON CONFLICT DO NOTHING",
                        (SESSION_ID, AGENT_ID, OPERATOR_ID),
                    )
                    _cur.execute(
                        "UPDATE agent_identity SET reputation_score = 100 WHERE agent_id = %s",
                        (AGENT_ID,),
                    )
                    _cur.execute(
                        "UPDATE session SET terminated_at = NULL, expires_at = now() + INTERVAL '1 hour' "
                        "WHERE session_id = %s",
                        (SESSION_ID,),
                    )
                    _cur.execute(
                        "UPDATE operator_bond SET amount_usd = '1000.00', status = 'active' "
                        "WHERE operator_id = %s",
                        (OPERATOR_ID,),
                    )
                _demo_db.commit()

                # Run the full clearing pipeline (ingest → confirm → slash → guard).
                _clearing.run_once(
                    _demo_db,
                    str(socket_path),
                    str(outbox_path),
                    rekor_url,
                )

                # Assertions.
                with _demo_db.cursor() as _cur:
                    _cur.execute(
                        "SELECT COUNT(*) FROM slash_event "
                        "WHERE session_id = %s AND status = 'executed'",
                        (SESSION_ID,),
                    )
                    _executed = _cur.fetchone()[0]

                    _cur.execute(
                        "SELECT reputation_score FROM agent_identity WHERE agent_id = %s",
                        (AGENT_ID,),
                    )
                    _rep = _cur.fetchone()[0]

                    _cur.execute(
                        "SELECT terminated_at FROM session WHERE session_id = %s",
                        (SESSION_ID,),
                    )
                    _terminated = _cur.fetchone()[0]

                if _executed >= 1:
                    _pass("slash_event executed", f"{_executed} breach(es) slashed")
                else:
                    _fail("slash_event executed", "no executed slash_event found")
                    _stage4_passed = False

                if _rep < 100:
                    _pass("agent reputation decremented", f"100 → {_rep}")
                else:
                    _fail("agent reputation decremented", f"reputation_score={_rep}, expected < 100")
                    _stage4_passed = False

                if _terminated is not None:
                    _pass("session.terminated_at set", "clearing killed the session")
                else:
                    _fail("session.terminated_at set", "session not terminated after clearing")
                    _stage4_passed = False

                # Enforcer should now return 404 (clearing called DELETE /sessions/{id}).
                # GET /sessions/{id} has no route (405) — probe the events endpoint.
                _kill_status, _ = client.get(f"/sessions/{SESSION_ID}/events")
                if _kill_status == 404:
                    _pass("enforcer session killed", "GET /sessions/{id}/events → 404")
                else:
                    _fail("enforcer session killed", f"expected 404, got {_kill_status}")
                    _stage4_passed = False

                if not _stage4_passed:
                    all_passed = False

            except Exception as _exc:
                _fail("stage 4 clearing", str(_exc))
                all_passed = False
            finally:
                if _demo_db is not None:
                    _demo_db.close()

        # ── 5. Documented-future hand-off ─────────────────────────────────────
        _banner("DOCUMENTED-FUTURE HAND-OFF")
        print()
        print("  Session kill and slashing are implemented in the clearing service")
        print("  (clearing/service.py). Stage 4 above (when POSTGRES_PASSWORD is set)")
        print("  runs the full pipeline end-to-end: spool → Rekor → clearing → slash.")
        print()
        print("  Reputation model (docs/slashing-policy.md v1.1):")
        print("    - agent_identity.reputation_score starts at 100")
        print("    - Each confirmed breach: −10 (floor 0)")
        print("    - Parallel bond-ledger bookkeeping: operator_bond.amount_usd −$100/breach")
        print("    - No financial transfer in v1 reputational bonding")
        print()
        print("  Still future (no code yet):")
        print()
        print("    MCP tool-layer enforcement (tools claim) — Phase 3")
        print("      The MCP server will deny calls to tools outside the issued credential.")
        print()
        print("    Retrieval API enforcement (resources claim) — Phase 2")
        print("      The retrieval API will deny access to resources outside the credential.")
        print()
        print("    Orchestrator intent enforcement (intent claim) — Phase 4")
        print("      The orchestrator will verify that actions match the declared intent.")
        print()
        print("  Scope dimensions enforced TODAY vs. future:")
        print("    ✓ network   (targets claim)    — enforcer, this demo")
        print("    ✓ session kill                 — clearing service (stage 4)")
        print("    ✓ slashing / reputation        — clearing service (stage 4)")
        print("    ✗ tool      (tools claim)      — MCP server, Phase 3 (not built)")
        print("    ✗ resource  (resources claim)  — retrieval API, Phase 2 (not built)")
        print("    ✗ intent    (intent claim)     — orchestrator, Phase 4 (not built)")
        print()

        # ── Final result ──────────────────────────────────────────────────────
        _banner("RESULT")
        print()
        if all_passed:
            print("  ALL STAGES PASSED — enforcement demo complete.")
            print()
            return 0
        else:
            print("  ONE OR MORE STAGES FAILED — see FAIL lines above.", file=sys.stderr)
            print()
            return 1

    finally:
        _cleanup(proc, client)


if __name__ == "__main__":
    sys.exit(main())
