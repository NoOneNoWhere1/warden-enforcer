import base64
import os
import platform
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from enforcer_client import EnforcerClient


def is_linux() -> bool:
    return platform.system() == "Linux"


def has_root() -> bool:
    return os.geteuid() == 0


@pytest.fixture
def require_linux():
    if not is_linux():
        pytest.skip("requires Linux kernel")


@pytest.fixture
def require_root():
    if not has_root():
        pytest.skip("requires root (nftables/namespace operations)")


def _enforcer_binary() -> Path | None:
    """Locate the built enforcer binary (go build -o bin/warden-enforcer)."""
    override = os.environ.get("ENFORCER_BIN")
    if override:
        return Path(override)
    candidate = Path(__file__).parents[2] / "enforcer" / "bin" / "warden-enforcer"
    if candidate.exists():
        return candidate
    return None


@pytest.fixture(scope="module")
def enforcer(tmp_path_factory):
    """
    Launch the real enforcer binary over its Unix socket and yield a handle
    exposing `.process`, `.socket_path`, and `.client`.

    The enforcer authenticates by socket file permissions, so the test dials
    the Unix socket directly — there is no TCP listener. The binary requires a
    signing key in the environment; we provision an ephemeral one. A missing
    binary on Linux is a hard failure (CI must build it first), not a skip,
    so the gate cannot pass by quietly testing nothing.
    """
    if not is_linux():
        pytest.skip("requires Linux kernel")
    if not has_root():
        pytest.skip("requires root (nftables/namespace operations)")

    bin_path = _enforcer_binary()
    if bin_path is None:
        pytest.fail("enforcer binary not found at enforcer/bin/warden-enforcer — build it before the gate")

    sock_dir = tmp_path_factory.mktemp("enforcer")
    socket_path = sock_dir / "api.sock"
    outbox_path = sock_dir / "outbox.jsonl"

    env = dict(os.environ)
    env["ENFORCER_KEY_ID"] = "gate-key-001"
    env["ENFORCER_SIGNING_KEY"] = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    env["ENFORCER_SOCKET"] = str(socket_path)
    # Durable spool in the test tempdir: the default path needs root
    # and would collide across modules. ENFORCER_REKOR_URL flows through from
    # the environment above — set by CI's gate job, unset locally.
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
        client=EnforcerClient(str(socket_path)),
    )

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    # The enforcer keeps no persistent state: killing it orphans the kernel
    # namespaces (and their wdn* veth uplinks) of any sessions the module
    # left behind, and the next module's fresh enforcer restarts its uplink
    # allocator at wdn0 — colliding with the orphans. Sweep them here.
    # (Startup reconciliation — re-adopting pre-existing namespaces — is not yet
    # implemented; this sweep is a test-only workaround.)
    netns_list = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    for line in netns_list.splitlines():
        name = line.split()[0]
        if name.startswith("warden_"):
            subprocess.run(["ip", "netns", "del", name], capture_output=True)


@pytest.fixture
def transit_guest():
    """
    Attach a throwaway 'guest' namespace to a session namespace and return a
    ping(ip) -> bool callable that sends from the guest.

    The session ruleset filters the *forward* hook: a process exec'd directly
    inside the session ns generates output-hook traffic the filter never
    sees. This fixture emulates the runsc downlink — guest traffic transits
    the session ns, so the forward rules (and masquerade) apply to it.
    """
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
    """
    Host-side dummy interface holding the gate-test target IPs, so
    reachability assertions are real: the allowed IP genuinely answers, and
    a blocked IP would answer too if the filter leaked.
    """
    subprocess.check_call(["ip", "link", "add", "wdummy0", "type", "dummy"])
    for ip in ("10.99.77.1/32", "10.99.88.1/32", "169.254.169.254/32"):
        subprocess.check_call(["ip", "addr", "add", ip, "dev", "wdummy0"])
    subprocess.check_call(["ip", "link", "set", "wdummy0", "up"])

    yield SimpleNamespace(
        allowed="10.99.77.1", blocked="10.99.88.1", metadata="169.254.169.254"
    )

    subprocess.run(["ip", "link", "del", "wdummy0"], capture_output=True)
