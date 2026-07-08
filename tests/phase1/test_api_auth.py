"""
API authentication boundary gate tests.

The enforcer has no TCP listener. Authentication is the Unix socket's file
permissions: only the owning user/group may connect; everyone else is rejected
by the OS, not by an HTTP 401. These tests assert that boundary is real.

Unlike test_nftables.py, these pass today — they exercise socket hardening in
main.go, which does not depend on the LinuxSandbox backend.
"""

import os
import pwd
import socket
import stat

import pytest

pytestmark = pytest.mark.linux_only


def test_socket_permissions_are_restrictive(enforcer):
    """Socket is 0660 and its directory is 0700 — no world access to the API."""
    sock = enforcer.socket_path
    sock_mode = stat.S_IMODE(os.stat(sock).st_mode)
    assert sock_mode == 0o660, f"socket must be 0660, got {oct(sock_mode)}"

    parent_mode = stat.S_IMODE(os.stat(sock.parent).st_mode)
    assert parent_mode == 0o700, f"socket directory must be 0700, got {oct(parent_mode)}"


def test_unprivileged_caller_cannot_connect(enforcer):
    """
    An unauthorized process is rejected at the OS level. Fork, drop to `nobody`,
    and attempt to connect — the child exits 0 only if the connect was refused.
    """
    try:
        nobody = pwd.getpwnam("nobody")
    except KeyError:
        pytest.skip("no 'nobody' user available to drop privileges to")

    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.setgid(nobody.pw_gid)
            os.setuid(nobody.pw_uid)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(3)
            try:
                s.connect(str(enforcer.socket_path))
                code = 2  # connected — the auth boundary FAILED
            except (PermissionError, OSError):
                code = 0  # EACCES / ENOENT — correctly rejected
            finally:
                s.close()
        except Exception:
            code = 3
        os._exit(code)

    _, status = os.waitpid(pid, 0)
    exit_code = os.waitstatus_to_exitcode(status)
    assert exit_code != 2, "unprivileged caller was able to connect — auth boundary breached"
    assert exit_code == 0, f"unexpected child failure (exit {exit_code})"
