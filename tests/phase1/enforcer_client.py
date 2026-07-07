"""
Minimal HTTP-over-Unix-socket client for the enforcer gate tests.

The enforcer binds a Unix domain socket, not a TCP port — file permissions are
the authentication boundary (E2). `requests` cannot speak to a Unix socket
without a third-party adapter, so this uses only the stdlib.
"""

import http.client
import json
import socket


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 5.0):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class EnforcerClient:
    def __init__(self, socket_path: str):
        self._socket_path = socket_path

    def _request(self, method: str, path: str, body=None):
        conn = _UnixHTTPConnection(self._socket_path)
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
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
        return status, parsed

    def post(self, path: str, body: dict):
        return self._request("POST", path, body)

    def delete(self, path: str):
        return self._request("DELETE", path)

    def get(self, path: str):
        return self._request("GET", path)
