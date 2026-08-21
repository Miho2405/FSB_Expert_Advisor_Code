"""The local web interface: security guards first, then the API itself.

Every test drives a real HTTP server on an ephemeral loopback port, so the
transport-level protections (Host pinning, CSRF, cookies, headers) are exercised
exactly as a browser would hit them.
"""

from __future__ import annotations

import http.client
import json
import threading
import time

import pytest
from conftest import TEST_MASTER, cheap_kdf

from pwman.errors import PwmanError
from pwman.session import Session
from pwman.vault import Entry
from pwman.web.server import PwmanHTTPServer, is_loopback, make_server

MASTER = TEST_MASTER.decode()


class Client:
    """Minimal HTTP client that mimics what the page does."""

    def __init__(self, server: PwmanHTTPServer) -> None:
        self.server = server
        self.port = server.port
        self.cookie: str | None = None
        self.csrf: str | None = None

    def request(self, method: str, path: str, body=None, *, csrf: bool = True, cookie: bool = True,
                host: str | None = None, origin: str | None = None, raw_body: bytes | None = None,
                headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        request_headers = dict(headers or {})
        request_headers.setdefault("Host", host or f"127.0.0.1:{self.port}")
        if origin:
            request_headers["Origin"] = origin
        if cookie and self.cookie:
            request_headers["Cookie"] = self.cookie
        if csrf and self.csrf:
            request_headers["X-CSRF-Token"] = self.csrf
        payload = raw_body
        if payload is None and body is not None:
            payload = json.dumps(body).encode()
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        data = response.read()
        try:
            parsed = json.loads(data.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        result = (response.status, dict(response.getheaders()), parsed, data)
        connection.close()
        return result

    def unlock(self, password: str = MASTER):
        status, headers, payload, _ = self.request("POST", "/api/unlock", {"password": password}, csrf=False)
        if status == 200:
            self.cookie = headers["Set-Cookie"].split(";")[0]
            self.csrf = payload["csrf"]
        return status, headers, payload


@pytest.fixture
def web(vault_path):
    with Session.create(vault_path, TEST_MASTER, kdf=cheap_kdf()) as session:
        session.vault.add(Entry(name="github", username="me@example.com", password="a-strong-enough-pw-42",
                                url="https://github.com", tags=["dev"], totp_secret="JBSWY3DPEHPK3PXP"))
        session.vault.add(Entry(name="bank", username="12345", password="hunter2", notes="pin 1234"))
        session.save()

    server = make_server(vault_path, port=0, idle_timeout=300, failure_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield Client(server)
    finally:
        server.app.lock("test")
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Binding and transport guards
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host, loopback", [("127.0.0.1", True), ("localhost", True), ("::1", True),
                                            ("0.0.0.0", False), ("192.168.1.10", False), ("example.com", False)])
def test_loopback_detection(host, loopback):
    assert is_loopback(host) is loopback


def test_binding_to_a_public_interface_is_refused(vault_path):
    with pytest.raises(PwmanError) as error:
        make_server(vault_path, host="0.0.0.0", port=0)
    assert "loopback only" in str(error.value)


def test_foreign_host_header_is_rejected(web):
    """DNS rebinding: a hostile site pointing its domain at 127.0.0.1."""
    status, _, payload, _ = web.request("GET", "/api/state", host="attacker.example.com")
    assert status == 403
    assert "Host" in payload["error"]


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_loopback_host_headers_are_accepted(web, host):
    status, _, _, _ = web.request("GET", "/api/state", host=f"{host}:{web.port}")
    assert status == 200


def test_foreign_origin_is_rejected(web):
    web.unlock()
    status, _, payload, _ = web.request("GET", "/api/entries", origin="https://evil.example")
    assert status == 403
    assert "Origin" in payload["error"]


def test_own_origin_is_accepted(web):
    web.unlock()
    status, _, _, _ = web.request("GET", "/api/entries", origin=f"http://localhost:{web.port}")
    assert status == 200


def test_no_cors_headers_are_ever_sent(web):
    for method, path in (("GET", "/api/state"), ("GET", "/"), ("OPTIONS", "/api/entries")):
        _, headers, _, _ = web.request(method, path)
        assert not [name for name in headers if name.lower().startswith("access-control-")]


def test_preflight_is_refused(web):
    status, _, _, _ = web.request("OPTIONS", "/api/entries")
    assert status == 405


def test_security_headers_on_every_response(web):
    for path in ("/", "/app.js", "/api/state"):
        _, headers, _, _ = web.request("GET", path)
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        assert "'unsafe-inline'" not in headers["Content-Security-Policy"]
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert "no-store" in headers["Cache-Control"]
        assert "Python" not in headers.get("Server", "")


def test_oversized_and_malformed_bodies_are_refused(web):
    status, _, payload, _ = web.request("POST", "/api/unlock", raw_body=b"x" * (1 << 20) + b"x",
                                        headers={"Content-Length": str((1 << 20) + 1)}, csrf=False)
    assert status == 400
    status, _, payload, _ = web.request("POST", "/api/unlock", raw_body=b"{not json", csrf=False)
    assert status == 400
    status, _, payload, _ = web.request("POST", "/api/unlock", raw_body=b'"a string"', csrf=False)
    assert status == 400


# --------------------------------------------------------------------------- #
# Static assets
# --------------------------------------------------------------------------- #

def test_index_and_assets_are_served(web):
    status, headers, _, body = web.request("GET", "/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"<title>pwman</title>" in body
    assert b"<script src=\"/app.js\">" in body
    assert b"onclick=" not in body  # no inline handlers: the CSP would block them

    for path, content_type in (("/app.js", "text/javascript"), ("/style.css", "text/css"),
                               ("/favicon.svg", "image/svg+xml")):
        status, headers, _, _ = web.request("GET", path)
        assert status == 200
        assert headers["Content-Type"].startswith(content_type)


@pytest.mark.parametrize("path", ["/../pwman/crypto.py", "/static/../../etc/passwd", "/vault.pmv", "/app.js/"])
def test_only_whitelisted_files_are_reachable(web, path):
    status, _, _, _ = web.request("GET", path)
    assert status == 404


def test_static_files_reject_other_methods(web):
    status, _, _, _ = web.request("POST", "/", {"x": 1})
    assert status == 405


# --------------------------------------------------------------------------- #
# Unlocking
# --------------------------------------------------------------------------- #

def test_state_before_unlocking_reveals_nothing(web):
    status, _, payload, _ = web.request("GET", "/api/state")
    assert status == 200
    assert payload["locked"] is True
    assert "entries" not in payload


def test_every_data_endpoint_requires_a_session(web):
    for method, path in (("GET", "/api/entries"), ("GET", "/api/audit"), ("GET", "/api/info"),
                         ("POST", "/api/entries"), ("POST", "/api/generate")):
        status, _, payload, _ = web.request(method, path, {} if method == "POST" else None)
        assert status == 401, path
        assert payload["error"] == "locked"


def test_wrong_master_password_sets_no_cookie(web):
    status, headers, payload = web.unlock("not the master password")
    assert status == 401
    assert "Set-Cookie" not in headers
    assert payload["failures"] == 1
    assert web.cookie is None


def test_failed_attempts_are_counted(web):
    for expected in (1, 2, 3):
        _, _, payload = web.unlock("wrong")
        assert payload["failures"] == expected
    assert web.unlock()[0] == 200


def test_unlock_sets_a_hardened_cookie(web):
    status, headers, payload = web.unlock()
    assert status == 200
    cookie = headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert len(payload["csrf"]) > 30
    assert payload["entries"] == 2


def test_a_session_cookie_from_before_a_lock_is_worthless(web):
    web.unlock()
    old_cookie, old_csrf = web.cookie, web.csrf
    web.request("POST", "/api/lock")

    web.cookie, web.csrf = old_cookie, old_csrf
    status, _, _, _ = web.request("GET", "/api/entries")
    assert status == 401


def test_lock_clears_the_cookie_and_wipes_the_keys(web):
    web.unlock()
    status, headers, _, _ = web.request("POST", "/api/lock")
    assert status == 200
    assert "Max-Age=0" in headers["Set-Cookie"]
    assert not web.server.app.unlocked


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("method, path, body", [
    ("POST", "/api/entries", {"name": "x"}),
    ("PUT", "/api/entries/{id}", {"username": "x"}),
    ("DELETE", "/api/entries/{id}", None),
    ("POST", "/api/entries/{id}/reveal", None),
    ("POST", "/api/lock", None),
])
def test_mutating_endpoints_need_the_csrf_token(web, method, path, body):
    web.unlock()
    entry_id = web.request("GET", "/api/entries")[2]["entries"][0]["id"]
    status, _, payload, _ = web.request(method, path.format(id=entry_id), body, csrf=False)
    assert status == 403
    assert "CSRF" in payload["error"]


def test_a_wrong_csrf_token_is_rejected(web):
    web.unlock()
    web.csrf = "definitely-not-the-token"
    status, _, _, _ = web.request("POST", "/api/generate", {"length": 20})
    assert status == 403


# --------------------------------------------------------------------------- #
# Reading entries
# --------------------------------------------------------------------------- #

def test_the_entry_list_carries_no_secrets(web):
    web.unlock()
    status, _, payload, raw = web.request("GET", "/api/entries")
    assert status == 200
    assert {entry["name"] for entry in payload["entries"]} == {"github", "bank"}
    assert b"hunter2" not in raw
    assert b"a-strong-enough-pw-42" not in raw
    assert b"JBSWY3DPEHPK3PXP" not in raw
    assert all("password" not in entry for entry in payload["entries"])
    assert payload["entries"][0]["bits"] > 0


def test_entry_detail_hides_the_password_but_shows_metadata(web):
    web.unlock()
    entry_id = _find(web, "bank")["id"]
    status, _, payload, raw = web.request("GET", f"/api/entries/{entry_id}")
    assert status == 200
    assert payload["notes"] == "pin 1234"
    assert payload["has_password"] is True
    assert b"hunter2" not in raw


def test_reveal_returns_the_password_only_on_a_guarded_post(web):
    web.unlock()
    entry_id = _find(web, "bank")["id"]
    assert web.request("GET", f"/api/entries/{entry_id}/reveal")[0] == 405

    status, _, payload, _ = web.request("POST", f"/api/entries/{entry_id}/reveal")
    assert status == 200
    assert payload["password"] == "hunter2"


def test_totp_endpoint(web):
    web.unlock()
    status, _, payload, _ = web.request("POST", f"/api/entries/{_find(web, 'github')['id']}/totp")
    assert status == 200
    assert payload["code"].isdigit() and len(payload["code"]) == 6
    assert 0 < payload["remaining"] <= 30

    status, _, _, _ = web.request("POST", f"/api/entries/{_find(web, 'bank')['id']}/totp")
    assert status == 404


def test_search_and_unknown_entries(web):
    web.unlock()
    status, _, payload, _ = web.request("POST", "/api/entries/search", {"q": "12345"})
    assert [entry["name"] for entry in payload["entries"]] == ["bank"]

    status, _, payload, _ = web.request("GET", "/api/entries/does-not-exist")
    assert status == 404


def test_audit_and_info(web):
    web.unlock()
    status, _, payload, _ = web.request("GET", "/api/audit")
    assert status == 200
    assert any(finding["entry"] == "bank" for finding in payload["findings"])

    status, _, payload, _ = web.request("GET", "/api/info")
    assert payload["entries"] == 2
    assert payload["mode"] == "0600"


# --------------------------------------------------------------------------- #
# Writing entries
# --------------------------------------------------------------------------- #

def test_create_update_delete_round_trip(web, vault_path):
    web.unlock()
    status, _, created, _ = web.request("POST", "/api/entries", {
        "name": "mail", "username": "me", "password": "created-through-the-web", "tags": "web, mail",
        "notes": "hello", "url": "https://mail.example",
    })
    assert status == 201
    assert created["tags"] == ["mail", "web"]

    status, _, updated, _ = web.request("PUT", f"/api/entries/{created['id']}",
                                        {"username": "changed", "password": "second-password-value"})
    assert status == 200
    assert updated["username"] == "changed"

    with Session.open(vault_path, TEST_MASTER) as session:  # really persisted, really encrypted
        entry = session.vault.get("mail")
        assert entry.password == "second-password-value"
        assert entry.history[0]["password"] == "created-through-the-web"
    with open(vault_path, "rb") as handle:
        assert b"second-password-value" not in handle.read()

    assert web.request("DELETE", f"/api/entries/{created['id']}")[0] == 200
    with Session.open(vault_path, TEST_MASTER) as session:
        assert not session.vault.has("mail")


def test_creation_validates_input(web):
    web.unlock()
    assert web.request("POST", "/api/entries", {"name": ""})[0] == 400
    assert web.request("POST", "/api/entries", {"name": "github"})[0] == 409          # duplicate
    assert web.request("POST", "/api/entries", {"name": "x", "username": 42})[0] == 400
    assert web.request("POST", "/api/entries", {"name": "y", "password": "p" * 9000})[0] == 400
    assert web.request("POST", "/api/entries", {"name": "z", "totp_secret": "not base32!"})[0] == 400


def test_generate_and_estimate(web):
    web.unlock()
    status, _, payload, _ = web.request("POST", "/api/generate", {"mode": "password", "length": 32})
    assert status == 200
    assert len(payload["value"]) == 32
    assert payload["bits"] > 150

    status, _, payload, _ = web.request("POST", "/api/generate", {"mode": "passphrase", "words": 5})
    assert len(payload["value"].split("-")) == 5
    assert payload["bits"] == 50.0

    status, _, payload, _ = web.request("POST", "/api/estimate", {"password": "123456"})
    assert payload["label"] == "very weak"
    assert payload["warnings"]


def test_generate_clamps_absurd_requests(web):
    web.unlock()
    assert len(web.request("POST", "/api/generate", {"length": 100000})[2]["value"]) == 256
    assert len(web.request("POST", "/api/generate", {"length": 1})[2]["value"]) == 4
    assert web.request("POST", "/api/generate", {"length": "twenty"})[0] == 400


def test_changing_the_master_password_requires_the_current_one(web, vault_path):
    web.unlock()
    status, _, payload, _ = web.request("POST", "/api/master", {"current": "wrong", "new": "brand-new-master-pw"})
    assert status == 401

    assert web.request("POST", "/api/master", {"current": MASTER, "new": "short"})[0] == 400

    status, _, _, _ = web.request("POST", "/api/master", {"current": MASTER, "new": "brand-new-master-pw"})
    assert status == 200
    with pytest.raises(Exception):
        Session.open(vault_path, TEST_MASTER)
    with Session.open(vault_path, b"brand-new-master-pw") as session:
        assert len(session.vault) == 2


# --------------------------------------------------------------------------- #
# Auto-lock
# --------------------------------------------------------------------------- #

def test_idle_timeout_locks_the_vault(vault_path):
    Session.create(vault_path, TEST_MASTER, kdf=cheap_kdf()).close()
    server = make_server(vault_path, port=0, idle_timeout=1, failure_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    client = Client(server)
    try:
        client.unlock()
        assert client.request("GET", "/api/entries")[0] == 200
        time.sleep(1.1)
        assert server.app.expire_if_idle() is True
        assert client.request("GET", "/api/entries")[0] == 401
        assert client.request("GET", "/api/state")[2]["reason"] == "idle"
    finally:
        server.app.lock("test")
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_polling_the_state_does_not_postpone_the_auto_lock(vault_path):
    """An open browser tab must not keep the vault alive forever."""
    Session.create(vault_path, TEST_MASTER, kdf=cheap_kdf()).close()
    server = make_server(vault_path, port=0, idle_timeout=1, failure_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    client = Client(server)
    try:
        client.unlock()
        for _ in range(6):  # what the page's poller does, for longer than the timeout
            time.sleep(0.2)
            assert client.request("GET", "/api/state")[0] == 200
        assert server.app.expire_if_idle() is True
    finally:
        server.app.lock("test")
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_real_requests_do_postpone_the_auto_lock(vault_path):
    Session.create(vault_path, TEST_MASTER, kdf=cheap_kdf()).close()
    server = make_server(vault_path, port=0, idle_timeout=2, failure_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    client = Client(server)
    try:
        client.unlock()
        for _ in range(6):
            time.sleep(0.2)
            assert client.request("GET", "/api/entries")[0] == 200
        assert server.app.expire_if_idle() is False
    finally:
        server.app.lock("test")
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _find(client: Client, name: str) -> dict:
    entries = client.request("GET", "/api/entries")[2]["entries"]
    return next(entry for entry in entries if entry["name"] == name)


def test_a_second_unlock_takes_over_the_session_and_says_so(web, vault_path):
    """Opening the UI in another window must not look like an idle lock."""
    first = Client(web.server)
    first.unlock()
    second = Client(web.server)
    second.unlock()

    status, _, payload, _ = first.request("GET", "/api/entries")
    assert status == 401
    assert payload["reason"] == "replaced"
    assert web.server.app.unlocked  # the vault itself is still open for the new window
    assert second.request("GET", "/api/entries")[0] == 200


def test_a_client_hanging_up_mid_request_is_not_an_error(web, capfd):
    """Closing a tab must not print a traceback into the user's terminal."""
    web.unlock()
    connection = http.client.HTTPConnection("127.0.0.1", web.port, timeout=5)
    connection.putrequest("GET", "/api/entries", skip_host=True)
    connection.putheader("Host", f"127.0.0.1:{web.port}")
    connection.putheader("Cookie", web.cookie or "")
    connection.endheaders()
    connection.sock.close()  # hang up before reading the response
    time.sleep(0.3)

    assert web.request("GET", "/api/entries")[0] == 200  # server still healthy
    assert "Traceback" not in capfd.readouterr().err


def test_the_server_shuts_down_cleanly_on_a_signal(vault_path, tmp_path):
    """`kill` (or a service manager stopping it) must run the wipe path."""
    import os
    import signal as signal_module
    import socket
    import subprocess
    import sys

    Session.create(vault_path, TEST_MASTER, kdf=cheap_kdf()).close()
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    process = subprocess.Popen(
        [sys.executable, "-m", "pwman", "--vault", vault_path, "web",
         "--port", str(port), "--no-browser"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            line = process.stdout.readline()
            if "web interface on" in line:
                break
        else:  # pragma: no cover - only on a very slow machine
            pytest.fail("server never announced itself")

        process.send_signal(signal_module.SIGTERM)
        output = process.stdout.read()
        assert process.wait(timeout=15) == 0
        assert "stopped; vault locked" in output
        assert "Traceback" not in output
    finally:
        if process.poll() is None:  # pragma: no cover - cleanup path
            process.kill()
            process.wait(timeout=5)
