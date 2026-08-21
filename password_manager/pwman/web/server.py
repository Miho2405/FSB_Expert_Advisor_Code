"""HTTP transport for the local web interface.

An unlocked vault behind an HTTP port is only acceptable with a specific set of
guards, so they are all in one place here:

* **Loopback only.** The socket refuses to bind anywhere but 127.0.0.1/::1, so
  the interface is never exposed to the network.
* **Host header pinning.** A malicious site can point its own domain at
  127.0.0.1 (DNS rebinding) and would then be *same-origin* with this server.
  Every request whose ``Host`` is not the loopback name we are serving is
  rejected before it reaches any handler -- this is the single most important
  check in this file.
* **CSRF token in a custom header.** A cross-origin page cannot set
  ``X-CSRF-Token`` without a preflight, and no CORS headers are ever sent, so
  every state-changing request must come from our own page.
* **Origin pinning.** When an ``Origin`` header is present it must match.
* **Cookie hygiene.** The session cookie is ``HttpOnly`` and ``SameSite=Strict``
  (``Secure`` is meaningless and would be dropped on plain-http loopback).
* **A strict CSP** with no inline script or style and no external origins, so a
  hypothetical injection has nowhere to send data.
* **Idle auto-lock** driven by a watchdog thread, not merely by page activity:
  closing the tab must not leave keys in memory.
"""

from __future__ import annotations

import ipaddress
import json
import os
import signal
import socket
import threading
import time
import webbrowser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..errors import PwmanError
from .app import WebApp, dispatch

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

COOKIE_NAME = "pwman_session"
# Polling this must not keep the vault alive, otherwise an open tab would defeat
# the idle auto-lock forever.
NON_ACTIVITY_PATHS = frozenset({"/api/state"})
CSRF_HEADER = "X-CSRF-Token"
MAX_BODY_BYTES = 1 << 20
WATCHDOG_INTERVAL = 1.0

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cache-Control": "no-store, max-age=0",
}


def is_loopback(host: str) -> bool:
    """True only for addresses that never leave this machine."""
    cleaned = host.strip().strip("[]")
    if cleaned in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


class PwmanHTTPServer(ThreadingHTTPServer):
    """Threading server that carries the application state."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], app: WebApp, *, verbose: bool = False) -> None:
        if not is_loopback(address[0]):
            raise PwmanError(f"refusing to bind to {address[0]}: the web interface is loopback only")
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, RequestHandler)
        self.app = app
        self.verbose = verbose

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def allowed_hosts(self) -> set[str]:
        port = self.port
        names = {"127.0.0.1", "localhost", "[::1]", "::1"}
        return {f"{name}:{port}" for name in names} | names


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "pwman"
    sys_version = ""  # do not advertise the Python version

    # -- plumbing ---------------------------------------------------------- #

    @property
    def app(self) -> WebApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        if getattr(self.server, "verbose", False):
            super().log_message(format, *args)

    def handle_one_request(self) -> None:
        """A browser closing a tab mid-response is normal, not an error.

        Without this, every navigation away prints a BrokenPipeError traceback
        to the terminal the user is watching.
        """
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def do_HEAD(self) -> None:
        self._send(HTTPStatus.METHOD_NOT_ALLOWED, b"", "text/plain; charset=utf-8")

    def do_OPTIONS(self) -> None:
        # No CORS, ever: an unanswered preflight is what stops cross-origin calls.
        self._send(HTTPStatus.METHOD_NOT_ALLOWED, b"", "text/plain; charset=utf-8")

    # -- the request pipeline ----------------------------------------------- #

    def _handle(self, method: str) -> None:
        if not self._host_is_ours():
            self._send_json(403, {"error": "unexpected Host header"})
            return

        parsed = urlsplit(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._serve_static(path, method)
            return

        body, error = self._read_body()
        if error:
            self._send_json(400, {"error": error})
            return
        payload: dict[str, Any] = dict(body)
        for key, values in parse_qs(parsed.query).items():
            payload.setdefault(key, values[0])

        context: dict[str, Any] = {
            "authenticated": self.app.valid_session(self._session_cookie()),
            "csrf_ok": self.app.valid_csrf(self.headers.get(CSRF_HEADER)),
            "origin_ok": self._origin_is_ours(),
        }
        if not context["origin_ok"]:
            self._send_json(403, {"error": "unexpected Origin header"})
            return
        if context["authenticated"] and path not in NON_ACTIVITY_PATHS:
            self.app.touch()

        status, response = dispatch(self.app, method, path, payload, context)
        self._send_json(status, response, context=context)

    def _host_is_ours(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        return host in self.server.allowed_hosts()  # type: ignore[attr-defined]

    def _origin_is_ours(self) -> bool:
        """Reject a present-but-foreign Origin; absence is fine (curl, tests)."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https"):
            return False
        return f"{parts.hostname or ''}:{parts.port or 80}".lower() in {
            f"127.0.0.1:{self.server.port}",  # type: ignore[attr-defined]
            f"localhost:{self.server.port}",  # type: ignore[attr-defined]
            f"::1:{self.server.port}",  # type: ignore[attr-defined]
        }

    def _session_cookie(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            cookie = SimpleCookie(raw)
        except Exception:  # pragma: no cover - malformed cookie header
            return None
        morsel = cookie.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def _read_body(self) -> tuple[dict[str, Any], str | None]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}, "invalid Content-Length"
        if length < 0 or length > MAX_BODY_BYTES:
            return {}, "request body too large"
        if length == 0:
            return {}, None
        # A cross-origin page can only send text/plain, form-urlencoded or
        # multipart without a preflight; insisting on JSON blocks that route
        # even before the Origin check.
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return {}, "request body must be sent as application/json"
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}, "request body must be JSON"
        if not isinstance(parsed, dict):
            return {}, "request body must be a JSON object"
        return parsed, None

    # -- responses ---------------------------------------------------------- #

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)
        for header, value in (extra or {}).items():
            self.send_header(header, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict[str, Any], context: dict[str, Any] | None = None) -> None:
        extra: dict[str, str] = {}
        if context and context.get("set_session"):
            extra["Set-Cookie"] = (
                f"{COOKIE_NAME}={context['set_session']}; HttpOnly; SameSite=Strict; Path=/"
            )
        elif context and context.get("clear_session"):
            extra["Set-Cookie"] = f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        body = json.dumps(payload).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra)

    def _serve_static(self, path: str, method: str) -> None:
        if method != "GET":
            self._send_json(405, {"error": "method not allowed"})
            return
        target = STATIC_FILES.get(path)
        if target is None:
            self._send_json(404, {"error": "not found"})
            return
        name, content_type = target
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as handle:
                body = handle.read()
        except OSError:  # pragma: no cover - only if the install is broken
            self._send_json(500, {"error": f"missing asset {name}"})
            return
        self._send(HTTPStatus.OK, body, content_type)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def make_server(vault_path: str, *, host: str = "127.0.0.1", port: int = 8765,
                idle_timeout: int = 300, verbose: bool = False,
                failure_delay: float = 0.25) -> PwmanHTTPServer:
    app = WebApp(vault_path, idle_timeout=idle_timeout, failure_delay=failure_delay)
    return PwmanHTTPServer((host, port), app, verbose=verbose)


def start_watchdog(server: PwmanHTTPServer, stop: threading.Event) -> threading.Thread:
    """Lock the vault on idle even if the browser never comes back."""

    def loop() -> None:
        while not stop.wait(WATCHDOG_INTERVAL):
            server.app.expire_if_idle()

    thread = threading.Thread(target=loop, name="pwman-web-watchdog", daemon=True)
    thread.start()
    return thread


def _install_signal_handlers() -> None:
    """Turn SIGTERM/SIGHUP into the same clean shutdown as Ctrl-C.

    Raising from the handler unwinds ``serve_forever`` in the main thread, which
    is what runs the wipe-and-close path.  Calling ``shutdown()`` here instead
    would deadlock against the very loop that is being stopped.
    """

    def raise_interrupt(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGHUP"):
        handler_signal = getattr(signal, name, None)
        if handler_signal is None:
            continue
        try:
            signal.signal(handler_signal, raise_interrupt)
        except (OSError, ValueError):  # not the main thread, or unsupported
            pass


def serve(vault_path: str, *, host: str = "127.0.0.1", port: int = 8765, idle_timeout: int = 300,
          open_browser: bool = True, verbose: bool = False, announce=print) -> int:
    """Run the web interface until Ctrl-C.  The vault starts locked."""
    if not os.path.exists(vault_path):
        raise PwmanError(f"no vault at {vault_path} (run `pwman init` first)")
    try:
        server = make_server(vault_path, host=host, port=port, idle_timeout=idle_timeout, verbose=verbose)
    except OSError as exc:
        raise PwmanError(f"cannot listen on {host}:{port}: {exc}") from None

    url = f"http://{'localhost' if host in ('127.0.0.1', 'localhost') else f'[{host}]'}:{server.port}/"
    _install_signal_handlers()
    stop = threading.Event()
    start_watchdog(server, stop)
    announce(f"pwman web interface on {url}")
    announce(f"  vault: {vault_path}")
    announce(f"  the vault is locked; unlock it in the browser, auto-lock after {idle_timeout}s idle")
    announce("  loopback only - press Ctrl-C to stop and wipe the keys")
    if open_browser:
        threading.Thread(target=_open_later, args=(url,), daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        announce("")
    finally:
        stop.set()
        server.app.lock("shutdown")
        server.shutdown()
        server.server_close()
        announce("stopped; vault locked")
    return 0


def _open_later(url: str) -> None:  # pragma: no cover - depends on the desktop
    time.sleep(0.3)
    try:
        webbrowser.open(url)
    except Exception:
        pass
