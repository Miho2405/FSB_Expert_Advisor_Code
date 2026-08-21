"""State and JSON API behind the web interface.

This module knows nothing about HTTP.  It owns the unlocked
:class:`~pwman.session.Session`, the tokens that guard it, and the idle timer;
``server.py`` maps requests onto it.  Keeping the split means the security rules
below can be tested without sockets.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from typing import Any, Callable

from .. import crypto, generator, strength
from ..errors import AuthenticationError, EntryNotFound, PwmanError, VaultError
from ..session import Session
from ..totp import TotpConfig, parse_secret_input, totp
from ..vault import Entry

TOKEN_BYTES = 32
DEFAULT_IDLE_TIMEOUT = 300
MAX_ENTRY_FIELD = 8192
MAX_NOTES = 65536

Handler = Callable[["WebApp", dict, dict], "tuple[int, dict]"]


class WebApp:
    """The unlocked-vault state machine the HTTP layer talks to."""

    def __init__(self, vault_path: str, *, idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
                 failure_delay: float = 0.25) -> None:
        self.vault_path = vault_path
        self.idle_timeout = max(int(idle_timeout), 0)
        self.failure_delay = failure_delay
        self._lock = threading.RLock()
        self._session: Session | None = None
        self._session_token: str | None = None
        self._csrf_token: str | None = None
        self._last_activity = 0.0
        self._failures = 0
        self._locked_reason = "start"

    # -- lock state --------------------------------------------------------- #

    @property
    def unlocked(self) -> bool:
        with self._lock:
            return self._session is not None

    def seconds_idle(self) -> float:
        with self._lock:
            return time.monotonic() - self._last_activity if self._session else 0.0

    def touch(self) -> None:
        with self._lock:
            self._last_activity = time.monotonic()

    def lock(self, reason: str = "manual") -> None:
        """Wipe the keys and invalidate every token."""
        with self._lock:
            if self._session is not None:
                self._session.close()
            self._session = None
            self._session_token = None
            self._csrf_token = None
            self._locked_reason = reason

    def expire_if_idle(self) -> bool:
        """Called by the watchdog: lock once the idle timeout has passed."""
        with self._lock:
            if self._session is None or self.idle_timeout <= 0:
                return False
            if time.monotonic() - self._last_activity < self.idle_timeout:
                return False
            self.lock("idle")
            return True

    # -- authentication ----------------------------------------------------- #

    def valid_session(self, token: str | None) -> bool:
        with self._lock:
            if self._session_token is None or not token:
                return False
            return secrets.compare_digest(self._session_token, token)

    def valid_csrf(self, token: str | None) -> bool:
        with self._lock:
            if self._csrf_token is None or not token:
                return False
            return secrets.compare_digest(self._csrf_token, token)

    def _unlock(self, password: str) -> dict[str, Any]:
        """Open the vault; raises AuthenticationError on a wrong password."""
        buffer = bytearray(password.encode("utf-8"))
        try:
            session = Session.open(self.vault_path, bytes(buffer))
        finally:
            crypto.wipe(buffer)
        with self._lock:
            if self._session is not None:  # replace any previous session
                self._session.close()
            self._session = session
            self._session_token = secrets.token_urlsafe(TOKEN_BYTES)
            self._csrf_token = secrets.token_urlsafe(TOKEN_BYTES)
            self._failures = 0
            self._last_activity = time.monotonic()
            return {"session": self._session_token, "csrf": self._csrf_token,
                    "warnings": session.warnings}

    # -- helpers ------------------------------------------------------------ #

    @property
    def session(self) -> Session:
        with self._lock:
            if self._session is None:
                raise PwmanError("vault is locked")
            return self._session

    def _entry_summary(self, entry: Entry) -> dict[str, Any]:
        estimate = strength.estimate(entry.password) if entry.password else None
        return {
            "id": entry.id,
            "name": entry.name,
            "username": entry.username,
            "url": entry.url,
            "tags": list(entry.tags),
            "has_password": bool(entry.password),
            "has_totp": bool(entry.totp_secret),
            "bits": round(estimate.bits, 1) if estimate else 0.0,
            "label": estimate.label if estimate else "very weak",
            "updated_at": entry.updated_at,
            "password_changed_at": entry.password_changed_at,
        }

    def _entry_detail(self, entry: Entry) -> dict[str, Any]:
        """Everything except the secrets themselves."""
        detail = self._entry_summary(entry)
        detail.update({
            "notes": entry.notes,
            "created_at": entry.created_at,
            "history": [{"changed_at": item.get("changed_at", "")} for item in entry.history],
        })
        return detail


# --------------------------------------------------------------------------- #
# Request payload validation
# --------------------------------------------------------------------------- #

def _text(payload: dict, key: str, *, limit: int = MAX_ENTRY_FIELD, default: str | None = "") -> str | None:
    if key not in payload:
        return default
    value = payload[key]
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PwmanError(f"{key} must be a string")
    if len(value) > limit:
        raise PwmanError(f"{key} is too long")
    return value


def _tags(payload: dict) -> list[str] | None:
    if "tags" not in payload:
        return None
    value = payload["tags"]
    if isinstance(value, str):
        value = value.replace(",", " ").split()
    if not isinstance(value, list):
        raise PwmanError("tags must be a list")
    if len(value) > 64:
        raise PwmanError("too many tags")
    unique: dict[str, str] = {}
    for tag in value:
        cleaned = str(tag).strip()
        if cleaned:
            unique.setdefault(cleaned.casefold(), cleaned)
    return sorted(unique.values(), key=str.casefold)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

def unlock(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    password = _text(payload, "password", limit=4096, default=None)
    if not password:
        return 400, {"error": "master password required"}
    try:
        tokens = app._unlock(password)
    except AuthenticationError:
        with app._lock:
            app._failures += 1
            failures = app._failures
        # The KDF already costs an attacker ~0.75 s per try; this adds a growing
        # penalty on top so a script cannot hammer the endpoint for free.
        time.sleep(min(app.failure_delay * 2**failures, 5.0))
        return 401, {"error": "wrong master password", "failures": failures}
    context["set_session"] = tokens["session"]
    return 200, {"csrf": tokens["csrf"], "warnings": tokens["warnings"],
                 "idle_timeout": app.idle_timeout, "entries": len(app.session.vault)}


def lock(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    app.lock("manual")
    context["clear_session"] = True
    return 200, {"locked": True}


def state(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    """Probe endpoint: safe to call while locked, reveals nothing about content."""
    return 200, {
        "locked": not app.unlocked,
        "authenticated": bool(context.get("authenticated")),
        "vault": app.vault_path,
        "idle_timeout": app.idle_timeout,
        "idle_seconds": round(app.seconds_idle()),
        "reason": app._locked_reason if not app.unlocked else "",
    }


def info(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    return 200, app.session.info()


def list_entries(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    vault = app.session.vault
    query = str(payload.get("q", ""))[:256]
    tag = str(payload.get("tag", ""))[:256]
    entries = vault.search(query, tag=tag)
    return 200, {
        "entries": [app._entry_summary(entry) for entry in entries],
        "tags": vault.tags(),
        "total": len(vault),
    }


def get_entry(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    return 200, app._entry_detail(app.session.vault.get(context["id"]))


def reveal_entry(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    """The only endpoint that returns a stored password -- POST and CSRF guarded."""
    entry = app.session.vault.get(context["id"])
    if not entry.password:
        return 404, {"error": "this entry has no password"}
    return 200, {"password": entry.password}


def entry_totp(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    entry = app.session.vault.get(context["id"])
    if not entry.totp_secret:
        return 404, {"error": "this entry has no TOTP secret"}
    code, remaining = totp(TotpConfig(entry.totp_secret))
    return 200, {"code": code, "remaining": remaining}


def create_entry(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    session = app.session
    name = (_text(payload, "name") or "").strip()
    if not name:
        return 400, {"error": "name is required"}
    entry = Entry(
        name=name,
        username=_text(payload, "username") or "",
        url=_text(payload, "url") or "",
        notes=_text(payload, "notes", limit=MAX_NOTES) or "",
        password=_text(payload, "password") or "",
        tags=_tags(payload) or [],
    )
    secret = (_text(payload, "totp_secret") or "").strip()
    if secret:
        entry.totp_secret = parse_secret_input(secret).secret
    session.vault.add(entry)
    session.save()
    return 201, app._entry_detail(entry)


def update_entry(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    session = app.session
    entry = session.vault.get(context["id"])
    changes: dict[str, Any] = {}
    for field, limit in (("name", MAX_ENTRY_FIELD), ("username", MAX_ENTRY_FIELD),
                         ("url", MAX_ENTRY_FIELD), ("notes", MAX_NOTES), ("password", MAX_ENTRY_FIELD)):
        value = _text(payload, field, limit=limit, default=None)
        if value is not None:
            changes[field] = value
    tags = _tags(payload)
    if tags is not None:
        changes["tags"] = tags
    if "totp_secret" in payload:
        secret = (_text(payload, "totp_secret") or "").strip()
        changes["totp_secret"] = parse_secret_input(secret).secret if secret else ""
    if not changes:
        return 400, {"error": "nothing to change"}
    session.vault.update(entry, **changes)
    session.save()
    return 200, app._entry_detail(entry)


def delete_entry(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    session = app.session
    entry = session.vault.get(context["id"])
    session.vault.delete(entry)
    session.save()
    return 200, {"deleted": entry.name}


def audit(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    findings = strength.audit(app.session.vault)
    return 200, {
        "findings": [finding.__dict__ for finding in findings],
        "summary": strength.summarise(findings),
        "entries": len(app.session.vault),
    }


def generate(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    """Generation runs server-side: the browser has no CSPRNG we control."""
    mode = str(payload.get("mode", "password"))
    if mode == "passphrase":
        words = _clamp(payload.get("words", generator.DEFAULT_WORDS), 3, 32)
        separator = str(payload.get("separator", "-"))[:4]
        value = generator.generate_passphrase(words, separator=separator,
                                              capitalize=bool(payload.get("capitalize")),
                                              add_digit=bool(payload.get("digit")))
        bits = generator.passphrase_entropy_bits(words, add_digit=bool(payload.get("digit")))
    else:
        policy = generator.Policy(
            length=_clamp(payload.get("length", generator.DEFAULT_LENGTH),
                          generator.MIN_LENGTH, generator.MAX_LENGTH),
            lower=payload.get("lower", True) is not False,
            upper=payload.get("upper", True) is not False,
            digits=payload.get("digits", True) is not False,
            symbols=payload.get("symbols", True) is not False,
            avoid_ambiguous=bool(payload.get("readable")),
        )
        value = generator.generate_password(policy)
        bits = generator.password_entropy_bits(policy)
    return 200, {"value": value, "bits": round(bits, 1)}


def estimate(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    """Strength feedback for something the user typed, without storing it."""
    password = _text(payload, "password", default="") or ""
    result = strength.estimate(password)
    return 200, {"bits": round(result.bits, 1), "label": result.label,
                 "warnings": list(result.warnings), "crack_time": result.crack_time_vault()}


def change_master(app: WebApp, payload: dict, context: dict) -> tuple[int, dict]:
    current = _text(payload, "current", limit=4096, default="") or ""
    new_password = _text(payload, "new", limit=4096, default="") or ""
    if len(new_password) < 10:
        return 400, {"error": "the new master password must be at least 10 characters"}
    session = app.session
    # Re-derive from the file to prove the caller knows the current password:
    # an unlocked browser tab alone must not be enough to lock the owner out.
    verification = Session.open(app.vault_path, current.encode("utf-8"))
    verification.close()
    session.change_master(new_password.encode("utf-8"))
    return 200, {"changed": True}


def _clamp(value: Any, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise PwmanError("expected a number") from None
    return max(low, min(number, high))


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #

ENTRY_ID = r"(?P<id>[A-Za-z0-9-]{1,64})"

# (method, pattern, handler, needs_auth, mutating)
ROUTES: tuple[tuple[str, re.Pattern[str], Handler, bool, bool], ...] = (
    # Unlock cannot carry a CSRF token yet -- it is the request that issues one.
    # The Host/Origin pinning plus the JSON content-type requirement is what
    # keeps a foreign page from reaching it.
    ("POST", re.compile(r"^/api/unlock$"), unlock, False, False),
    ("GET", re.compile(r"^/api/state$"), state, False, False),
    ("POST", re.compile(r"^/api/lock$"), lock, True, True),
    ("GET", re.compile(r"^/api/info$"), info, True, False),
    ("POST", re.compile(r"^/api/entries/search$"), list_entries, True, True),
    ("GET", re.compile(r"^/api/entries$"), list_entries, True, False),
    ("POST", re.compile(r"^/api/entries$"), create_entry, True, True),
    ("GET", re.compile(rf"^/api/entries/{ENTRY_ID}$"), get_entry, True, False),
    ("PUT", re.compile(rf"^/api/entries/{ENTRY_ID}$"), update_entry, True, True),
    ("DELETE", re.compile(rf"^/api/entries/{ENTRY_ID}$"), delete_entry, True, True),
    ("POST", re.compile(rf"^/api/entries/{ENTRY_ID}/reveal$"), reveal_entry, True, True),
    ("POST", re.compile(rf"^/api/entries/{ENTRY_ID}/totp$"), entry_totp, True, True),
    ("GET", re.compile(r"^/api/audit$"), audit, True, False),
    ("POST", re.compile(r"^/api/generate$"), generate, True, True),
    ("POST", re.compile(r"^/api/estimate$"), estimate, True, True),
    ("POST", re.compile(r"^/api/master$"), change_master, True, True),
)


def dispatch(app: WebApp, method: str, path: str, payload: dict, context: dict) -> tuple[int, dict]:
    """Find and run the handler for one request.

    ``context`` carries what the transport already checked (``authenticated``,
    ``csrf_ok``) and receives cookie instructions back.
    """
    allowed_methods = set()
    for route_method, pattern, handler, needs_auth, mutating in ROUTES:
        match = pattern.match(path)
        if not match:
            continue
        if route_method != method:
            allowed_methods.add(route_method)
            continue
        context.update(match.groupdict())
        if needs_auth and not context.get("authenticated"):
            if app.unlocked:
                # The vault is open, but this token is not the current one: a
                # second window unlocked and took the session over.
                return 401, {"error": "session replaced", "reason": "replaced"}
            return 401, {"error": "locked", "reason": app._locked_reason}
        if mutating and not context.get("csrf_ok"):
            return 403, {"error": "missing or invalid CSRF token"}
        try:
            return handler(app, payload, context)
        except EntryNotFound as error:
            return 404, {"error": str(error)}
        except VaultError as error:
            return 409, {"error": str(error)}
        except AuthenticationError as error:
            return 401, {"error": str(error)}
        except PwmanError as error:
            return 400, {"error": str(error)}
    if allowed_methods:
        return 405, {"error": f"method not allowed; try {', '.join(sorted(allowed_methods))}"}
    return 404, {"error": "no such endpoint"}
