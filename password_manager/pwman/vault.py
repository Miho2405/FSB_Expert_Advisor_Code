"""The decrypted vault: entries and the operations on them.

Only plain data lives here -- the crypto layer neither knows nor cares what the
payload means.  That separation keeps the format testable and makes it obvious
that no code path can write an entry to disk unencrypted.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .errors import VaultError, VaultFormatError

SCHEMA = 1
HISTORY_LIMIT = 10


def now_iso() -> str:
    """UTC timestamp, second resolution -- no local time zone leaks into the file."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value: str) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def age_days(value: str) -> float | None:
    stamp = parse_iso(value)
    if stamp is None:
        return None
    return (datetime.now(timezone.utc) - stamp).total_seconds() / 86400.0


@dataclass
class Entry:
    """One stored login."""

    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    totp_secret: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    password_changed_at: str = field(default_factory=now_iso)
    history: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "tags": list(self.tags),
            "totp_secret": self.totp_secret,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "password_changed_at": self.password_changed_at,
            "history": [dict(h) for h in self.history],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "Entry":
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            raise VaultFormatError("vault contains a malformed entry")
        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in known}
        kwargs.setdefault("id", str(uuid.uuid4()))
        tags = kwargs.get("tags") or []
        kwargs["tags"] = [str(t) for t in tags] if isinstance(tags, list) else []
        history = kwargs.get("history") or []
        kwargs["history"] = [
            {"password": str(h.get("password", "")), "changed_at": str(h.get("changed_at", ""))}
            for h in history
            if isinstance(h, dict)
        ]
        for text_field in ("username", "password", "url", "notes", "totp_secret", "created_at", "updated_at",
                           "password_changed_at"):
            if text_field in kwargs and not isinstance(kwargs[text_field], str):
                kwargs[text_field] = str(kwargs[text_field])
        return cls(**kwargs)

    def redacted(self) -> dict[str, Any]:
        """Same shape, but with every secret removed -- safe to print or log."""
        data = self.to_dict()
        data["password"] = "***" if self.password else ""
        data["totp_secret"] = "***" if self.totp_secret else ""
        data["history"] = [{"changed_at": h.get("changed_at", ""), "password": "***"} for h in self.history]
        return data


class Vault:
    """An ordered collection of entries with unique, case-insensitive names."""

    def __init__(self, entries: Iterable[Entry] | None = None) -> None:
        self._entries: list[Entry] = list(entries or [])

    # -- container behaviour ---------------------------------------------- #

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[Entry]:
        return iter(self._entries)

    @property
    def entries(self) -> list[Entry]:
        return list(self._entries)

    def names(self) -> list[str]:
        return sorted((e.name for e in self._entries), key=str.casefold)

    def tags(self) -> list[str]:
        return sorted({t for e in self._entries for t in e.tags}, key=str.casefold)

    # -- lookup ------------------------------------------------------------ #

    def get(self, needle: str) -> Entry:
        """Find exactly one entry by name (case-insensitive), id, or substring.

        Ambiguity is an error, never a silent "first match wins": picking the
        wrong login is how people paste a password into the wrong site.
        """
        needle = needle.strip()
        if not needle:
            raise VaultError("no entry name given")
        for entry in self._entries:
            if entry.id == needle or entry.name.casefold() == needle.casefold():
                return entry
        matches = [e for e in self._entries if needle.casefold() in e.name.casefold()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise VaultError(f"no entry matching {needle!r}")
        listed = ", ".join(sorted(e.name for e in matches)[:10])
        raise VaultError(f"{needle!r} matches {len(matches)} entries: {listed}")

    def has(self, name: str) -> bool:
        return any(e.name.casefold() == name.strip().casefold() for e in self._entries)

    def search(self, query: str = "", *, tag: str = "") -> list[Entry]:
        """Substring search over name, username, url, tags and notes."""
        query = query.strip().casefold()
        tag = tag.strip().casefold()
        result = []
        for entry in self._entries:
            if tag and tag not in [t.casefold() for t in entry.tags]:
                continue
            haystack = " ".join([entry.name, entry.username, entry.url, entry.notes, " ".join(entry.tags)]).casefold()
            if not query or query in haystack:
                result.append(entry)
        return sorted(result, key=lambda e: e.name.casefold())

    # -- mutation ----------------------------------------------------------- #

    def add(self, entry: Entry) -> Entry:
        name = entry.name.strip()
        if not name:
            raise VaultError("entry name must not be empty")
        if self.has(name):
            raise VaultError(f"an entry named {name!r} already exists")
        stored = replace(entry, name=name)
        self._entries.append(stored)
        return stored

    def update(self, entry: Entry, **changes: Any) -> Entry:
        """Apply field changes, maintaining history and timestamps."""
        if "name" in changes:
            new_name = str(changes["name"]).strip()
            if not new_name:
                raise VaultError("entry name must not be empty")
            if new_name.casefold() != entry.name.casefold() and self.has(new_name):
                raise VaultError(f"an entry named {new_name!r} already exists")
            entry.name = new_name
        if "password" in changes:
            new_password = str(changes["password"])
            if new_password != entry.password:
                if entry.password:
                    entry.history.insert(0, {"password": entry.password, "changed_at": entry.password_changed_at})
                    del entry.history[HISTORY_LIMIT:]
                entry.password = new_password
                entry.password_changed_at = now_iso()
        for key in ("username", "url", "notes", "totp_secret"):
            if key in changes:
                setattr(entry, key, str(changes[key]))
        if "tags" in changes:
            unique: dict[str, str] = {}
            for tag in changes["tags"]:
                cleaned = str(tag).strip()
                if cleaned:
                    unique.setdefault(cleaned.casefold(), cleaned)  # first spelling wins
            entry.tags = sorted(unique.values(), key=str.casefold)
        entry.updated_at = now_iso()
        return entry

    def delete(self, entry: Entry) -> None:
        self._entries = [e for e in self._entries if e.id != entry.id]

    # -- serialisation ------------------------------------------------------ #

    def to_payload(self) -> bytes:
        document = {"schema": SCHEMA, "entries": [e.to_dict() for e in self._entries]}
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_payload(cls, payload: bytes) -> "Vault":
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise VaultFormatError("vault content is not valid JSON (file may be corrupt)") from None
        if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
            raise VaultFormatError("vault content has an unexpected shape")
        schema = document.get("schema")
        if schema != SCHEMA:
            raise VaultFormatError(f"unsupported vault schema {schema!r}; this build understands {SCHEMA}")
        return cls(Entry.from_dict(item) for item in document["entries"])
