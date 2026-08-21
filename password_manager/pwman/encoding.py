"""Deterministic encoding helpers shared by the file format and the AAD."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .errors import VaultFormatError


def b64e(data: bytes) -> str:
    """Base64 (standard alphabet, padded) for JSON transport."""
    return base64.b64encode(bytes(data)).decode("ascii")


def b64d(text: Any) -> bytes:
    if not isinstance(text, str):
        raise VaultFormatError("expected a base64 string in the vault header")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise VaultFormatError("vault header contains invalid base64") from None


def canonical_json(obj: Any) -> bytes:
    """Byte-stable JSON used as AEAD associated data.

    Sorted keys, no insignificant whitespace, no non-ASCII escapes surprises:
    the same header object must always produce the same bytes, otherwise
    authentication would fail after a harmless round-trip through ``json``.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
