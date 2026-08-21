"""RFC 4226 / RFC 6238 one-time passwords.

Storing TOTP seeds next to passwords weakens the "second factor" idea -- one
stolen vault then yields both.  It is still offered because the realistic
alternative is people disabling 2FA entirely; SECURITY.md spells out the
trade-off so the choice is informed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

from .errors import PwmanError

ALGORITHMS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}
DEFAULT_STEP = 30
DEFAULT_DIGITS = 6


@dataclass(frozen=True)
class TotpConfig:
    secret: str
    digits: int = DEFAULT_DIGITS
    step: int = DEFAULT_STEP
    algorithm: str = "sha1"
    label: str = ""

    def to_uri_fragment(self) -> str:
        return f"{self.secret} ({self.algorithm}, {self.digits} digits, {self.step}s)"


def normalize_secret(secret: str) -> bytes:
    """Decode a base32 TOTP seed, tolerating spaces, lowercase and missing padding."""
    cleaned = "".join(secret.split()).replace("-", "").upper()
    if not cleaned:
        raise PwmanError("empty TOTP secret")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        raw = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError):
        raise PwmanError("TOTP secret is not valid base32") from None
    if not raw:
        raise PwmanError("TOTP secret decodes to nothing")
    return raw


def hotp(key: bytes, counter: int, *, digits: int = DEFAULT_DIGITS, algorithm: str = "sha1") -> str:
    """RFC 4226 counter-based one-time password."""
    if algorithm not in ALGORITHMS:
        raise PwmanError(f"unsupported TOTP algorithm: {algorithm}")
    if not 6 <= digits <= 10:
        raise PwmanError("TOTP digits must be between 6 and 10")
    digest = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)


def totp(config: TotpConfig, *, at: float | None = None) -> tuple[str, int]:
    """Current code and the seconds it stays valid."""
    moment = time.time() if at is None else at
    if config.step <= 0:
        raise PwmanError("TOTP step must be positive")
    counter = int(moment // config.step)
    code = hotp(normalize_secret(config.secret), counter, digits=config.digits, algorithm=config.algorithm)
    remaining = int(config.step - (moment % config.step))
    return code, remaining


def parse_otpauth(uri: str) -> TotpConfig:
    """Parse an ``otpauth://totp/...`` URI as produced by most 2FA QR codes."""
    parsed = urlparse(uri.strip())
    if parsed.scheme != "otpauth" or parsed.netloc.lower() != "totp":
        raise PwmanError("not an otpauth://totp/ URI")
    query = parse_qs(parsed.query)
    secret = (query.get("secret") or [""])[0]
    if not secret:
        raise PwmanError("otpauth URI has no secret")
    algorithm = (query.get("algorithm") or ["SHA1"])[0].lower()
    if algorithm not in ALGORITHMS:
        raise PwmanError(f"unsupported TOTP algorithm: {algorithm}")
    try:
        digits = int((query.get("digits") or [DEFAULT_DIGITS])[0])
        step = int((query.get("period") or [DEFAULT_STEP])[0])
    except ValueError:
        raise PwmanError("otpauth URI has non-numeric digits/period") from None
    normalize_secret(secret)  # fail early on a broken seed
    return TotpConfig(secret=secret, digits=digits, step=step, algorithm=algorithm,
                      label=unquote(parsed.path.lstrip("/")))


def parse_secret_input(value: str) -> TotpConfig:
    """Accept either a raw base32 seed or a full otpauth:// URI."""
    value = value.strip()
    if value.lower().startswith("otpauth://"):
        return parse_otpauth(value)
    normalize_secret(value)
    return TotpConfig(secret="".join(value.split()).upper())
