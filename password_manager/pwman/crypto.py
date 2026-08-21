"""Key derivation and authenticated encryption for pwman.

Nothing in here is home-grown crypto: key derivation is Argon2id (or scrypt),
encryption is an AEAD from ``cryptography`` (AES-256-GCM or ChaCha20-Poly1305),
and sub-keys come from HKDF-SHA256.  This module only wires those primitives
together and enforces the parameters.

Key hierarchy
-------------
::

    master password --Argon2id/scrypt--> KEK (key encryption key)
                                          |
                          HKDF(KEK, wrap_salt) --> wrap key --AEAD--> [ vault key ]
                                                                            |
                                          HKDF(VK, body_salt) --> body key --AEAD--> [ entries ]

Every save draws a fresh random ``wrap_salt`` and ``body_salt``, so the AEAD key
is unique per save and a repeated nonce can never lead to key/nonce reuse -- the
one failure mode that breaks GCM and Poly1305 catastrophically.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import AuthenticationError, CryptoError

KEY_LEN = 32          # 256 bit keys throughout
NONCE_LEN = 12        # 96 bit nonces: the native size for GCM and ChaCha20-Poly1305
SALT_LEN = 32         # HKDF salt per save
KDF_SALT_LEN = 16     # Argon2/scrypt salt

AES_GCM = "AES-256-GCM"
CHACHA = "ChaCha20-Poly1305"
CIPHERS = (AES_GCM, CHACHA)

ARGON2ID = "argon2id"
SCRYPT = "scrypt"

# OWASP "Password Storage" minimums (2024).  Vaults are created well above these;
# they exist so a hand-edited header cannot ask us to derive a key cheaply.
MIN_ARGON2 = {"memory_kib": 19 * 1024, "time_cost": 2, "parallelism": 1}
MIN_SCRYPT = {"n": 1 << 15, "r": 8, "p": 1}

# Defaults used when calibration is skipped.  Argon2id: 64 MiB, t=3, p=4 is the
# "second recommended option" from RFC 9106 with a larger memory cost.
DEFAULT_ARGON2 = {"memory_kib": 64 * 1024, "time_cost": 3, "parallelism": 4}
DEFAULT_SCRYPT = {"n": 1 << 17, "r": 8, "p": 1}


def random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes (``os.urandom``/``getrandom``)."""
    return os.urandom(n)


def wipe(buf: bytearray) -> None:
    """Best-effort zeroisation of a mutable buffer.

    Python cannot wipe ``str``/``bytes`` (immutable, possibly interned, and the
    GC may have copied them).  Key material is therefore kept in ``bytearray``
    and cleared here; see SECURITY.md for the honest limits of this.
    """
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


def equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison."""
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class KdfParams:
    """Serialisable description of how the KEK is derived from the password."""

    algo: str
    salt: bytes
    params: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.algo not in (ARGON2ID, SCRYPT):
            raise CryptoError(f"unsupported KDF: {self.algo!r}")
        if len(self.salt) < 16:
            raise CryptoError("KDF salt too short")
        required = ("memory_kib", "time_cost", "parallelism") if self.algo == ARGON2ID else ("n", "r", "p")
        missing = [k for k in required if k not in self.params]
        if missing:
            raise CryptoError(f"missing KDF parameters: {', '.join(missing)}")
        for key, value in self.params.items():  # every parameter, not just the required ones
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise CryptoError(f"KDF parameter {key} must be a positive integer")
        if self.algo == SCRYPT:
            n = self.params["n"]
            if n & (n - 1):
                raise CryptoError("scrypt n must be a power of two")

    def weaknesses(self) -> list[str]:
        """Human readable warnings if the stored cost is below the minimum."""
        minimums = MIN_ARGON2 if self.algo == ARGON2ID else MIN_SCRYPT
        return [
            f"{name}={self.params[name]} is below the recommended minimum {want}"
            for name, want in minimums.items()
            if self.params[name] < want
        ]

    def to_dict(self) -> dict[str, Any]:
        from .encoding import b64e

        return {"algo": self.algo, "salt": b64e(self.salt), **{k: int(v) for k, v in sorted(self.params.items())}}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "KdfParams":
        from .encoding import b64d

        if not isinstance(data, Mapping) or "algo" not in data or "salt" not in data:
            raise CryptoError("malformed KDF header")
        params = {k: v for k, v in data.items() if k not in ("algo", "salt")}
        return cls(algo=str(data["algo"]), salt=b64d(data["salt"]), params=params)

    def describe(self) -> str:
        if self.algo == ARGON2ID:
            return (
                f"Argon2id (m={self.params['memory_kib'] // 1024} MiB, "
                f"t={self.params['time_cost']}, p={self.params['parallelism']})"
            )
        return f"scrypt (N=2^{self.params['n'].bit_length() - 1}, r={self.params['r']}, p={self.params['p']})"


def argon2_available() -> bool:
    """True if an Argon2id implementation can be used."""
    return _argon2_backend() is not None


def _argon2_backend() -> Callable[[bytes, bytes, Mapping[str, int]], bytes] | None:
    """Return an Argon2id derive function from whichever backend is installed."""
    try:  # preferred: argon2-cffi (the reference implementation)
        from argon2.low_level import Type, hash_secret_raw

        def _cffi(password: bytes, salt: bytes, p: Mapping[str, int]) -> bytes:
            return hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=int(p["time_cost"]),
                memory_cost=int(p["memory_kib"]),
                parallelism=int(p["parallelism"]),
                hash_len=KEY_LEN,
                type=Type.ID,
            )

        return _cffi
    except Exception:  # pragma: no cover - depends on the installed environment
        pass

    try:  # cryptography >= 44 ships Argon2id as well
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        def _cryptography(password: bytes, salt: bytes, p: Mapping[str, int]) -> bytes:
            return Argon2id(
                salt=salt,
                length=KEY_LEN,
                iterations=int(p["time_cost"]),
                lanes=int(p["parallelism"]),
                memory_cost=int(p["memory_kib"]),
            ).derive(password)

        return _cryptography
    except Exception:  # pragma: no cover - depends on the installed environment
        return None


def default_kdf_params(prefer: str | None = None) -> KdfParams:
    """Default parameters for a new vault, Argon2id when available."""
    algo = prefer or (ARGON2ID if argon2_available() else SCRYPT)
    if algo == ARGON2ID and not argon2_available():
        raise CryptoError("Argon2id requested but no Argon2 backend is installed (pip install argon2-cffi)")
    params = dict(DEFAULT_ARGON2 if algo == ARGON2ID else DEFAULT_SCRYPT)
    return KdfParams(algo=algo, salt=random_bytes(KDF_SALT_LEN), params=params)


def derive_key(password: bytes, kdf: KdfParams) -> bytearray:
    """Derive the 256 bit key encryption key from the master password.

    Returns a ``bytearray`` so the caller can wipe it; never a ``bytes``.
    """
    if not isinstance(password, (bytes, bytearray)):
        raise CryptoError("password must be bytes")
    if kdf.algo == ARGON2ID:
        backend = _argon2_backend()
        if backend is None:
            raise CryptoError(
                "this vault uses Argon2id but no Argon2 backend is installed (pip install argon2-cffi)"
            )
        raw = backend(bytes(password), kdf.salt, kdf.params)
    else:
        n, r, p = int(kdf.params["n"]), int(kdf.params["r"]), int(kdf.params["p"])
        # hashlib refuses to allocate past maxmem, so state the real requirement.
        maxmem = 128 * n * r * (p + 1) + (1 << 20)
        raw = hashlib.scrypt(bytes(password), salt=kdf.salt, n=n, r=r, p=p, maxmem=maxmem, dklen=KEY_LEN)
    key = bytearray(raw)
    if isinstance(raw, bytearray):  # pragma: no cover - defensive
        wipe(raw)
    return key


def calibrate_kdf(target_seconds: float = 0.75, algo: str | None = None) -> KdfParams:
    """Pick KDF parameters that take roughly ``target_seconds`` on this machine.

    Slow is the point: the cost is paid once per unlock by the user and once per
    guess by an attacker.  Values are clamped so a fast machine cannot produce
    something unopenable on a slow phone, and a slow machine cannot fall below
    the OWASP minimum.
    """
    algo = algo or (ARGON2ID if argon2_available() else SCRYPT)
    probe = KdfParams(
        algo=algo,
        salt=random_bytes(KDF_SALT_LEN),
        params=dict(DEFAULT_ARGON2 if algo == ARGON2ID else DEFAULT_SCRYPT),
    )
    start = time.perf_counter()
    wipe(derive_key(b"calibration probe", probe))
    elapsed = max(time.perf_counter() - start, 1e-6)
    factor = target_seconds / elapsed

    if algo == ARGON2ID:
        memory = int(DEFAULT_ARGON2["memory_kib"] * factor)
        memory = max(MIN_ARGON2["memory_kib"], min(memory, 1024 * 1024))  # 19 MiB .. 1 GiB
        memory -= memory % 1024
        params = {**DEFAULT_ARGON2, "memory_kib": memory}
    else:
        exponent = (DEFAULT_SCRYPT["n"].bit_length() - 1) + int(round(_log2(factor)))
        exponent = max(15, min(exponent, 21))  # 32 MiB .. 2 GiB at r=8
        params = {**DEFAULT_SCRYPT, "n": 1 << exponent}
    return KdfParams(algo=algo, salt=random_bytes(KDF_SALT_LEN), params=params)


def _log2(value: float) -> float:
    import math

    return math.log2(value) if value > 0 else 0.0


# --------------------------------------------------------------------------- #
# Sub-keys and AEAD
# --------------------------------------------------------------------------- #

def subkey(parent: bytes, salt: bytes, info: bytes) -> bytearray:
    """HKDF-SHA256 sub-key derivation, one key per (salt, info) pair."""
    if len(parent) != KEY_LEN:
        raise CryptoError("parent key must be 32 bytes")
    derived = HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info).derive(bytes(parent))
    return bytearray(derived)


def _aead(cipher: str, key: bytes):
    if cipher == AES_GCM:
        return AESGCM(bytes(key))
    if cipher == CHACHA:
        return ChaCha20Poly1305(bytes(key))
    raise CryptoError(f"unsupported cipher: {cipher!r}")


def encrypt(cipher: str, key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt with a fresh random nonce.  Returns ``(nonce, ciphertext||tag)``."""
    nonce = random_bytes(NONCE_LEN)
    return nonce, _aead(cipher, key).encrypt(nonce, plaintext, aad)


def decrypt(cipher: str, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and verify.  Any tampering or a wrong key raises AuthenticationError."""
    if len(nonce) != NONCE_LEN:
        raise AuthenticationError("vault is corrupt (bad nonce length)")
    try:
        return _aead(cipher, key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise AuthenticationError("wrong master password, or the vault file was modified") from None
