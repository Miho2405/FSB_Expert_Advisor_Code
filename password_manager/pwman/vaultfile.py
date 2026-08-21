"""The encrypted container: file format, sealing/unsealing, atomic writes.

File layout (UTF-8 JSON, so a vault can be inspected and copied around safely)::

    {
      "magic":  "PWMANVLT",
      "format": 1,
      "cipher": "AES-256-GCM",
      "kdf":    {"algo": "argon2id", "salt": b64, "memory_kib": ..., ...},
      "wrap":   {"salt": b64, "nonce": b64, "ct": b64},   # the vault key, wrapped
      "body":   {"salt": b64, "nonce": b64, "ct": b64}    # the entries
    }

Everything outside the ciphertexts is public but *authenticated*: the header is
passed as associated data, so an attacker cannot flip the cipher, weaken the KDF
cost or swap a body from another vault without the AEAD tag failing.  The body's
associated data also covers the wrap block, which binds the two together.
"""

from __future__ import annotations

import json
import os
import stat
import struct
from dataclasses import dataclass
from typing import Any

from . import crypto
from .encoding import b64d, b64e, canonical_json
from .errors import AuthenticationError, PwmanError, VaultFormatError

MAGIC = "PWMANVLT"
FORMAT = 1

INFO_WRAP = b"pwman/v1/wrap"
INFO_BODY = b"pwman/v1/body"

PAD_BLOCK = 4096          # payload is padded to a multiple of this, hiding vault size
MAX_FILE_BYTES = 64 << 20  # refuse absurd inputs instead of allocating them


# --------------------------------------------------------------------------- #
# Padding
# --------------------------------------------------------------------------- #

def _pad(payload: bytes) -> bytes:
    """Length-prefix and pad, so the ciphertext size only reveals a 4 KiB bucket."""
    if len(payload) >= 1 << 32:
        raise PwmanError("vault payload too large")
    framed = struct.pack(">I", len(payload)) + payload
    remainder = len(framed) % PAD_BLOCK
    if remainder:
        framed += b"\x00" * (PAD_BLOCK - remainder)
    return framed


def _unpad(framed: bytes) -> bytes:
    if len(framed) < 4:
        raise VaultFormatError("vault payload is truncated")
    (length,) = struct.unpack(">I", framed[:4])
    if length > len(framed) - 4:
        raise VaultFormatError("vault payload is truncated")
    return framed[4 : 4 + length]


# --------------------------------------------------------------------------- #
# Session keys
# --------------------------------------------------------------------------- #

@dataclass
class SealedContext:
    """Live key material for one unlocked vault.

    Holds the KEK (derived from the master password) and the vault key, so
    repeated saves do not have to re-run the KDF.  Call :meth:`close` -- or use
    it as a context manager -- to wipe both.
    """

    kdf: crypto.KdfParams
    cipher: str
    _kek: bytearray
    _vault_key: bytearray

    def __enter__(self) -> "SealedContext":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        crypto.wipe(self._kek)
        crypto.wipe(self._vault_key)

    # -- sealing ---------------------------------------------------------- #

    def seal(self, payload: bytes) -> bytes:
        """Encrypt ``payload`` into a complete vault file image."""
        header = {"magic": MAGIC, "format": FORMAT, "cipher": self.cipher, "kdf": self.kdf.to_dict()}
        header_bytes = canonical_json(header)

        wrap_salt = crypto.random_bytes(crypto.SALT_LEN)
        wrap_key = crypto.subkey(self._kek, wrap_salt, INFO_WRAP)
        try:
            wrap_nonce, wrap_ct = crypto.encrypt(
                self.cipher, wrap_key, bytes(self._vault_key), INFO_WRAP + b"|" + header_bytes
            )
        finally:
            crypto.wipe(wrap_key)
        wrap = {"salt": b64e(wrap_salt), "nonce": b64e(wrap_nonce), "ct": b64e(wrap_ct)}

        body_salt = crypto.random_bytes(crypto.SALT_LEN)
        body_key = crypto.subkey(self._vault_key, body_salt, INFO_BODY)
        try:
            body_aad = INFO_BODY + b"|" + header_bytes + b"|" + canonical_json(wrap)
            body_nonce, body_ct = crypto.encrypt(self.cipher, body_key, _pad(payload), body_aad)
        finally:
            crypto.wipe(body_key)
        body = {"salt": b64e(body_salt), "nonce": b64e(body_nonce), "ct": b64e(body_ct)}

        document = {**header, "wrap": wrap, "body": body}
        return json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    def rekey(self, new_password: bytes, kdf: crypto.KdfParams | None = None) -> "SealedContext":
        """Return a context for the same vault key under a new master password.

        The vault key does not change, so this is a re-wrap: no entry is
        re-encrypted with different content, only the outer layer changes.
        """
        params = kdf or crypto.default_kdf_params(self.kdf.algo)
        kek = crypto.derive_key(new_password, params)
        return SealedContext(kdf=params, cipher=self.cipher, _kek=kek, _vault_key=bytearray(self._vault_key))


def create(password: bytes, *, kdf: crypto.KdfParams | None = None, cipher: str = crypto.AES_GCM) -> SealedContext:
    """Set up key material for a brand new vault."""
    if cipher not in crypto.CIPHERS:
        raise PwmanError(f"unsupported cipher: {cipher!r}")
    params = kdf or crypto.default_kdf_params()
    return SealedContext(
        kdf=params,
        cipher=cipher,
        _kek=crypto.derive_key(password, params),
        _vault_key=bytearray(crypto.random_bytes(crypto.KEY_LEN)),
    )


def unseal(blob: bytes, password: bytes) -> tuple[SealedContext, bytes, list[str]]:
    """Open a vault image.

    Returns ``(context, payload, warnings)``.  Raises
    :class:`~pwman.errors.AuthenticationError` for a wrong password *and* for a
    modified file -- the caller cannot tell the two apart, and neither can an
    attacker probing with a corrupted file.
    """
    document = _parse(blob)
    header = {
        "magic": document["magic"],
        "format": document["format"],
        "cipher": document["cipher"],
        "kdf": document["kdf"],
    }
    header_bytes = canonical_json(header)
    kdf = crypto.KdfParams.from_dict(document["kdf"])
    cipher = document["cipher"]
    warnings = [f"weak key derivation: {w}" for w in kdf.weaknesses()]

    wrap, body = document["wrap"], document["body"]
    kek = crypto.derive_key(password, kdf)
    wrap_key = None
    try:
        wrap_key = crypto.subkey(kek, b64d(wrap["salt"]), INFO_WRAP)
        vault_key = bytearray(
            crypto.decrypt(
                cipher, wrap_key, b64d(wrap["nonce"]), b64d(wrap["ct"]), INFO_WRAP + b"|" + header_bytes
            )
        )
    except AuthenticationError:
        crypto.wipe(kek)
        raise
    finally:
        if wrap_key is not None:
            crypto.wipe(wrap_key)

    body_key = crypto.subkey(vault_key, b64d(body["salt"]), INFO_BODY)
    try:
        body_aad = INFO_BODY + b"|" + header_bytes + b"|" + canonical_json(wrap)
        payload = _unpad(crypto.decrypt(cipher, body_key, b64d(body["nonce"]), b64d(body["ct"]), body_aad))
    except AuthenticationError:
        crypto.wipe(kek)
        crypto.wipe(vault_key)
        raise
    finally:
        crypto.wipe(body_key)

    if len(vault_key) != crypto.KEY_LEN:
        crypto.wipe(kek)
        crypto.wipe(vault_key)
        raise VaultFormatError("vault key has the wrong size")

    return SealedContext(kdf=kdf, cipher=cipher, _kek=kek, _vault_key=vault_key), payload, warnings


def _parse(blob: bytes) -> dict[str, Any]:
    if len(blob) > MAX_FILE_BYTES:
        raise VaultFormatError("file is too large to be a vault")
    try:
        document = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VaultFormatError("not a pwman vault (unreadable file)") from None
    if not isinstance(document, dict) or document.get("magic") != MAGIC:
        raise VaultFormatError("not a pwman vault (missing magic)")
    if document.get("format") != FORMAT:
        raise VaultFormatError(
            f"unsupported vault format {document.get('format')!r}; this build understands format {FORMAT}"
        )
    if document.get("cipher") not in crypto.CIPHERS:
        raise VaultFormatError(f"unsupported cipher {document.get('cipher')!r}")
    for section in ("kdf", "wrap", "body"):
        if not isinstance(document.get(section), dict):
            raise VaultFormatError(f"vault header is missing the {section!r} section")
    for section in ("wrap", "body"):
        for key in ("salt", "nonce", "ct"):
            if key not in document[section]:
                raise VaultFormatError(f"vault header is missing {section}.{key}")
    # Only the known fields are authenticated, so anything else must not be there:
    # unknown keys would ride along unprotected and could hide smuggled data.
    unexpected = set(document) - {"magic", "format", "cipher", "kdf", "wrap", "body"}
    if unexpected:
        raise VaultFormatError(f"vault header has unexpected fields: {', '.join(sorted(unexpected))}")
    return document


def is_vault(blob: bytes) -> bool:
    try:
        _parse(blob)
        return True
    except VaultFormatError:
        return False


# --------------------------------------------------------------------------- #
# File I/O
# --------------------------------------------------------------------------- #

def read(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        raise PwmanError(f"no vault at {path} (run `pwman init` first)") from None
    except IsADirectoryError:
        raise PwmanError(f"{path} is a directory") from None
    except PermissionError:
        raise PwmanError(f"no permission to read {path}") from None


def write_atomic(path: str, data: bytes, *, backup: bool = True) -> None:
    """Write ``data`` to ``path`` without ever leaving a half-written vault.

    The new image goes to a 0600 temp file in the same directory, is flushed to
    disk, and only then replaces the old file with ``os.replace`` (atomic on
    POSIX and on Windows).  The directory entry is fsynced too, so a crash right
    after the rename cannot resurrect the old file on ext4/xfs.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)

    if backup and os.path.exists(path):
        with open(path, "rb") as handle:
            previous = handle.read()
        _write_new_file(path + ".bak", previous)

    temp_path = f"{path}.tmp.{os.getpid()}"
    _write_new_file(temp_path, data)
    os.replace(temp_path, path)
    _fsync_dir(directory)


def _write_new_file(path: str, data: bytes) -> None:
    """Create/replace ``path`` with mode 0600, fsynced."""
    if os.path.exists(path):
        os.unlink(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover - e.g. Windows
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - some filesystems refuse
        pass
    finally:
        os.close(fd)


def permission_warnings(path: str) -> list[str]:
    """Warn if the vault (or its directory) is readable by other local users."""
    warnings: list[str] = []
    try:
        info = os.stat(path)
    except OSError:
        return warnings
    if not stat.S_ISREG(info.st_mode):
        warnings.append(f"{path} is not a regular file")
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.append(f"{path} is accessible to other users (mode {stat.S_IMODE(info.st_mode):04o}); chmod 600 it")
    return warnings
