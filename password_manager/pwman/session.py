"""Ties the encrypted file, the key material and the decrypted vault together.

A Session is the only object that holds plaintext entries.  Everything that
opens one is expected to close it again -- ``with Session.open(...) as session``
-- so key material is wiped as soon as the command is done.
"""

from __future__ import annotations

import os
from typing import Any

from . import crypto, vaultfile
from .errors import PwmanError
from .vault import Vault

ENV_VAULT = "PWMAN_VAULT"
DEFAULT_NAME = "vault.pmv"


def default_vault_path() -> str:
    """``$PWMAN_VAULT``, else ``$XDG_DATA_HOME/pwman/vault.pmv``, else ``~/.local/share/...``."""
    override = os.environ.get(ENV_VAULT)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "pwman", DEFAULT_NAME)


def _file_stamp(path: str) -> tuple[int, int, int] | None:
    """Cheap identity of a file: inode, size and modification time."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_ino, info.st_size, info.st_mtime_ns)


class Session:
    """An unlocked vault plus the keys needed to save it again."""

    def __init__(self, path: str, context: vaultfile.SealedContext, vault: Vault,
                 warnings: list[str] | None = None) -> None:
        self.path = path
        self.context = context
        self.vault = vault
        self.warnings = list(warnings or [])
        self._closed = False
        self._stamp = _file_stamp(path)

    # -- lifecycle ---------------------------------------------------------- #

    @classmethod
    def create(cls, path: str, password: bytes, *, kdf: crypto.KdfParams | None = None,
               cipher: str = crypto.AES_GCM) -> "Session":
        if os.path.exists(path):
            raise PwmanError(f"{path} already exists - refusing to overwrite an existing vault")
        context = vaultfile.create(password, kdf=kdf, cipher=cipher)
        session = cls(path, context, Vault())
        session.save(backup=False)
        return session

    @classmethod
    def open(cls, path: str, password: bytes) -> "Session":
        blob = vaultfile.read(path)
        context, payload, warnings = vaultfile.unseal(blob, password)
        try:
            vault = Vault.from_payload(payload)
        except Exception:
            context.close()
            raise
        return cls(path, context, vault, warnings + vaultfile.permission_warnings(path))

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self.context.close()
            self._closed = True

    # -- persistence -------------------------------------------------------- #

    def save(self, *, backup: bool = True) -> None:
        """Encrypt and write the vault, refusing to overwrite someone else's work.

        pwman does not lock the file for the whole session -- that would leave a
        stale lock behind after a crash.  Instead the file's identity is checked
        right before writing, so a parallel session's changes are never silently
        lost; the user is told to re-run instead.
        """
        if self._closed:
            raise PwmanError("session is closed")
        current = _file_stamp(self.path)
        if current is not None and self._stamp is not None and current != self._stamp:
            raise PwmanError(
                f"{self.path} changed on disk since it was unlocked - "
                "another pwman session may be running; re-run the command"
            )
        image = self.context.seal(self.vault.to_payload())
        vaultfile.write_atomic(self.path, image, backup=backup)
        self._stamp = _file_stamp(self.path)

    def change_master(self, new_password: bytes, *, kdf: crypto.KdfParams | None = None) -> None:
        """Re-wrap the vault key under a new master password and persist it."""
        new_context = self.context.rekey(new_password, kdf=kdf)
        old_context, self.context = self.context, new_context
        try:
            self.save()
        except Exception:
            self.context = old_context
            new_context.close()
            raise
        old_context.close()

    # -- reporting ---------------------------------------------------------- #

    def info(self) -> dict[str, Any]:
        stat = os.stat(self.path) if os.path.exists(self.path) else None
        return {
            "path": self.path,
            "entries": len(self.vault),
            "tags": len(self.vault.tags()),
            "cipher": self.context.cipher,
            "kdf": self.context.kdf.describe(),
            "format": vaultfile.FORMAT,
            "size_bytes": stat.st_size if stat else 0,
            "mode": f"{stat.st_mode & 0o777:04o}" if stat else "-",
            "warnings": self.warnings,
        }
