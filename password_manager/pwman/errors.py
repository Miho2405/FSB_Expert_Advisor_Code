"""Exception hierarchy for pwman.

All errors that can reach the user are subclasses of :class:`PwmanError` so the
CLI can print a short message instead of a traceback.  Tracebacks are avoided on
purpose: they can carry fragments of secrets in local variables.
"""

from __future__ import annotations


class PwmanError(Exception):
    """Base class for all expected pwman failures."""


class CryptoError(PwmanError):
    """Raised when a cryptographic operation fails."""


class AuthenticationError(CryptoError):
    """Wrong master password, or the vault file was tampered with.

    The two cases are deliberately indistinguishable: an attacker who can modify
    the file must not learn whether a guessed password was correct.
    """


class VaultFormatError(PwmanError):
    """The file is not a pwman vault, or uses an unsupported format version."""


class VaultError(PwmanError):
    """Vault content level error (duplicate name, empty name, ambiguous match)."""


class EntryNotFound(VaultError):
    """No entry matches the given name or id."""


class ClipboardError(PwmanError):
    """No usable clipboard backend, or the backend failed."""
