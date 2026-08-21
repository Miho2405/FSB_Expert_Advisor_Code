"""pwman - a small, offline, end-to-end encrypted password manager.

The vault is a single authenticated-encrypted file.  Secrets never leave the
machine: there is no sync, no telemetry and no network access at all unless the
user explicitly asks for the (k-anonymous) breach check.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
