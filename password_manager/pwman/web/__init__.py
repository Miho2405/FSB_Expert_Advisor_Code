"""Local web interface for pwman.

The vault is decrypted in *this* process and the browser is a thin client over
loopback.  Doing the crypto in the browser instead would mean shipping Argon2id
as a WebAssembly blob or falling back to PBKDF2, which browsers do offer -- both
would be a downgrade from what the CLI already does.

See ``server.py`` for the protections that make a localhost HTTP server an
acceptable place to put an unlocked vault.
"""

from __future__ import annotations

__all__ = ["serve", "WebApp"]


def __getattr__(name: str):  # keep `import pwman.web` cheap for the CLI
    if name == "serve":
        from .server import serve

        return serve
    if name == "WebApp":
        from .app import WebApp

        return WebApp
    raise AttributeError(name)
