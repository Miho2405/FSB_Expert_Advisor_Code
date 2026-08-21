"""Clipboard access with an automatic wipe.

Secrets are handed to the helper on **stdin**, never as a command line argument:
argv is world-readable in ``/proc`` on Linux and shows up in ``ps`` output.

The clipboard is a shared, unauthenticated channel that any process on the
machine can read, which is why the copy is cleared again after a timeout -- and
only if the clipboard still holds our value, so a wipe never destroys something
the user copied in the meantime.
"""

from __future__ import annotations

import hmac
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass

from .errors import ClipboardError

DEFAULT_TIMEOUT = 20


@dataclass(frozen=True)
class Backend:
    name: str
    copy_cmd: tuple[str, ...]
    paste_cmd: tuple[str, ...] | None


BACKENDS = (
    Backend("wl-copy", ("wl-copy",), ("wl-paste", "--no-newline")),
    Backend("xclip", ("xclip", "-selection", "clipboard"), ("xclip", "-selection", "clipboard", "-o")),
    Backend("xsel", ("xsel", "--clipboard", "--input"), ("xsel", "--clipboard", "--output")),
    Backend("pbcopy", ("pbcopy",), ("pbpaste",)),
    Backend("termux", ("termux-clipboard-set",), ("termux-clipboard-get",)),
    Backend("clip.exe", ("clip.exe",), None),
)


def find_backend() -> Backend | None:
    for backend in BACKENDS:
        if shutil.which(backend.copy_cmd[0]):
            return backend
    return None


def available() -> bool:
    return find_backend() is not None


def copy(text: str, backend: Backend | None = None) -> Backend:
    """Put ``text`` on the clipboard.  Returns the backend that was used."""
    backend = backend or find_backend()
    if backend is None:
        raise ClipboardError(
            "no clipboard tool found (install wl-clipboard, xclip or xsel), use --show to print instead"
        )
    try:
        subprocess.run(
            list(backend.copy_cmd),
            input=text.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"clipboard backend {backend.name} failed: {exc}") from None
    return backend


def paste(backend: Backend | None = None) -> str | None:
    """Read the clipboard back, or ``None`` if this backend cannot read."""
    backend = backend or find_backend()
    if backend is None or backend.paste_cmd is None:
        return None
    try:
        result = subprocess.run(
            list(backend.paste_cmd), capture_output=True, check=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.decode("utf-8", errors="replace")


def clear(previous: str, backend: Backend | None = None) -> bool:
    """Clear the clipboard, but only while it still contains ``previous``.

    Returns True if it cleared, False if the user copied something else since.
    """
    backend = backend or find_backend()
    if backend is None:
        return False
    current = paste(backend)
    if current is not None and not hmac.compare_digest(current.strip(), previous.strip()):
        return False
    try:
        copy("", backend)
    except ClipboardError:  # pragma: no cover - backend disappeared mid-run
        return False
    return True


def copy_and_clear(text: str, timeout: int = DEFAULT_TIMEOUT, *, announce=None) -> None:
    """Copy, wait ``timeout`` seconds, then wipe.  Ctrl-C wipes immediately.

    Blocking is intentional: a detached background wiper would keep the secret
    alive in a second process, and would survive the user's session ending.
    """
    backend = copy(text)
    if announce:
        announce(backend)
    try:
        deadline = time.monotonic() + max(timeout, 0)
        while time.monotonic() < deadline:
            time.sleep(min(0.25, max(deadline - time.monotonic(), 0)))
    except KeyboardInterrupt:
        pass
    finally:
        cleared = clear(text, backend)
        if not cleared and sys.stderr.isatty():
            print("clipboard changed meanwhile - left it alone", file=sys.stderr)
