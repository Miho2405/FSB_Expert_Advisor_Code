"""Terminal prompts for secrets.

``getpass`` reads from ``/dev/tty`` with echo disabled, so the master password
never lands in the terminal scrollback -- and never in the shell history, which
is why no command in the CLI accepts a password as an argument.
"""

from __future__ import annotations

import getpass
import sys

from .errors import PwmanError

MIN_MASTER_LENGTH = 10


def _to_buffer(text: str) -> bytearray:
    """Move a password into a wipeable buffer as early as possible."""
    return bytearray(text.encode("utf-8"))


def read_master(prompt: str = "Master password: ", *, confirm: bool = False,
                min_length: int = MIN_MASTER_LENGTH) -> bytearray:
    """Prompt for the master password, optionally twice."""
    if not sys.stdin.isatty():
        raise PwmanError("no terminal available for the password prompt; use --password-stdin")
    while True:
        first = getpass.getpass(prompt)
        if confirm and len(first) < min_length:
            print(f"too short - use at least {min_length} characters", file=sys.stderr)
            continue
        if not confirm:
            if not first:
                print("password must not be empty", file=sys.stderr)
                continue
            return _to_buffer(first)
        second = getpass.getpass("Repeat master password: ")
        if first != second:
            print("passwords did not match, try again", file=sys.stderr)
            continue
        return _to_buffer(first)


def read_password_stdin() -> bytearray:
    """Read the master password from the first line of stdin (for scripts)."""
    line = sys.stdin.readline()
    if not line:
        raise PwmanError("no password on stdin")
    return _to_buffer(line.rstrip("\n"))


def read_secret(prompt: str, *, confirm: bool = False) -> str:
    """Prompt for an entry secret (password, TOTP seed, ...)."""
    if not sys.stdin.isatty():
        raise PwmanError("no terminal available for the prompt")
    while True:
        value = getpass.getpass(prompt)
        if not confirm:
            return value
        if value == getpass.getpass("Repeat: "):
            return value
        print("values did not match, try again", file=sys.stderr)


def ask(prompt: str, default: str = "") -> str:
    """Plain, echoed prompt for non-secret fields."""
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return answer or default


def confirm_action(question: str, *, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return default
    suffix = "[y/N]" if not default else "[Y/n]"
    try:
        answer = input(f"{question} {suffix} ").strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in ("y", "yes", "j", "ja")
