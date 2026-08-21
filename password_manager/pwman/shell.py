"""Interactive session: unlock once, work, auto-lock when idle.

Unlocking is deliberately expensive (that is the whole point of the KDF), so
typing the master password for every single lookup pushes people towards weak
master passwords or shell aliases that store it.  The shell keeps the vault open
in one process instead -- with an idle timeout, because an unattended unlocked
terminal is exactly the threat a password manager exists to contain.

There is no background agent and no key material on disk: when this process
exits, the keys are wiped and the clipboard is cleared.
"""

from __future__ import annotations

import shlex
import sys
from typing import Any

from . import clipboard, generator, strength
from .errors import PwmanError
from .session import Session
from .vault import Entry

PROMPT = "pwman> "

HELP = """commands:
  list [query]            list entries (add --long for tags and strength)
  show NAME               show an entry with the password masked
  get NAME [--show]       copy the password to the clipboard (--show prints it)
  totp NAME               show the current one-time code
  add NAME [--generate]   add an entry
  set NAME FIELD VALUE    change username/url/notes/tags
  passwd NAME [--generate] change an entry's password
  rm NAME                 delete an entry
  gen [length]            generate a password (no vault change)
  audit                   report weak, reused and stale passwords
  help                    this text
  lock | quit | exit      wipe the keys and leave"""


def _read_line(timeout: int) -> str | None:
    """Read one command, or return None when the idle timeout expires."""
    sys.stdout.write(PROMPT)
    sys.stdout.flush()
    if timeout > 0 and sys.stdin.isatty():
        try:
            import select

            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None
        except (ImportError, OSError, ValueError):  # pragma: no cover - non-POSIX stdin
            pass
    line = sys.stdin.readline()
    if not line:  # EOF
        raise EOFError
    return line.strip()


def run_shell(session: Session, out: Any, timeout: int = 300) -> int:
    """Run the interactive loop until the user leaves or the vault auto-locks."""
    out.say(out.paint(f"{len(session.vault)} entries unlocked - `help` for commands, "
                      f"auto-lock after {timeout}s idle", "grey"))
    copied: str | None = None
    try:
        while True:
            try:
                line = _read_line(timeout)
            except EOFError:
                out.say("")
                break
            except KeyboardInterrupt:
                out.say("")
                continue
            if line is None:
                out.say(out.paint(f"\nidle for {timeout}s - locking", "yellow"))
                break
            if not line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                out.error(f"cannot parse: {exc}")
                continue
            command, arguments = parts[0].lower(), parts[1:]
            if command in ("quit", "exit", "lock", "q"):
                break
            try:
                result = _dispatch(session, out, command, arguments)
            except PwmanError as exc:
                out.error(str(exc))
                continue
            except KeyboardInterrupt:
                out.say("")
                continue
            if isinstance(result, str):
                copied = result
    finally:
        if copied:
            clipboard.clear(copied)
        session.close()
        out.say(out.paint("locked", "grey"))
    return 0


def _dispatch(session: Session, out: Any, command: str, arguments: list[str]) -> str | None:
    """Run one shell command.  Returns a value that was put on the clipboard, if any."""
    vault = session.vault

    if command in ("help", "?"):
        out.say(HELP)
        return None

    if command in ("list", "ls"):
        long = "--long" in arguments
        query = " ".join(a for a in arguments if not a.startswith("--"))
        entries = vault.search(query)
        if not entries:
            out.say("no entries")
            return None
        width = max(len(e.name) for e in entries)
        for entry in entries:
            line = f"{entry.name.ljust(width)}  {out.paint(entry.username or '-', 'grey')}"
            if long:
                bits = strength.estimate(entry.password).bits if entry.password else 0
                line += f"  {out.paint(','.join(entry.tags) or '-', 'blue')}  {out.paint(f'{bits:.0f} bits', 'grey')}"
            out.say(line)
        return None

    if command == "show":
        entry = vault.get(_need(arguments, "show NAME"))
        for label, value in (("name", entry.name), ("username", entry.username), ("url", entry.url),
                             ("tags", ", ".join(entry.tags)), ("password", "*" * 12 if entry.password else ""),
                             ("totp", "configured" if entry.totp_secret else ""), ("notes", entry.notes),
                             ("updated", entry.updated_at)):
            if value:
                out.say(f"{out.paint(label.rjust(8), 'grey')}  {value}")
        return None

    if command == "get":
        entry = vault.get(_need([a for a in arguments if not a.startswith("--")], "get NAME"))
        if not entry.password:
            raise PwmanError(f"{entry.name} has no password")
        if "--show" in arguments:
            out.say(entry.password)
            return None
        clipboard.copy(entry.password)
        out.say(out.paint("copied - the clipboard is wiped when this shell exits", "green"))
        return entry.password

    if command == "totp":
        from . import totp as totp_module

        entry = vault.get(_need(arguments, "totp NAME"))
        if not entry.totp_secret:
            raise PwmanError(f"{entry.name} has no TOTP secret")
        code, remaining = totp_module.totp(totp_module.TotpConfig(entry.totp_secret))
        out.say(f"{code}  {out.paint(f'({remaining}s left)', 'grey')}")
        return None

    if command == "add":
        name = _need([a for a in arguments if not a.startswith("--")], "add NAME")
        password = generator.generate_password() if "--generate" in arguments else _prompt_secret()
        entry = vault.add(Entry(name=name, password=password))
        session.save()
        estimate = strength.estimate(password)
        out.say(out.paint(f"added {entry.name} ({estimate.bits:.0f} bits)", "green"))
        if "--generate" in arguments:
            clipboard.copy(password)
            out.say(out.paint("copied to clipboard", "green"))
            return password
        return None

    if command == "set":
        if len(arguments) < 3:
            raise PwmanError("usage: set NAME FIELD VALUE")
        entry = vault.get(arguments[0])
        field = arguments[1].lower()
        value: Any = " ".join(arguments[2:])
        if field not in ("username", "url", "notes", "tags", "name"):
            raise PwmanError("field must be one of: username, url, notes, tags, name")
        if field == "tags":
            value = value.replace(",", " ").split()
        vault.update(entry, **{field: value})
        session.save()
        out.say(out.paint(f"updated {entry.name}", "green"))
        return None

    if command == "passwd":
        entry = vault.get(_need([a for a in arguments if not a.startswith("--")], "passwd NAME"))
        password = generator.generate_password() if "--generate" in arguments else _prompt_secret()
        vault.update(entry, password=password)
        session.save()
        out.say(out.paint(f"changed password for {entry.name}", "green"))
        if "--generate" in arguments:
            clipboard.copy(password)
            out.say(out.paint("copied to clipboard", "green"))
            return password
        return None

    if command == "rm":
        entry = vault.get(_need(arguments, "rm NAME"))
        vault.delete(entry)
        session.save()
        out.say(out.paint(f"deleted {entry.name}", "green"))
        return None

    if command == "gen":
        length = int(arguments[0]) if arguments and arguments[0].isdigit() else generator.DEFAULT_LENGTH
        policy = generator.Policy(length=length)
        password = generator.generate_password(policy)
        out.say(f"{password}  {out.paint(f'({generator.password_entropy_bits(policy):.0f} bits)', 'grey')}")
        return None

    if command == "audit":
        findings = strength.audit(vault)
        if not findings:
            out.say(out.paint("no issues found", "green"))
            return None
        for finding in findings:
            out.say(f"{finding.severity.ljust(8)} {finding.entry}: {finding.kind} - {finding.detail}")
        return None

    if command == "save":
        session.save()
        out.say(out.paint("saved", "green"))
        return None

    raise PwmanError(f"unknown command {command!r} - try `help`")


def _need(arguments: list[str], usage: str) -> str:
    if not arguments:
        raise PwmanError(f"usage: {usage}")
    return arguments[0]


def _prompt_secret() -> str:
    from .prompt import read_secret

    value = read_secret("Password (empty to generate): ")
    return value or generator.generate_password()
