"""Command line interface.

Two rules shape this module:

* No secret is ever accepted as a command line argument -- argv is visible to
  every process on the machine and lands in the shell history.  Secrets come
  from a terminal prompt, or explicitly from stdin for scripting.
* No secret is ever printed unless the user asked for it with ``--show``; the
  default path for a password is the clipboard, which is wiped afterwards.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Callable, Sequence

from . import __version__, clipboard, crypto, generator, prompt, pwned, strength
from .errors import AuthenticationError, PwmanError
from .session import Session, default_vault_path
from .vault import Entry

OK = 0
ERROR = 1
USAGE = 2
AUTH = 3
FINDINGS = 4

FIELDS = ("password", "username", "url", "notes", "totp")


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

class Out:
    """Tiny stdout/stderr wrapper with optional colour."""

    COLORS = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "grey": "90", "bold": "1"}

    def __init__(self, quiet: bool = False, color: bool | None = None) -> None:
        self.quiet = quiet
        if color is None:
            color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"
        self.color = color

    def paint(self, text: str, style: str) -> str:
        if not self.color or style not in self.COLORS:
            return text
        return f"\033[{self.COLORS[style]}m{text}\033[0m"

    def say(self, text: str = "") -> None:
        if not self.quiet:
            print(text)

    def data(self, text: str) -> None:
        """Machine-readable output: always printed, even with --quiet."""
        print(text)

    def warn(self, text: str) -> None:
        print(self.paint(f"warning: {text}", "yellow"), file=sys.stderr)

    def error(self, text: str) -> None:
        print(self.paint(f"error: {text}", "red"), file=sys.stderr)


def _bits(value: float) -> str:
    return f"{value:.0f} bits"


# --------------------------------------------------------------------------- #
# Shared plumbing
# --------------------------------------------------------------------------- #

def _master_password(args: argparse.Namespace, *, confirm: bool = False) -> bytearray:
    if getattr(args, "password_stdin", False):
        return prompt.read_password_stdin()
    return prompt.read_master(confirm=confirm)


def _open_session(args: argparse.Namespace, out: Out) -> Session:
    password = _master_password(args)
    try:
        session = Session.open(args.vault, bytes(password))
    finally:
        crypto.wipe(password)
    for warning in session.warnings:
        out.warn(warning)
    return session


def _entry_password(args: argparse.Namespace, *, required: bool) -> str | None:
    """Password for an entry: generated, from stdin, or prompted."""
    if getattr(args, "generate", False):
        return generator.generate_password(_policy_from_args(args))
    if getattr(args, "passphrase", False):
        return generator.generate_passphrase(args.words, separator=args.separator)
    if getattr(args, "secret_stdin", False):
        line = sys.stdin.readline()
        if not line:
            raise PwmanError("no entry password on stdin")
        return line.rstrip("\n")
    if not sys.stdin.isatty():
        if required:
            raise PwmanError("no terminal for the password prompt; use --generate or --secret-stdin")
        return None
    value = prompt.read_secret("Entry password (empty to skip): ", confirm=False)
    return value or (None if not required else "")


def _policy_from_args(args: argparse.Namespace) -> generator.Policy:
    return generator.Policy(
        length=getattr(args, "length", generator.DEFAULT_LENGTH),
        lower=not getattr(args, "no_lower", False),
        upper=not getattr(args, "no_upper", False),
        digits=not getattr(args, "no_digits", False),
        symbols=not getattr(args, "no_symbols", False),
        avoid_ambiguous=getattr(args, "readable", False),
    )


def _deliver_secret(value: str, args: argparse.Namespace, out: Out, *, what: str, soft: bool = False) -> int:
    """Show, copy or refuse to leak a secret, according to the flags.

    ``soft`` marks calls where delivery is a convenience (the entry is already
    stored): a missing clipboard is then a hint, not a failed command.
    """
    if args.show:
        out.data(value)
        return OK
    if not clipboard.available():
        if soft:
            out.warn("no clipboard tool available - read it back with `pwman get NAME --show`")
            return OK
        out.error("no clipboard tool available - re-run with --show to print the value instead")
        return ERROR
    clipboard.copy_and_clear(
        value,
        args.timeout,
        announce=lambda backend: out.say(
            out.paint(f"{what} copied to clipboard ({backend.name}); clearing in {args.timeout}s", "green")
        ),
    )
    out.say("clipboard cleared")
    return OK


def _print_entry(entry: Entry, out: Out, *, show: bool) -> None:
    strength_info = strength.estimate(entry.password) if entry.password else None
    rows = [
        ("name", entry.name),
        ("username", entry.username),
        ("url", entry.url),
        ("tags", ", ".join(entry.tags)),
        ("password", entry.password if show else ("*" * 12 if entry.password else "")),
        ("strength", f"{_bits(strength_info.bits)} ({strength_info.label})" if strength_info else ""),
        ("totp", ("configured" if entry.totp_secret else "")),
        ("updated", entry.updated_at),
        ("password age", entry.password_changed_at),
        ("notes", entry.notes),
    ]
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        if value:
            out.say(f"{out.paint(label.rjust(width), 'grey')}  {value}")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_init(args: argparse.Namespace, out: Out) -> int:
    if os.path.exists(args.vault):
        out.error(f"{args.vault} already exists")
        return ERROR
    out.say("Choose a master password.  It is the only thing protecting the vault:")
    out.say(out.paint("  it cannot be recovered, reset, or brute-forced back for you.", "grey"))
    password = _master_password(args, confirm=True)
    try:
        estimate = strength.estimate(bytes(password).decode("utf-8", errors="replace"))
        if estimate.bits < 60:
            out.warn(
                f"that master password is {estimate.label} ({_bits(estimate.bits)}); "
                f"a passphrase like `{generator.generate_passphrase(5)}` would be far stronger"
            )
            if sys.stdin.isatty() and not prompt.confirm_action("Use it anyway?"):
                return ERROR
        if args.kdf_seconds > 0:
            out.say(f"calibrating key derivation for ~{args.kdf_seconds:g}s ...")
            kdf = crypto.calibrate_kdf(args.kdf_seconds, algo=args.kdf)
        else:
            kdf = crypto.default_kdf_params(args.kdf)
        session = Session.create(args.vault, bytes(password), kdf=kdf, cipher=args.cipher)
    finally:
        crypto.wipe(password)
    with session:
        out.say(out.paint(f"created {session.path}", "green"))
        out.say(f"  cipher: {session.context.cipher}")
        out.say(f"  key derivation: {session.context.kdf.describe()}")
    return OK


def cmd_add(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        if session.vault.has(args.name):
            out.error(f"an entry named {args.name!r} already exists")
            return ERROR
        interactive = sys.stdin.isatty() and not (args.generate or args.passphrase or args.secret_stdin)
        username = args.username if args.username is not None else (prompt.ask("Username") if interactive else "")
        url = args.url if args.url is not None else (prompt.ask("URL") if interactive else "")
        notes = args.notes or ""
        password = _entry_password(args, required=True) or ""

        entry = Entry(
            name=args.name,
            username=username,
            url=url,
            notes=notes,
            tags=sorted({t.strip() for t in (args.tags or []) if t.strip()}, key=str.casefold),
            password=password,
        )
        if args.totp:
            from . import totp as totp_module

            config = totp_module.parse_secret_input(args.totp)
            entry.totp_secret = config.secret
        session.vault.add(entry)
        session.save()
        out.say(out.paint(f"added {entry.name}", "green"))
        if password:
            estimate = strength.estimate(password)
            out.say(f"  strength: {_bits(estimate.bits)} ({estimate.label})")
            for warning in estimate.warnings[:3]:
                out.warn(warning)
        if args.generate or args.passphrase:
            return _deliver_secret(password, args, out, what="password", soft=True)
    return OK


def cmd_get(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        entry = session.vault.get(args.name)
        if args.field == "totp":
            return _show_totp(entry, args, out)
        value = {"password": entry.password, "username": entry.username, "url": entry.url,
                 "notes": entry.notes}[args.field]
        if not value:
            out.error(f"{entry.name} has no {args.field}")
            return ERROR
        if args.field != "password":
            out.data(value)
            return OK
        if not args.show and not args.copy:
            _print_entry(entry, out, show=False)
            out.say("")
        return _deliver_secret(value, args, out, what="password")


def _show_totp(entry: Entry, args: argparse.Namespace, out: Out) -> int:
    from . import totp as totp_module

    if not entry.totp_secret:
        out.error(f"{entry.name} has no TOTP secret")
        return ERROR
    code, remaining = totp_module.totp(totp_module.TotpConfig(entry.totp_secret))
    if args.show or not args.copy:
        out.data(code)
        out.say(out.paint(f"valid for {remaining}s", "grey"))
        return OK
    return _deliver_secret(code, args, out, what="TOTP code")


def cmd_list(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        entries = session.vault.search(args.query or "", tag=args.tag or "")
        if args.json:
            out.data(json.dumps([e.redacted() for e in entries], indent=2))
            return OK
        if not entries:
            out.say("no entries")
            return OK
        width = max(len(e.name) for e in entries)
        for entry in entries:
            line = f"{entry.name.ljust(width)}  {out.paint(entry.username or '-', 'grey')}"
            if args.long:
                tags = ",".join(entry.tags)
                bits = strength.estimate(entry.password).bits if entry.password else 0
                line += f"  {out.paint(tags or '-', 'blue')}  {out.paint(_bits(bits), 'grey')}"
            out.say(line)
        out.say(out.paint(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}", "grey"))
    return OK


def cmd_edit(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        entry = session.vault.get(args.name)
        changes: dict[str, Any] = {}
        for field in ("username", "url", "notes"):
            value = getattr(args, field)
            if value is not None:
                changes[field] = value
        if args.rename:
            changes["name"] = args.rename
        if args.tags is not None:
            changes["tags"] = args.tags
        if args.totp is not None:
            from . import totp as totp_module

            changes["totp_secret"] = totp_module.parse_secret_input(args.totp).secret if args.totp else ""
        new_password = None
        if args.generate or args.passphrase or args.secret_stdin or args.password:
            new_password = _entry_password(args, required=True)
            if new_password is not None:
                changes["password"] = new_password
        if not changes:
            out.error("nothing to change - pass --username/--url/--password/--generate/...")
            return USAGE
        session.vault.update(entry, **changes)
        session.save()
        out.say(out.paint(f"updated {entry.name}", "green"))
        if new_password:
            estimate = strength.estimate(new_password)
            out.say(f"  strength: {_bits(estimate.bits)} ({estimate.label})")
            if args.generate or args.passphrase:
                return _deliver_secret(new_password, args, out, what="password", soft=True)
    return OK


def cmd_rm(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        entry = session.vault.get(args.name)
        if not args.force and not prompt.confirm_action(f"Delete {entry.name!r}?"):
            out.say("cancelled")
            return OK
        session.vault.delete(entry)
        session.save()
        out.say(out.paint(f"deleted {entry.name}", "green"))
    return OK


def cmd_gen(args: argparse.Namespace, out: Out) -> int:
    """Generate passwords without touching the vault (no master password needed)."""
    values = []
    for _ in range(max(args.count, 1)):
        if args.passphrase:
            values.append(generator.generate_passphrase(args.words, separator=args.separator,
                                                        capitalize=args.capitalize, add_digit=args.digit))
        else:
            values.append(generator.generate_password(_policy_from_args(args)))
    bits = (
        generator.passphrase_entropy_bits(args.words, add_digit=args.digit)
        if args.passphrase
        else generator.password_entropy_bits(_policy_from_args(args))
    )
    if args.copy and len(values) == 1:
        out.say(out.paint(f"{_bits(bits)} of entropy", "grey"))
        return _deliver_secret(values[0], args, out, what="password")
    for value in values:
        out.data(value)
    out.say(out.paint(f"{_bits(bits)} of entropy each", "grey"))
    return OK


def cmd_passwd(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        out.say("Now choose the new master password.")
        new_password = (
            prompt.read_password_stdin()  # second stdin line, for scripted rotation
            if args.password_stdin
            else prompt.read_master("New master password: ", confirm=True)
        )
        try:
            estimate = strength.estimate(bytes(new_password).decode("utf-8", errors="replace"))
            if estimate.bits < 60:
                out.warn(f"new master password is {estimate.label} ({_bits(estimate.bits)})")
                if sys.stdin.isatty() and not prompt.confirm_action("Use it anyway?"):
                    return ERROR
            kdf = crypto.calibrate_kdf(args.kdf_seconds, algo=session.context.kdf.algo) if args.kdf_seconds > 0 else None
            session.change_master(bytes(new_password), kdf=kdf)
        finally:
            crypto.wipe(new_password)
        out.say(out.paint("master password changed", "green"))
        out.say(out.paint(f"a backup of the old vault is at {session.path}.bak - delete it once you are sure", "grey"))
    return OK


def cmd_audit(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        checker = None
        if args.pwned:
            out.say(out.paint("checking Have I Been Pwned (only 5 hash characters leave this machine) ...", "grey"))
            checker = pwned.make_cached_checker()
        findings = strength.audit(session.vault, weak_bits=args.weak_bits, old_days=args.old_days,
                                  pwned_lookup=checker)
        if args.json:
            out.data(json.dumps([f.__dict__ for f in findings], indent=2))
            return FINDINGS if findings else OK
        if not findings:
            out.say(out.paint(f"no issues found in {len(session.vault)} entries", "green"))
            return OK
        width = max(len(f.entry) for f in findings)
        styles = {"critical": "red", "high": "red", "medium": "yellow", "low": "grey"}
        for finding in findings:
            severity = out.paint(finding.severity.ljust(8), styles.get(finding.severity, "grey"))
            out.say(f"{severity} {finding.entry.ljust(width)}  {finding.kind}: {finding.detail}")
        counts = strength.summarise(findings)
        out.say(out.paint("\n" + ", ".join(f"{count} {kind}" for kind, count in sorted(counts.items())), "grey"))
    return FINDINGS


def cmd_info(args: argparse.Namespace, out: Out) -> int:
    with _open_session(args, out) as session:
        info = session.info()
        if args.json:
            out.data(json.dumps(info, indent=2))
            return OK
        for key, value in info.items():
            if key == "warnings":
                continue
            out.say(f"{out.paint(key.rjust(11), 'grey')}  {value}")
    return OK


def cmd_export(args: argparse.Namespace, out: Out) -> int:
    if not args.insecure_plaintext:
        out.error(
            "export writes every password in clear text; pass --insecure-plaintext to confirm "
            "(to move a vault safely, just copy the vault file itself)"
        )
        return USAGE
    with _open_session(args, out) as session:
        entries = [e.to_dict() for e in session.vault]
        if args.format == "json":
            payload = json.dumps({"entries": entries}, indent=2).encode("utf-8")
        else:
            import csv
            import io

            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=["name", "url", "username", "password", "notes"],
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
            payload = buffer.getvalue().encode("utf-8")
        from .vaultfile import write_atomic

        write_atomic(args.out, payload, backup=False)  # 0600, like the vault
        out.warn(f"{args.out} now contains {len(entries)} passwords in clear text - delete it when done")
    return OK


def _import_tags(value: Any) -> list[str]:
    """Accept both our JSON export (a list) and browser CSV exports (a string)."""
    if isinstance(value, list):
        return [str(tag).strip() for tag in value if str(tag).strip()]
    return [tag.strip() for tag in str(value or "").split(",") if tag.strip()]


def cmd_import(args: argparse.Namespace, out: Out) -> int:
    try:
        with open(args.file, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as exc:
        out.error(f"cannot read {args.file}: {exc}")
        return ERROR

    records: list[dict[str, Any]] = []
    if args.format == "json" or (args.format == "auto" and raw.lstrip().startswith(("{", "["))):
        try:
            document = json.loads(raw)
            items = document["entries"] if isinstance(document, dict) else document
            records = [dict(item) for item in items]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            out.error(f"{args.file} is not a JSON export with an 'entries' list")
            return ERROR
    else:
        import csv
        import io

        for row in csv.DictReader(io.StringIO(raw)):
            records.append({(k or "").strip().lower(): (v or "") for k, v in row.items()})

    with _open_session(args, out) as session:
        added = skipped = 0
        for record in records:
            name = record.get("name") or record.get("title") or record.get("url") or ""
            if not name:
                skipped += 1
                continue
            if session.vault.has(name):
                if not args.replace:
                    skipped += 1
                    continue
                session.vault.delete(session.vault.get(name))
            session.vault.add(
                Entry(
                    name=name,
                    username=record.get("username") or record.get("login") or "",
                    password=record.get("password") or "",
                    url=record.get("url") or "",
                    notes=record.get("notes") or record.get("note") or "",
                    tags=_import_tags(record.get("tags")),
                )
            )
            added += 1
        if args.dry_run:
            out.say(f"would import {added} entries, skip {skipped}")
            return OK
        session.save()
        out.say(out.paint(f"imported {added} entries ({skipped} skipped)", "green"))
        out.warn("delete the import file - it holds your passwords in clear text")
    return OK


def cmd_shell(args: argparse.Namespace, out: Out) -> int:
    from .shell import run_shell

    with _open_session(args, out) as session:
        return run_shell(session, out, timeout=args.timeout_lock)


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

def _add_secret_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-g", "--generate", action="store_true", help="generate a random password")
    parser.add_argument("--passphrase", action="store_true", help="generate a random passphrase instead")
    parser.add_argument("--secret-stdin", action="store_true",
                        help="read the entry password from stdin (for scripts)")
    parser.add_argument("-l", "--length", type=int, default=generator.DEFAULT_LENGTH,
                        help=f"generated password length (default {generator.DEFAULT_LENGTH})")
    parser.add_argument("-w", "--words", type=int, default=generator.DEFAULT_WORDS,
                        help=f"words in a generated passphrase (default {generator.DEFAULT_WORDS})")
    parser.add_argument("--separator", default="-", help="passphrase separator (default '-')")
    parser.add_argument("--no-symbols", action="store_true", help="no punctuation in generated passwords")
    parser.add_argument("--no-digits", action="store_true", help="no digits")
    parser.add_argument("--no-upper", action="store_true", help="no upper case letters")
    parser.add_argument("--no-lower", action="store_true", help="no lower case letters")
    parser.add_argument("--readable", action="store_true", help="avoid look-alike characters (0/O, 1/l/I)")


def _add_reveal_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-s", "--show", action="store_true", help="print the secret to stdout")
    parser.add_argument("-c", "--copy", action="store_true", help="copy to the clipboard (default)")
    parser.add_argument("-t", "--timeout", type=int, default=clipboard.DEFAULT_TIMEOUT,
                        help=f"seconds before the clipboard is wiped (default {clipboard.DEFAULT_TIMEOUT})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwman",
        description="Offline, end-to-end encrypted password manager.",
        epilog="Secrets are never taken as command line arguments; they are prompted for or read from stdin.",
    )
    parser.add_argument("--vault", default=default_vault_path(),
                        help="vault file (default: $PWMAN_VAULT or ~/.local/share/pwman/vault.pmv)")
    parser.add_argument("--password-stdin", action="store_true",
                        help="read the master password from the first line of stdin")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print machine-readable output")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("-V", "--version", action="version", version=f"pwman {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a new vault")
    init.add_argument("--cipher", choices=crypto.CIPHERS, default=crypto.AES_GCM)
    init.add_argument("--kdf", choices=(crypto.ARGON2ID, crypto.SCRYPT), default=None,
                      help="key derivation function (default: Argon2id when available)")
    init.add_argument("--kdf-seconds", type=float, default=0.75,
                      help="tune the KDF to take about this long (0 = fixed defaults)")
    init.set_defaults(func=cmd_init)

    add = subparsers.add_parser("add", help="add an entry")
    add.add_argument("name")
    add.add_argument("-u", "--username", default=None)
    add.add_argument("--url", default=None)
    add.add_argument("--notes", default=None)
    add.add_argument("--tags", nargs="*", default=None)
    add.add_argument("--totp", default=None, help="TOTP seed or otpauth:// URI")
    _add_secret_flags(add)
    _add_reveal_flags(add)
    add.set_defaults(func=cmd_add)

    get = subparsers.add_parser("get", help="read an entry (password goes to the clipboard)")
    get.add_argument("name")
    get.add_argument("-f", "--field", choices=FIELDS, default="password")
    _add_reveal_flags(get)
    get.set_defaults(func=cmd_get)

    listing = subparsers.add_parser("list", help="list entries")
    listing.add_argument("query", nargs="?", default="")
    listing.add_argument("--tag", default="")
    listing.add_argument("--long", action="store_true", help="show tags and password strength")
    listing.add_argument("--json", action="store_true", help="machine-readable output (secrets redacted)")
    listing.set_defaults(func=cmd_list)

    search = subparsers.add_parser("search", help="alias for `list QUERY`")
    search.add_argument("query")
    search.add_argument("--tag", default="")
    search.add_argument("--long", action="store_true")
    search.add_argument("--json", action="store_true")
    search.set_defaults(func=cmd_list)

    edit = subparsers.add_parser("edit", help="change an entry")
    edit.add_argument("name")
    edit.add_argument("--rename", default=None)
    edit.add_argument("-u", "--username", default=None)
    edit.add_argument("--url", default=None)
    edit.add_argument("--notes", default=None)
    edit.add_argument("--tags", nargs="*", default=None)
    edit.add_argument("--totp", default=None, help="new TOTP seed, or '' to remove it")
    edit.add_argument("-p", "--password", action="store_true", help="prompt for a new password")
    _add_secret_flags(edit)
    _add_reveal_flags(edit)
    edit.set_defaults(func=cmd_edit)

    remove = subparsers.add_parser("rm", help="delete an entry")
    remove.add_argument("name")
    remove.add_argument("-f", "--force", action="store_true")
    remove.set_defaults(func=cmd_rm)

    gen = subparsers.add_parser("gen", help="generate a password without opening the vault")
    gen.add_argument("-n", "--count", type=int, default=1)
    gen.add_argument("--capitalize", action="store_true", help="capitalise passphrase words")
    gen.add_argument("--digit", action="store_true", help="append two random digits to a passphrase")
    _add_secret_flags(gen)
    _add_reveal_flags(gen)
    gen.set_defaults(func=cmd_gen, show=True)

    passwd = subparsers.add_parser("passwd", help="change the master password")
    passwd.add_argument("--kdf-seconds", type=float, default=0.0,
                        help="also re-tune the key derivation cost")
    passwd.set_defaults(func=cmd_passwd)

    audit = subparsers.add_parser("audit", help="find weak, reused, stale or breached passwords")
    audit.add_argument("--weak-bits", type=float, default=60.0, help="flag entries below this entropy")
    audit.add_argument("--old-days", type=float, default=365.0, help="flag passwords older than this")
    audit.add_argument("--pwned", action="store_true",
                       help="also query Have I Been Pwned (k-anonymous, sends 5 hash characters)")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    info = subparsers.add_parser("info", help="show vault metadata")
    info.add_argument("--json", action="store_true")
    info.set_defaults(func=cmd_info)

    export = subparsers.add_parser("export", help="write entries to a plain text file")
    export.add_argument("out")
    export.add_argument("--format", choices=("json", "csv"), default="json")
    export.add_argument("--insecure-plaintext", action="store_true", help="required: confirms the risk")
    export.set_defaults(func=cmd_export)

    importer = subparsers.add_parser("import", help="import entries from JSON or CSV")
    importer.add_argument("file")
    importer.add_argument("--format", choices=("auto", "json", "csv"), default="auto")
    importer.add_argument("--replace", action="store_true", help="overwrite entries with the same name")
    importer.add_argument("--dry-run", action="store_true")
    importer.set_defaults(func=cmd_import)

    shell = subparsers.add_parser("shell", help="interactive session (unlock once, auto-locks when idle)")
    shell.add_argument("--timeout-lock", type=int, default=300, help="idle seconds before locking (default 300)")
    shell.set_defaults(func=cmd_shell)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Out(quiet=args.quiet, color=False if args.no_color else None)
    args.vault = os.path.abspath(os.path.expanduser(args.vault))
    handler: Callable[[argparse.Namespace, Out], int] = args.func
    try:
        return handler(args, out)
    except AuthenticationError as exc:
        out.error(str(exc))
        return AUTH
    except PwmanError as exc:
        out.error(str(exc))
        return ERROR
    except KeyboardInterrupt:
        out.say("")
        return ERROR
    except BrokenPipeError:  # pragma: no cover - e.g. `pwman list | head`
        return OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
