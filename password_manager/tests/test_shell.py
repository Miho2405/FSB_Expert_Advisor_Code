"""The interactive shell: dispatch, persistence and auto-lock."""

from __future__ import annotations

import io
import sys

import pytest
from conftest import TEST_MASTER, cheap_kdf

from pwman import clipboard, shell
from pwman.cli import Out
from pwman.session import Session
from pwman.vault import Entry


@pytest.fixture
def session(vault_path):
    session = Session.create(vault_path, TEST_MASTER, kdf=cheap_kdf())
    session.vault.add(Entry(name="github", username="me", password="hunter2", tags=["dev"]))
    session.vault.add(Entry(name="bank", username="12345", password="a-much-longer-password-42"))
    session.save()
    return session


@pytest.fixture
def drive(monkeypatch, capsys):
    """Feed a script of commands to the shell and return everything it printed."""

    def _drive(session, *commands: str, timeout: int = 0):
        monkeypatch.setattr(sys, "stdin", io.StringIO("".join(c + "\n" for c in commands)))
        code = shell.run_shell(session, Out(color=False), timeout=timeout)
        return code, capsys.readouterr()

    return _drive


def test_list_and_show_never_print_the_password(session, drive):
    code, captured = drive(session, "list", "show github", "exit")
    assert code == 0
    assert "github" in captured.out
    assert "hunter2" not in captured.out
    assert "************" in captured.out


def test_get_show_prints_on_request(session, drive):
    _, captured = drive(session, "get github --show", "exit")
    assert "hunter2" in captured.out


def test_get_uses_the_clipboard_and_wipes_it_on_exit(session, drive, monkeypatch):
    board = {"value": None}
    monkeypatch.setattr(clipboard, "copy", lambda text, backend=None: board.update(value=text))
    monkeypatch.setattr(clipboard, "clear", lambda text, backend=None: board.update(value=""))

    _, captured = drive(session, "get github", "exit")
    assert "copied" in captured.out
    assert "hunter2" not in captured.out
    assert board["value"] == ""  # wiped when the shell exited


def test_changes_are_saved_immediately(session, drive, vault_path):
    drive(session, "add newentry --generate", "set github username other@example.com", "rm bank", "exit")
    with Session.open(vault_path, TEST_MASTER) as reopened:
        assert reopened.vault.names() == ["github", "newentry"]
        assert reopened.vault.get("github").username == "other@example.com"


def test_password_change_records_history(session, drive, vault_path):
    drive(session, "passwd github --generate", "exit")
    with Session.open(vault_path, TEST_MASTER) as reopened:
        entry = reopened.vault.get("github")
        assert entry.password != "hunter2"
        assert entry.history[0]["password"] == "hunter2"


def test_audit_and_gen_and_help(session, drive):
    _, captured = drive(session, "audit", "gen 24", "help", "exit")
    assert "github" in captured.out and "weak" in captured.out
    assert "bits" in captured.out
    assert "commands:" in captured.out


def test_unknown_commands_and_bad_arguments_do_not_end_the_session(session, drive):
    _, captured = drive(session, "frobnicate", "get", "get nonexistent", "list", "exit")
    assert "unknown command" in captured.err
    assert "usage: get NAME" in captured.err
    assert "no entry matching" in captured.err
    assert "github" in captured.out  # the shell kept running


def test_idle_timeout_locks_the_vault(session, monkeypatch, capsys):
    monkeypatch.setattr(shell, "_read_line", lambda timeout: None)  # pretend nobody typed
    code = shell.run_shell(session, Out(color=False), timeout=7)
    captured = capsys.readouterr()
    assert code == 0
    assert "idle for 7s" in captured.out
    assert "locked" in captured.out
    assert not any(session.context._vault_key)  # keys wiped


def test_eof_locks_the_vault(session, drive):
    _, captured = drive(session)  # no commands at all: immediate EOF
    assert "locked" in captured.out
    assert not any(session.context._vault_key)
