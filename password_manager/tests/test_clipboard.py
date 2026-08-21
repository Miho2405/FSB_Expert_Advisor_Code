"""Clipboard handling -- with stub backends, so no real clipboard is touched."""

from __future__ import annotations

import subprocess

import pytest

from pwman import clipboard
from pwman.errors import ClipboardError


@pytest.fixture
def stub_backend(monkeypatch):
    """Pretend xclip exists and record what it is asked to do."""
    state = {"content": "", "calls": []}

    def fake_which(name):
        return "/usr/bin/xclip" if name == "xclip" else None

    def fake_run(command, **kwargs):
        state["calls"].append((tuple(command), kwargs.get("input")))
        if "-o" in command:
            return subprocess.CompletedProcess(command, 0, stdout=state["content"].encode(), stderr=b"")
        state["content"] = (kwargs.get("input") or b"").decode()
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(clipboard.shutil, "which", fake_which)
    monkeypatch.setattr(clipboard.subprocess, "run", fake_run)
    return state


def test_secret_is_passed_on_stdin_never_as_an_argument(stub_backend):
    clipboard.copy("s3cr3t")
    command, stdin = stub_backend["calls"][-1]
    assert stdin == b"s3cr3t"
    assert not any("s3cr3t" in part for part in command)


def test_copy_and_paste_round_trip(stub_backend):
    clipboard.copy("value")
    assert clipboard.paste() == "value"
    assert clipboard.available()


def test_clear_wipes_our_own_value(stub_backend):
    clipboard.copy("value")
    assert clipboard.clear("value") is True
    assert stub_backend["content"] == ""


def test_clear_leaves_someone_elses_value_alone(stub_backend):
    clipboard.copy("value")
    stub_backend["content"] = "something the user copied later"
    assert clipboard.clear("value") is False
    assert stub_backend["content"] == "something the user copied later"


def test_copy_and_clear_wipes_after_the_timeout(stub_backend):
    announced = []
    clipboard.copy_and_clear("temporary", timeout=0, announce=announced.append)
    assert announced and announced[0].name == "xclip"
    assert stub_backend["content"] == ""


def test_missing_backend_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: None)
    assert not clipboard.available()
    with pytest.raises(ClipboardError) as error:
        clipboard.copy("x")
    assert "--show" in str(error.value)


def test_backend_failure_is_wrapped(monkeypatch, stub_backend):
    def fail(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(clipboard.subprocess, "run", fail)
    with pytest.raises(ClipboardError):
        clipboard.copy("x")
    assert clipboard.paste() is None  # reading failures are soft
