"""The optional breach check -- verified entirely offline with a stub fetcher."""

from __future__ import annotations

import pytest

from pwman import pwned
from pwman.errors import PwmanError


def test_only_five_hash_characters_would_leave_the_machine():
    prefix, suffix = pwned.prefix_and_suffix("password")
    assert prefix == "5BAA6"  # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    assert len(prefix) == 5
    assert prefix + suffix == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_the_full_password_is_never_passed_to_the_fetcher():
    seen: list[str] = []

    def fetch(prefix: str) -> str:
        seen.append(prefix)
        return ""

    pwned.check("hunter2", fetch=fetch)
    assert seen == [pwned.prefix_and_suffix("hunter2")[0]]
    assert "hunter2" not in seen[0]


def test_a_matching_suffix_returns_the_breach_count():
    _, suffix = pwned.prefix_and_suffix("password")
    body = f"AAAA:1\r\n{suffix}:9,659,365\r\nBBBB:2"
    assert pwned.check("password", fetch=lambda prefix: body) == 9659365


def test_a_missing_suffix_returns_zero():
    assert pwned.check("password", fetch=lambda prefix: "AAAA:1\r\nBBBB:2") == 0
    assert pwned.check("", fetch=lambda prefix: pytest.fail("must not be called")) == 0


def test_response_parsing_is_case_insensitive_and_survives_junk():
    _, suffix = pwned.prefix_and_suffix("password")
    assert pwned.parse_range_response(f"{suffix.lower()}:5", suffix) == 5
    assert pwned.parse_range_response(f"{suffix}:not-a-number", suffix) == 1
    assert pwned.parse_range_response("garbage without a colon", suffix) == 0


def test_cached_checker_fetches_each_prefix_once():
    calls: list[str] = []

    def fetch(prefix: str) -> str:
        calls.append(prefix)
        return ""

    checker = pwned.make_cached_checker(fetch)
    for _ in range(5):
        checker("password")
        checker("password")
    assert len(calls) == 1


def test_network_failures_become_readable_errors(monkeypatch):
    def explode(prefix: str) -> str:
        raise OSError("no route to host")

    monkeypatch.setattr(pwned, "_http_fetch", lambda prefix: (_ for _ in ()).throw(PwmanError("breach check failed")))
    with pytest.raises(PwmanError):
        pwned.check("password")
