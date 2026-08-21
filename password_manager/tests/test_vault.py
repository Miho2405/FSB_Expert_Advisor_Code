"""Entry bookkeeping: uniqueness, lookup, history, serialisation."""

from __future__ import annotations

import json

import pytest

from pwman.errors import VaultError, VaultFormatError
from pwman.vault import Entry, Vault, age_days, now_iso


def make_vault() -> Vault:
    vault = Vault()
    vault.add(Entry(name="GitHub", username="me@example.com", password="alpha", tags=["dev"], url="https://github.com"))
    vault.add(Entry(name="Bank", username="12345", password="beta", tags=["money"]))
    vault.add(Entry(name="Gitlab", username="me", password="gamma", tags=["dev"]))
    return vault


def test_names_are_unique_case_insensitively():
    vault = make_vault()
    with pytest.raises(VaultError):
        vault.add(Entry(name="github"))
    assert len(vault) == 3


def test_empty_names_are_rejected():
    with pytest.raises(VaultError):
        Vault().add(Entry(name="   "))


def test_lookup_prefers_exact_match_over_substring():
    vault = make_vault()
    assert vault.get("GitHub").username == "me@example.com"
    assert vault.get("github").username == "me@example.com"
    assert vault.get("Gitlab").username == "me"


def test_ambiguous_lookup_refuses_to_guess():
    vault = make_vault()
    with pytest.raises(VaultError) as error:
        vault.get("git")
    assert "matches 2 entries" in str(error.value)


def test_lookup_by_id_and_missing_entry():
    vault = make_vault()
    entry = vault.get("Bank")
    assert vault.get(entry.id) is entry
    with pytest.raises(VaultError):
        vault.get("nothing here")


def test_search_covers_all_visible_fields_and_tags():
    vault = make_vault()
    assert [e.name for e in vault.search("github.com")] == ["GitHub"]
    assert [e.name for e in vault.search("", tag="dev")] == ["GitHub", "Gitlab"]
    assert [e.name for e in vault.search("12345")] == ["Bank"]
    assert len(vault.search("")) == 3


def test_changing_the_password_records_history_once():
    vault = make_vault()
    entry = vault.get("Bank")
    original_changed_at = entry.password_changed_at

    vault.update(entry, password="beta")  # unchanged: no history, no new timestamp
    assert entry.history == []
    assert entry.password_changed_at == original_changed_at

    vault.update(entry, password="delta")
    assert entry.password == "delta"
    assert [h["password"] for h in entry.history] == ["beta"]


def test_history_is_capped():
    vault = Vault()
    entry = vault.add(Entry(name="x", password="p0"))
    for index in range(1, 30):
        vault.update(entry, password=f"p{index}")
    assert len(entry.history) == 10
    assert entry.history[0]["password"] == "p28"


def test_rename_respects_uniqueness():
    vault = make_vault()
    with pytest.raises(VaultError):
        vault.update(vault.get("Bank"), name="GitHub")
    vault.update(vault.get("Bank"), name="Savings")
    assert vault.get("Savings").username == "12345"


def test_tags_are_normalised():
    vault = Vault()
    entry = vault.add(Entry(name="x"))
    vault.update(entry, tags=[" Work ", "work", "", "Mail"])
    assert entry.tags == ["Mail", "Work"]


def test_delete_removes_exactly_one_entry():
    vault = make_vault()
    vault.delete(vault.get("Bank"))
    assert vault.names() == ["GitHub", "Gitlab"]


def test_payload_round_trip_preserves_everything():
    vault = make_vault()
    entry = vault.get("GitHub")
    vault.update(entry, password="new", notes="line1\nline2", totp_secret="JBSWY3DPEHPK3PXP")
    restored = Vault.from_payload(vault.to_payload())
    assert restored.names() == vault.names()
    original, copy = vault.get("GitHub"), restored.get("GitHub")
    assert copy.to_dict() == original.to_dict()


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"schema": 99, "entries": []}',
                                     b'{"schema": 1, "entries": [{"no": "name"}]}'])
def test_broken_payloads_are_reported(payload):
    with pytest.raises(VaultFormatError):
        Vault.from_payload(payload)


def test_unknown_fields_are_ignored_on_load():
    payload = b'{"schema": 1, "entries": [{"name": "x", "password": "p", "future_field": 1}]}'
    vault = Vault.from_payload(payload)
    assert vault.get("x").password == "p"


def test_redacted_hides_every_secret():
    entry = Entry(name="x", password="hunter2-current", totp_secret="JBSWY3DPEHPK3PXP",
                  history=[{"password": "hunter1-previous", "changed_at": now_iso()}])
    serialised = json.dumps(entry.redacted())
    for leak in ("hunter2-current", "hunter1-previous", "JBSWY3DPEHPK3PXP"):
        assert leak not in serialised
    assert entry.redacted()["name"] == "x"
    assert entry.redacted()["password"] == "***"


def test_age_days_handles_junk_and_real_timestamps():
    assert age_days("not a date") is None
    assert 0 <= age_days(now_iso()) < 0.01
    assert age_days("2020-01-01T00:00:00+00:00") > 1000
