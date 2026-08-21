"""The session layer: opening, saving, rotating, closing."""

from __future__ import annotations

import os

import pytest
from conftest import TEST_MASTER, cheap_kdf

from pwman import crypto
from pwman.errors import AuthenticationError, PwmanError
from pwman.session import Session
from pwman.vault import Entry


def new_session(path: str) -> Session:
    return Session.create(path, TEST_MASTER, kdf=cheap_kdf())


def test_create_writes_an_openable_vault(vault_path):
    with new_session(vault_path) as session:
        session.vault.add(Entry(name="x", password="p"))
        session.save()

    with Session.open(vault_path, TEST_MASTER) as reopened:
        assert reopened.vault.get("x").password == "p"


def test_create_refuses_to_clobber(vault_path):
    new_session(vault_path).close()
    with pytest.raises(PwmanError):
        new_session(vault_path)


def test_open_with_the_wrong_password(vault_path):
    new_session(vault_path).close()
    with pytest.raises(AuthenticationError):
        Session.open(vault_path, b"wrong password entirely")


def test_saving_twice_keeps_a_backup(vault_path):
    with new_session(vault_path) as session:
        session.vault.add(Entry(name="first", password="p"))
        session.save()
        session.vault.add(Entry(name="second", password="p"))
        session.save()
    assert os.path.exists(vault_path + ".bak")
    with Session.open(vault_path + ".bak", TEST_MASTER) as backup:
        assert backup.vault.names() == ["first"]


def test_change_master_rewraps_without_touching_the_entries(vault_path):
    with new_session(vault_path) as session:
        session.vault.add(Entry(name="x", password="p"))
        session.save()
        session.change_master(b"a-completely-new-master", kdf=cheap_kdf())
        assert session.vault.get("x").password == "p"

    with pytest.raises(AuthenticationError):
        Session.open(vault_path, TEST_MASTER)
    with Session.open(vault_path, b"a-completely-new-master") as reopened:
        assert reopened.vault.get("x").password == "p"


def test_closing_wipes_the_key_material(vault_path):
    session = new_session(vault_path)
    key = session.context._vault_key
    assert any(key)
    session.close()
    assert not any(key)
    with pytest.raises(PwmanError):
        session.save()


def test_close_is_idempotent(vault_path):
    session = new_session(vault_path)
    session.close()
    session.close()


def test_info_surfaces_the_real_metadata(vault_path):
    with new_session(vault_path) as session:
        info = session.info()
    assert info["entries"] == 0
    assert info["mode"] == "0600"
    assert info["cipher"] == crypto.AES_GCM
    assert "Argon2id" in info["kdf"] or "scrypt" in info["kdf"]


def test_permission_problems_are_reported_on_open(vault_path):
    new_session(vault_path).close()
    os.chmod(vault_path, 0o666)
    with Session.open(vault_path, TEST_MASTER) as session:
        assert any("accessible to other users" in w for w in session.warnings)


def test_save_refuses_to_clobber_a_parallel_session(vault_path):
    """Two unlocked sessions must not silently overwrite each other."""
    first = new_session(vault_path)
    second = Session.open(vault_path, TEST_MASTER)

    second.vault.add(Entry(name="from-second", password="p"))
    second.save()

    first.vault.add(Entry(name="from-first", password="p"))
    with pytest.raises(PwmanError) as error:
        first.save()
    assert "changed on disk" in str(error.value)

    first.close()
    second.close()
    with Session.open(vault_path, TEST_MASTER) as reopened:
        assert reopened.vault.names() == ["from-second"]
