"""The encrypted container: round trips, tamper detection, safe writing."""

from __future__ import annotations

import json
import os
import stat

import pytest
from conftest import TEST_MASTER, cheap_kdf

from pwman import crypto, vaultfile
from pwman.errors import AuthenticationError, PwmanError, VaultFormatError


def seal(payload: bytes = b"hello", *, cipher: str = crypto.AES_GCM) -> bytes:
    with vaultfile.create(TEST_MASTER, kdf=cheap_kdf(), cipher=cipher) as context:
        return context.seal(payload)


@pytest.mark.parametrize("cipher", crypto.CIPHERS)
def test_round_trip(cipher):
    blob = seal(b'{"entries": []}', cipher=cipher)
    context, payload, warnings = vaultfile.unseal(blob, TEST_MASTER)
    context.close()
    assert payload == b'{"entries": []}'
    assert warnings == []


def test_plaintext_never_appears_in_the_file():
    blob = seal(b"super-secret-value")
    assert b"super-secret-value" not in blob
    assert "super-secret-value" not in blob.decode("utf-8")


def test_wrong_password_is_rejected():
    with pytest.raises(AuthenticationError):
        vaultfile.unseal(seal(), b"not the master password")


def test_repeated_saves_never_repeat_a_nonce_or_salt():
    context, _, _ = vaultfile.unseal(seal(), TEST_MASTER)
    images = [json.loads(context.seal(b"same payload")) for _ in range(20)]
    context.close()
    for section in ("wrap", "body"):
        for field in ("salt", "nonce", "ct"):
            values = {image[section][field] for image in images}
            assert len(values) == 20, f"{section}.{field} repeated across saves"


def test_padding_hides_the_payload_size():
    small = len(seal(b"a"))
    bigger = len(seal(b"b" * 1000))
    assert small == bigger
    assert len(seal(b"c" * 9000)) > small


@pytest.mark.parametrize("path", [("kdf", "salt"), ("wrap", "ct"), ("wrap", "nonce"), ("wrap", "salt"),
                                  ("body", "ct"), ("body", "nonce"), ("body", "salt")])
def test_flipping_any_ciphertext_or_salt_is_detected(path):
    document = json.loads(seal())
    import base64

    section, field = path
    raw = bytearray(base64.b64decode(document[section][field]))
    raw[0] ^= 0x01
    document[section][field] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(AuthenticationError):
        vaultfile.unseal(json.dumps(document).encode(), TEST_MASTER)


def test_downgrading_the_kdf_cost_is_detected():
    """The header is authenticated, so an attacker cannot make unlocking cheap."""
    document = json.loads(seal())
    document["kdf"]["time_cost"] = 1
    with pytest.raises(AuthenticationError):
        vaultfile.unseal(json.dumps(document).encode(), TEST_MASTER)


def test_bodies_cannot_be_swapped_between_vaults():
    """Even with the same master password, a body belongs to exactly one wrap."""
    first = json.loads(seal(b"first vault"))
    second = json.loads(seal(b"second vault"))
    first["body"] = second["body"]
    with pytest.raises(AuthenticationError):
        vaultfile.unseal(json.dumps(first).encode(), TEST_MASTER)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("magic"),
        lambda d: d.update(magic="OTHER"),
        lambda d: d.update(format=99),
        lambda d: d.update(cipher="rot13"),
        lambda d: d.pop("body"),
        lambda d: d["wrap"].pop("nonce"),
    ],
)
def test_malformed_headers_are_reported_as_format_errors(mutate):
    document = json.loads(seal())
    mutate(document)
    with pytest.raises(VaultFormatError):
        vaultfile.unseal(json.dumps(document).encode(), TEST_MASTER)


def test_non_json_input_is_reported_as_format_error():
    with pytest.raises(VaultFormatError):
        vaultfile.unseal(b"\x00\x01\x02 not a vault", TEST_MASTER)
    assert not vaultfile.is_vault(b"nope")
    assert vaultfile.is_vault(seal())


def test_invalid_base64_is_reported_not_crashed():
    document = json.loads(seal())
    document["body"]["ct"] = "not base64!!"
    with pytest.raises(VaultFormatError):
        vaultfile.unseal(json.dumps(document).encode(), TEST_MASTER)


def test_rekey_keeps_the_content_and_changes_the_password():
    context, payload, _ = vaultfile.unseal(seal(b"content"), TEST_MASTER)
    rekeyed = context.rekey(b"a-brand-new-master-password", kdf=cheap_kdf())
    blob = rekeyed.seal(payload)
    context.close()
    rekeyed.close()

    with pytest.raises(AuthenticationError):
        vaultfile.unseal(blob, TEST_MASTER)
    reopened, again, _ = vaultfile.unseal(blob, b"a-brand-new-master-password")
    reopened.close()
    assert again == b"content"


def test_weak_parameters_produce_a_warning_not_a_failure():
    weak = crypto.KdfParams(crypto.SCRYPT, b"x" * 16, {"n": 1 << 12, "r": 8, "p": 1})
    with vaultfile.create(TEST_MASTER, kdf=weak, cipher=crypto.AES_GCM) as context:
        blob = context.seal(b"payload")
    reopened, payload, warnings = vaultfile.unseal(blob, TEST_MASTER)
    reopened.close()
    assert payload == b"payload"
    assert any("weak key derivation" in w for w in warnings)


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

def test_write_atomic_creates_a_private_file(tmp_path):
    target = str(tmp_path / "sub" / "vault.pmv")
    vaultfile.write_atomic(target, b"first", backup=False)
    assert vaultfile.read(target) == b"first"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert vaultfile.permission_warnings(target) == []


def test_write_atomic_keeps_a_backup_and_leaves_no_temp_files(tmp_path):
    target = str(tmp_path / "vault.pmv")
    vaultfile.write_atomic(target, b"first", backup=False)
    vaultfile.write_atomic(target, b"second")
    assert vaultfile.read(target) == b"second"
    assert vaultfile.read(target + ".bak") == b"first"
    assert stat.S_IMODE(os.stat(target + ".bak").st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir() if ".tmp." in p.name] == []


def test_world_readable_vault_is_flagged(tmp_path):
    target = str(tmp_path / "vault.pmv")
    vaultfile.write_atomic(target, b"data", backup=False)
    os.chmod(target, 0o644)
    assert any("accessible to other users" in w for w in vaultfile.permission_warnings(target))


def test_reading_a_missing_vault_explains_itself(tmp_path):
    with pytest.raises(PwmanError) as error:
        vaultfile.read(str(tmp_path / "nope.pmv"))
    assert "init" in str(error.value)


def test_oversized_input_is_refused():
    with pytest.raises(VaultFormatError):
        vaultfile.unseal(b"x" * (vaultfile.MAX_FILE_BYTES + 1), TEST_MASTER)


def test_unknown_header_fields_are_refused():
    """Anything outside the authenticated fields could ride along unprotected."""
    document = json.loads(seal())
    document["comment"] = "smuggled, unauthenticated payload"
    with pytest.raises(VaultFormatError) as error:
        vaultfile.unseal(json.dumps(document).encode(), TEST_MASTER)
    assert "unexpected fields" in str(error.value)
