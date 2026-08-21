"""Key derivation, sub-keys and AEAD."""

from __future__ import annotations

import pytest

from pwman import crypto
from pwman.errors import AuthenticationError, CryptoError


def test_derive_key_is_deterministic_and_salted(kdf):
    first = crypto.derive_key(b"master", kdf)
    second = crypto.derive_key(b"master", kdf)
    assert bytes(first) == bytes(second)
    assert len(first) == crypto.KEY_LEN

    other_salt = crypto.KdfParams(kdf.algo, crypto.random_bytes(16), dict(kdf.params))
    assert bytes(crypto.derive_key(b"master", other_salt)) != bytes(first)
    assert bytes(crypto.derive_key(b"other", kdf)) != bytes(first)


def test_derive_key_returns_a_wipeable_buffer(kdf):
    key = crypto.derive_key(b"master", kdf)
    assert isinstance(key, bytearray)
    crypto.wipe(key)
    assert bytes(key) == b"\x00" * crypto.KEY_LEN


def test_scrypt_backend_matches_hashlib():
    import hashlib

    params = crypto.KdfParams(crypto.SCRYPT, b"s" * 16, {"n": 1 << 14, "r": 8, "p": 1})
    expected = hashlib.scrypt(b"pw", salt=b"s" * 16, n=1 << 14, r=8, p=1, maxmem=1 << 26, dklen=32)
    assert bytes(crypto.derive_key(b"pw", params)) == expected


@pytest.mark.parametrize(
    "algo, params",
    [
        (crypto.ARGON2ID, {"memory_kib": 1024, "time_cost": 1}),          # missing parallelism
        (crypto.SCRYPT, {"n": 1 << 15, "r": 8, "p": 0}),                  # non-positive
        (crypto.SCRYPT, {"n": 1000, "r": 8, "p": 1}),                     # n not a power of two
        ("md5", {"n": 1, "r": 1, "p": 1}),                                # unknown algorithm
    ],
)
def test_bad_kdf_parameters_are_rejected(algo, params):
    with pytest.raises(CryptoError):
        crypto.KdfParams(algo, b"x" * 16, params)


def test_short_salt_is_rejected():
    with pytest.raises(CryptoError):
        crypto.KdfParams(crypto.SCRYPT, b"short", {"n": 1 << 15, "r": 8, "p": 1})


def test_weaknesses_flags_cheap_parameters():
    weak = crypto.KdfParams(crypto.SCRYPT, b"x" * 16, {"n": 1 << 10, "r": 8, "p": 1})
    assert weak.weaknesses()
    strong = crypto.KdfParams(crypto.SCRYPT, b"x" * 16, dict(crypto.DEFAULT_SCRYPT))
    assert strong.weaknesses() == []


def test_kdf_params_survive_serialisation(kdf):
    restored = crypto.KdfParams.from_dict(kdf.to_dict())
    assert restored.algo == kdf.algo
    assert restored.salt == kdf.salt
    assert dict(restored.params) == {k: int(v) for k, v in kdf.params.items()}


def test_calibration_stays_within_bounds():
    from conftest import REAL_CALIBRATE_KDF

    params = REAL_CALIBRATE_KDF(0.05)  # the autouse fixture replaced crypto.calibrate_kdf
    assert params.weaknesses() == []
    if params.algo == crypto.ARGON2ID:
        assert crypto.MIN_ARGON2["memory_kib"] <= params.params["memory_kib"] <= 1024 * 1024


def test_subkeys_differ_per_salt_and_info():
    parent = crypto.random_bytes(32)
    a = bytes(crypto.subkey(parent, b"salt-a", b"info"))
    b = bytes(crypto.subkey(parent, b"salt-b", b"info"))
    c = bytes(crypto.subkey(parent, b"salt-a", b"other"))
    assert len({a, b, c}) == 3
    assert a == bytes(crypto.subkey(parent, b"salt-a", b"info"))


@pytest.mark.parametrize("cipher", crypto.CIPHERS)
def test_aead_round_trip(cipher):
    key = crypto.random_bytes(32)
    nonce, ciphertext = crypto.encrypt(cipher, key, b"attack at dawn", b"header")
    assert b"attack" not in ciphertext
    assert crypto.decrypt(cipher, key, nonce, ciphertext, b"header") == b"attack at dawn"


@pytest.mark.parametrize("cipher", crypto.CIPHERS)
def test_aead_detects_every_kind_of_tampering(cipher):
    key = crypto.random_bytes(32)
    nonce, ciphertext = crypto.encrypt(cipher, key, b"secret", b"header")

    flipped = bytearray(ciphertext)
    flipped[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        crypto.decrypt(cipher, key, nonce, bytes(flipped), b"header")
    with pytest.raises(AuthenticationError):
        crypto.decrypt(cipher, key, nonce, ciphertext, b"other header")
    with pytest.raises(AuthenticationError):
        crypto.decrypt(cipher, key, crypto.random_bytes(12), ciphertext, b"header")
    with pytest.raises(AuthenticationError):
        crypto.decrypt(cipher, crypto.random_bytes(32), nonce, ciphertext, b"header")


def test_nonces_are_not_reused():
    key = crypto.random_bytes(32)
    nonces = {crypto.encrypt(crypto.AES_GCM, key, b"x", b"")[0] for _ in range(500)}
    assert len(nonces) == 500


def test_equal_is_constant_time_wrapper():
    assert crypto.equal(b"abc", b"abc")
    assert not crypto.equal(b"abc", b"abd")


def test_every_kdf_parameter_must_be_a_positive_integer():
    """A crafted header must not smuggle non-numeric values into the KDF."""
    with pytest.raises(CryptoError):
        crypto.KdfParams(crypto.SCRYPT, b"x" * 16, {"n": 1 << 15, "r": 8, "p": 1, "extra": "not an int"})
    with pytest.raises(CryptoError):
        crypto.KdfParams(crypto.SCRYPT, b"x" * 16, {"n": 1 << 15, "r": 8, "p": True})
