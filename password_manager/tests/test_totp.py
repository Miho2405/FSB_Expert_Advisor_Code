"""RFC 4226 / RFC 6238 conformance."""

from __future__ import annotations

import base64

import pytest

from pwman.errors import PwmanError
from pwman.totp import TotpConfig, hotp, normalize_secret, parse_otpauth, parse_secret_input, totp

RFC_SEED_SHA1 = base64.b32encode(b"12345678901234567890").decode()
RFC_SEED_SHA256 = base64.b32encode(b"12345678901234567890123456789012").decode()
RFC_SEED_SHA512 = base64.b32encode((b"1234567890" * 7)[:64]).decode()


@pytest.mark.parametrize("moment, expected", [
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
])
def test_rfc6238_sha1_vectors(moment, expected):
    code, _ = totp(TotpConfig(RFC_SEED_SHA1, digits=8), at=moment)
    assert code == expected


@pytest.mark.parametrize("moment, expected", [(59, "46119246"), (1111111109, "68084774"), (20000000000, "77737706")])
def test_rfc6238_sha256_vectors(moment, expected):
    code, _ = totp(TotpConfig(RFC_SEED_SHA256, digits=8, algorithm="sha256"), at=moment)
    assert code == expected


@pytest.mark.parametrize("moment, expected", [(59, "90693936"), (1111111109, "25091201"), (20000000000, "47863826")])
def test_rfc6238_sha512_vectors(moment, expected):
    code, _ = totp(TotpConfig(RFC_SEED_SHA512, digits=8, algorithm="sha512"), at=moment)
    assert code == expected


def test_rfc4226_hotp_vectors():
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    for counter, code in enumerate(expected):
        assert hotp(b"12345678901234567890", counter) == code


def test_remaining_seconds_counts_down_within_the_step():
    _, remaining = totp(TotpConfig(RFC_SEED_SHA1), at=1000.0)
    assert remaining == 30 - int(1000 % 30)


def test_code_changes_at_the_step_boundary():
    first, _ = totp(TotpConfig(RFC_SEED_SHA1), at=1000)   # counter 33 spans 990..1019
    same, _ = totp(TotpConfig(RFC_SEED_SHA1), at=1019)
    later, _ = totp(TotpConfig(RFC_SEED_SHA1), at=1020)
    assert first == same
    assert first != later


def test_secrets_tolerate_spaces_lowercase_and_missing_padding():
    canonical = normalize_secret("JBSWY3DPEHPK3PXP")
    assert normalize_secret("jbsw y3dp ehpk 3pxp") == canonical
    assert normalize_secret("JBSWY3DP-EHPK3PXP") == canonical


@pytest.mark.parametrize("bad", ["", "not base32 !!", "1111111"])
def test_broken_secrets_are_rejected(bad):
    with pytest.raises(PwmanError):
        normalize_secret(bad)


def test_parse_otpauth_uri():
    config = parse_otpauth(
        "otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=8&period=60"
    )
    assert config.secret == "JBSWY3DPEHPK3PXP"
    assert (config.digits, config.step) == (8, 60)
    assert config.label == "GitHub:me@example.com"


@pytest.mark.parametrize("uri", [
    "https://example.com",
    "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/x?issuer=nothing",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=md5",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=many",
])
def test_broken_uris_are_rejected(uri):
    with pytest.raises(PwmanError):
        parse_otpauth(uri)


def test_parse_secret_input_accepts_both_forms():
    assert parse_secret_input("jbswy3dpehpk3pxp").secret == "JBSWY3DPEHPK3PXP"
    assert parse_secret_input("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").secret == "JBSWY3DPEHPK3PXP"


@pytest.mark.parametrize("digits", [4, 11])
def test_unreasonable_digit_counts_are_rejected(digits):
    with pytest.raises(PwmanError):
        hotp(b"key", 0, digits=digits)
