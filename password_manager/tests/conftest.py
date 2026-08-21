"""Shared fixtures.

Real vaults use deliberately slow key derivation.  Tests would spend all their
time in Argon2, so the fixtures below patch in the cheapest parameters that are
still *valid* (they meet the enforced minimums, so no warning path is skipped).
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pwman import crypto  # noqa: E402

TEST_MASTER = b"tree-lamp-river-quiet-orbit-seven"

# Captured before any fixture patches it, so tests can still exercise the real thing.
REAL_CALIBRATE_KDF = crypto.calibrate_kdf


def cheap_kdf(prefer: str | None = None) -> crypto.KdfParams:
    """Fast but still-valid parameters (Argon2id at the enforced minimum)."""
    algo = prefer or (crypto.ARGON2ID if crypto.argon2_available() else crypto.SCRYPT)
    params = dict(crypto.MIN_ARGON2) if algo == crypto.ARGON2ID else dict(crypto.MIN_SCRYPT)
    return crypto.KdfParams(algo=algo, salt=crypto.random_bytes(crypto.KDF_SALT_LEN), params=params)


@pytest.fixture
def kdf() -> crypto.KdfParams:
    return cheap_kdf()


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every code path that creates a vault use the cheap parameters."""
    monkeypatch.setattr(crypto, "default_kdf_params", cheap_kdf)
    monkeypatch.setattr(crypto, "calibrate_kdf", lambda seconds=0.75, algo=None: cheap_kdf(algo))


@pytest.fixture
def vault_path(tmp_path) -> str:
    return str(tmp_path / "vault.pmv")
