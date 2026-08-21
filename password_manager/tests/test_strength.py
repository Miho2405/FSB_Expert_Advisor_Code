"""Strength estimation and the vault audit."""

from __future__ import annotations

import pytest

from pwman import generator, strength
from pwman.vault import Entry, Vault


@pytest.mark.parametrize("password", ["123456", "password", "qwerty", "letmein", "admin"])
def test_famous_passwords_are_rated_hopeless(password):
    estimate = strength.estimate(password)
    assert estimate.bits < 20
    assert estimate.label == "very weak"
    assert estimate.crack_time_fast() == "instantly"


@pytest.mark.parametrize("password", ["P@ssw0rd", "Passw0rd", "l3tm31n"])
def test_leetspeak_does_not_rescue_a_common_password(password):
    assert strength.estimate(password).bits < 40


def test_generated_passwords_score_close_to_their_true_entropy():
    policy = generator.Policy(length=20)
    true_bits = generator.password_entropy_bits(policy)
    for _ in range(20):
        estimate = strength.estimate(generator.generate_password(policy))
        assert estimate.bits > true_bits - 25
        assert estimate.label in ("strong", "excellent")


def test_generated_passphrases_are_not_mistaken_for_random_strings():
    """A word-based secret must be priced as words, not as 30 random characters."""
    phrase = generator.generate_passphrase(6)
    estimate = strength.estimate(phrase)
    assert estimate.bits < len(phrase) * 4
    assert estimate.bits > 50


def test_repeated_blocks_are_priced_as_one_block():
    assert strength.estimate("abcabcabcabcabcabc").bits < strength.estimate("abcdefghijklmnopqr").bits


def test_patterns_are_reported():
    warnings = strength.estimate("qwerty1988abc").warnings
    joined = " ".join(warnings)
    assert "keyboard sequence" in joined
    assert "year" in joined
    assert "sequential characters" in joined


def test_empty_password():
    estimate = strength.estimate("")
    assert estimate.bits == 0
    assert "empty" in estimate.warnings[0]


def test_longer_is_stronger():
    policy_short = generator.Policy(length=8)
    policy_long = generator.Policy(length=32)
    short = strength.estimate(generator.generate_password(policy_short)).bits
    long = strength.estimate(generator.generate_password(policy_long)).bits
    assert long > short


@pytest.mark.parametrize("seconds, expected", [(0.4, "instantly"), (90, "1.5 minutes"), (7200, "2.0 hours"),
                                               (86400 * 400, "1.1 years"), (1e30, "longer than the age of the universe")])
def test_duration_formatting(seconds, expected):
    assert strength.format_duration(seconds) == expected


def test_crack_time_reflects_the_hashing_cost():
    estimate = strength.estimate(generator.generate_password(generator.Policy(length=12, symbols=False)))
    assert estimate.crack_time_vault() != estimate.crack_time_fast()


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

def build_vault() -> Vault:
    vault = Vault()
    vault.add(Entry(name="strong", password=generator.generate_password(generator.Policy(length=24))))
    vault.add(Entry(name="weak", password="hunter2"))
    vault.add(Entry(name="reuse-a", password="the-same-password-9876"))
    vault.add(Entry(name="reuse-b", password="the-same-password-9876"))
    vault.add(Entry(name="empty", password=""))
    vault.add(Entry(name="stale", password=generator.generate_password(generator.Policy(length=24)),
                    password_changed_at="2019-01-01T00:00:00+00:00"))
    return vault


def kinds_for(findings, name):
    return {f.kind for f in findings if f.entry == name}


def test_audit_finds_each_class_of_problem():
    findings = strength.audit(build_vault())
    assert kinds_for(findings, "weak") == {"weak"}
    assert "reused" in kinds_for(findings, "reuse-a")
    assert "reused" in kinds_for(findings, "reuse-b")
    assert kinds_for(findings, "empty") == {"empty"}
    assert "old" in kinds_for(findings, "stale")
    assert kinds_for(findings, "strong") == set()


def test_reuse_report_names_the_other_entries_not_itself():
    findings = strength.audit(build_vault())
    detail = next(f.detail for f in findings if f.entry == "reuse-a" and f.kind == "reused")
    assert "reuse-b" in detail
    assert "reuse-a" not in detail


def test_recycling_an_old_password_is_flagged():
    vault = Vault()
    entry = vault.add(Entry(name="x", password="first-password-value"))
    vault.update(entry, password="second-password-value")
    vault.update(entry, password="first-password-value")
    assert "recycled" in kinds_for(strength.audit(vault), "x")


def test_findings_are_sorted_by_severity():
    findings = strength.audit(build_vault())
    ranks = [strength.SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_breach_check_is_only_used_when_supplied():
    vault = Vault()
    vault.add(Entry(name="x", password=generator.generate_password()))
    assert not [f for f in strength.audit(vault) if f.kind == "breached"]

    findings = strength.audit(vault, pwned_lookup=lambda password: 42)
    breached = [f for f in findings if f.kind == "breached"]
    assert breached and "42" in breached[0].detail


def test_audit_thresholds_are_configurable():
    vault = Vault()
    vault.add(Entry(name="x", password="short1!"))
    assert not strength.audit(vault, weak_bits=0, old_days=99999)
    assert strength.audit(vault, weak_bits=200, old_days=99999)


def test_summarise_counts_by_kind():
    counts = strength.summarise(strength.audit(build_vault()))
    assert counts["reused"] == 2
    assert counts["weak"] >= 1
