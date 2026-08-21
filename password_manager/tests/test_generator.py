"""Random generation: policy guarantees, entropy accounting, word list quality."""

from __future__ import annotations

import math
import re
from collections import Counter

import pytest

from pwman import generator
from pwman.errors import PwmanError


def test_generated_password_matches_the_policy():
    policy = generator.Policy(length=24)
    for _ in range(50):
        password = generator.generate_password(policy)
        assert len(password) == 24
        assert any(c in generator.LOWER for c in password)
        assert any(c in generator.UPPER for c in password)
        assert any(c in generator.DIGITS for c in password)
        assert any(c in generator.SYMBOLS for c in password)


def test_disabled_classes_never_appear():
    policy = generator.Policy(length=32, symbols=False, digits=False)
    for _ in range(20):
        password = generator.generate_password(policy)
        assert re.fullmatch(r"[A-Za-z]{32}", password)


def test_readable_mode_avoids_lookalikes():
    policy = generator.Policy(length=64, avoid_ambiguous=True)
    for _ in range(10):
        assert not set(generator.generate_password(policy)) & set(generator.AMBIGUOUS)


def test_passwords_do_not_repeat():
    passwords = {generator.generate_password(generator.Policy(length=16)) for _ in range(500)}
    assert len(passwords) == 500


def test_characters_are_close_to_uniform():
    """A biased generator (e.g. modulo bias, or padding fixed positions) fails this."""
    policy = generator.Policy(length=32, symbols=False)
    counts = Counter("".join(generator.generate_password(policy) for _ in range(400)))
    alphabet = policy.alphabet()
    expected = 400 * 32 / len(alphabet)
    assert set(counts) <= set(alphabet)
    for char in alphabet:
        assert 0.6 * expected < counts[char] < 1.4 * expected, char


def test_first_and_last_positions_are_not_special():
    """Naive implementations force a symbol into the last slot -- this catches that."""
    policy = generator.Policy(length=12)
    first = Counter(generator.generate_password(policy)[0] for _ in range(400))
    last = Counter(generator.generate_password(policy)[-1] for _ in range(400))
    assert len([c for c in first if c in generator.SYMBOLS]) > 3
    assert len([c for c in last if c in generator.LOWER]) > 3


def test_entropy_matches_a_brute_force_count(monkeypatch):
    """Check the inclusion-exclusion maths against an exhaustive enumeration.

    The alphabet is shrunk to four characters so every possible password can
    actually be counted.
    """
    monkeypatch.setattr(generator, "LOWER", "ab")
    monkeypatch.setattr(generator, "DIGITS", "12")
    policy = generator.Policy(length=4, lower=True, upper=False, digits=True, symbols=False)

    from itertools import product

    acceptable = [
        candidate
        for candidate in product(policy.alphabet(), repeat=4)
        if any(c in "ab" for c in candidate) and any(c in "12" for c in candidate)
    ]
    assert len(acceptable) == 4**4 - 2**4 - 2**4
    assert generator.password_entropy_bits(policy) == pytest.approx(math.log2(len(acceptable)))


def test_entropy_without_class_requirements_is_the_naive_value():
    policy = generator.Policy(length=10, require_each=False)
    assert generator.password_entropy_bits(policy) == pytest.approx(10 * math.log2(len(policy.alphabet())))


def test_requiring_classes_costs_a_little_entropy():
    strict = generator.Policy(length=8)
    loose = generator.Policy(length=8, require_each=False)
    assert generator.password_entropy_bits(strict) < generator.password_entropy_bits(loose)


@pytest.mark.parametrize("policy", [
    generator.Policy(length=2),                                     # too short
    generator.Policy(length=1000),                                  # too long
    generator.Policy(length=3, lower=True, upper=True, digits=True, symbols=True),  # cannot fit all classes
])
def test_impossible_policies_are_rejected(policy):
    with pytest.raises(PwmanError):
        generator.generate_password(policy)


def test_no_character_class_at_all_is_rejected():
    with pytest.raises(PwmanError):
        generator.generate_password(generator.Policy(lower=False, upper=False, digits=False, symbols=False))


# --------------------------------------------------------------------------- #
# Passphrases
# --------------------------------------------------------------------------- #

def test_bundled_wordlist_is_exactly_a_power_of_two():
    words = generator.load_wordlist()
    assert len(words) == 1024, "10 bits per word depends on exactly 1024 entries"
    assert len(set(words)) == 1024
    assert all(re.fullmatch(r"[a-z]{4,8}", word) for word in words)
    assert len({word[:3] for word in words}) == 1024, "3-character prefixes must stay unique"


def test_passphrase_shape_and_entropy():
    phrase = generator.generate_passphrase(6)
    assert len(phrase.split("-")) == 6
    assert generator.passphrase_entropy_bits(6) == pytest.approx(60.0)
    assert generator.passphrase_entropy_bits(6, add_digit=True) == pytest.approx(60 + math.log2(100))


def test_passphrase_options():
    phrase = generator.generate_passphrase(4, separator=" ", capitalize=True, add_digit=True)
    words = phrase.split(" ")
    assert len(words) == 5
    assert all(word[0].isupper() for word in words[:4])
    assert words[-1].isdigit()


def test_passphrase_words_are_drawn_independently():
    phrases = [generator.generate_passphrase(4) for _ in range(300)]
    assert len(set(phrases)) == 300
    positions = [Counter(p.split("-")[i] for p in phrases) for i in range(4)]
    for counter in positions:
        assert len(counter) > 150, "a position with few distinct words suggests a broken draw"


@pytest.mark.parametrize("words", [0, 2, 100])
def test_silly_passphrase_lengths_are_rejected(words):
    with pytest.raises(PwmanError):
        generator.generate_passphrase(words)
