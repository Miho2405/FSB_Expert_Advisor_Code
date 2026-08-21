"""Generation of passwords and passphrases from the system CSPRNG.

Every choice goes through :mod:`secrets`, which draws from the OS entropy source
and selects uniformly (``secrets.choice`` uses rejection sampling internally, so
there is no modulo bias).  Class requirements ("at least one digit") are honoured
by rejecting whole candidates instead of patching characters into fixed
positions -- patching would collapse entropy at those positions and is why so
many generated passwords end in a predictable "!1".
"""

from __future__ import annotations

import math
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations

from .errors import PwmanError

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
# Punctuation that survives copy/paste, shell quoting and most "special character"
# policies.  Quotes, backslash and space are left out on purpose.
SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
# Glyphs that look alike in common terminal and document fonts.
AMBIGUOUS = "0O1lI5S2Z8B|`'\","

MIN_LENGTH = 4
MAX_LENGTH = 256
DEFAULT_LENGTH = 20
DEFAULT_WORDS = 6

WORDLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")


@dataclass(frozen=True)
class Policy:
    """What a generated password may and must contain."""

    length: int = DEFAULT_LENGTH
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = True
    avoid_ambiguous: bool = False
    require_each: bool = True

    def classes(self) -> list[str]:
        selected = [
            pool
            for enabled, pool in ((self.lower, LOWER), (self.upper, UPPER), (self.digits, DIGITS), (self.symbols, SYMBOLS))
            if enabled
        ]
        if self.avoid_ambiguous:
            selected = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in selected]
        selected = [pool for pool in selected if pool]
        if not selected:
            raise PwmanError("at least one character class must be enabled")
        return selected

    def alphabet(self) -> str:
        return "".join(self.classes())

    def validate(self) -> None:
        if not MIN_LENGTH <= self.length <= MAX_LENGTH:
            raise PwmanError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
        classes = self.classes()
        if self.require_each and self.length < len(classes):
            raise PwmanError(f"length {self.length} cannot contain all {len(classes)} required character classes")


def generate_password(policy: Policy | None = None) -> str:
    """Return a fresh random password satisfying ``policy``."""
    policy = policy or Policy()
    policy.validate()
    classes = policy.classes()
    alphabet = "".join(classes)

    for _ in range(10_000):  # ~impossible to exhaust; guards against a bad policy
        candidate = "".join(secrets.choice(alphabet) for _ in range(policy.length))
        if not policy.require_each or all(any(c in pool for c in candidate) for pool in classes):
            return candidate
    raise PwmanError("could not satisfy the password policy")  # pragma: no cover


def password_entropy_bits(policy: Policy | None = None) -> float:
    """Exact entropy of :func:`generate_password` for this policy, in bits.

    Rejection sampling makes every acceptable string equally likely, so the
    entropy is ``log2(number of acceptable strings)``.  That count comes from
    inclusion-exclusion over the required classes -- a percent or so below the
    naive ``length * log2(alphabet)``, and honest about it.
    """
    policy = policy or Policy()
    policy.validate()
    classes = policy.classes()
    total = sum(len(pool) for pool in classes)
    if not policy.require_each:
        return policy.length * math.log2(total)

    acceptable = 0
    for size in range(len(classes) + 1):
        for excluded in combinations(classes, size):
            remaining = total - sum(len(pool) for pool in excluded)
            acceptable += (-1) ** size * remaining**policy.length
    if acceptable <= 0:  # pragma: no cover - validate() rules this out
        raise PwmanError("policy cannot be satisfied")
    return math.log2(acceptable)


@lru_cache(maxsize=1)
def load_wordlist(path: str | None = None) -> tuple[str, ...]:
    """Load the bundled 1024 word list (10 bits per word, unique 3-char prefixes)."""
    with open(path or WORDLIST_PATH, "r", encoding="ascii") as handle:
        words = tuple(line.strip() for line in handle if line.strip())
    if len(words) < 256:  # pragma: no cover - the bundled file is validated in tests
        raise PwmanError("word list is too small to generate passphrases")
    return words


def generate_passphrase(
    words: int = DEFAULT_WORDS,
    *,
    separator: str = "-",
    capitalize: bool = False,
    add_digit: bool = False,
    wordlist: tuple[str, ...] | None = None,
) -> str:
    """Diceware-style passphrase: ``words`` independent uniform picks."""
    if not 3 <= words <= 32:
        raise PwmanError("passphrase length must be between 3 and 32 words")
    pool = wordlist or load_wordlist()
    chosen = [secrets.choice(pool) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if add_digit:
        phrase += separator + str(secrets.randbelow(100)).zfill(2)
    return phrase


def passphrase_entropy_bits(
    words: int = DEFAULT_WORDS, *, add_digit: bool = False, wordlist: tuple[str, ...] | None = None
) -> float:
    """Entropy of :func:`generate_passphrase`.

    Capitalisation is deliberately not counted: it is applied to every word, so
    an attacker who knows the setting gains nothing.
    """
    pool = wordlist or load_wordlist()
    bits = words * math.log2(len(pool))
    if add_digit:
        bits += math.log2(100)
    return bits
