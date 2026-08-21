"""Password strength estimation and vault auditing.

The estimator is deliberately pessimistic: it computes several ways an attacker
could describe a password (raw character search, word segmentation, a list of
known-common passwords, a repeated block) and reports the *cheapest* one.  A
generated 20 character password comes out near its true entropy, while
"Passw0rd!" and "correct-horse" come out for what they are.

This is a heuristic, not a proof -- see SECURITY.md.  It is used for guidance in
`pwman audit`, never to gate anything cryptographic.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Iterable

from .generator import DIGITS, LOWER, SYMBOLS, UPPER, load_wordlist

COMMON_WORDS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common_words.txt")

# Separators an attacker tries first when a password looks like joined words.
SEPARATORS = "-_. ,+/&@!*#"
from .vault import Entry, Vault, age_days

# The passwords every credential-stuffing list starts with.  Order is roughly by
# frequency, which is what makes a rank-based estimate meaningful.
COMMON_PASSWORDS = (
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567", "111111", "123123",
    "abc123", "1234567890", "1234", "password1", "iloveyou", "000000", "qwerty123", "dragon", "monkey",
    "letmein", "sunshine", "princess", "football", "welcome", "admin", "login", "master", "hello",
    "freedom", "whatever", "trustno1", "starwars", "passw0rd", "zaq12wsx", "qazwsx", "asdfgh", "shadow",
    "superman", "batman", "michael", "jordan", "harley", "ranger", "hunter", "buster", "soccer",
    "baseball", "killer", "mustang", "access", "flower", "matrix", "secret", "summer", "ashley",
    "bailey", "charlie", "daniel", "jessica", "pepper", "chelsea", "diamond", "yankees", "thunder",
    "taylor", "matthew", "andrew", "joshua", "amanda", "orange", "biteme", "banana", "cookie",
    "computer", "internet", "samsung", "google", "facebook", "linkedin", "myspace", "hottie", "loveme",
    "zxcvbnm", "asdfghjkl", "qwertyuiop", "1q2w3e4r", "1qaz2wsx", "q1w2e3r4", "aa123456", "abcd1234",
    "test", "guest", "root", "toor", "changeme", "default", "temp", "demo", "pass", "secret123",
    "letmein123", "welcome1", "admin123", "root123", "p@ssw0rd", "qwe123", "121212", "654321",
    "666666", "888888", "987654321", "112233", "159753", "7777777", "trustme", "iloveu", "lovely",
)
COMMON_INDEX = {p: i for i, p in enumerate(COMMON_PASSWORDS)}

LEET = str.maketrans({"4": "a", "@": "a", "8": "b", "3": "e", "6": "g", "1": "l", "!": "i", "0": "o",
                      "5": "s", "$": "s", "7": "t", "+": "t", "2": "z"})

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "azertyuiop", "qwertzuiop")

# Guess rates for the "how long would this take" line.  The fast figure assumes
# a leaked *fast* hash (single SHA-256/NTLM) on rented GPUs; the vault figure is
# what our own Argon2id parameters cost an attacker.
GUESSES_PER_SECOND_FAST = 1e11
GUESSES_PER_SECOND_VAULT = 1e4

LABELS = ((28, "very weak"), (40, "weak"), (60, "fair"), (80, "strong"), (float("inf"), "excellent"))


@dataclass(frozen=True)
class Strength:
    bits: float
    label: str
    warnings: tuple[str, ...] = ()

    def crack_time_fast(self) -> str:
        return format_duration(guesses(self.bits) / GUESSES_PER_SECOND_FAST)

    def crack_time_vault(self) -> str:
        return format_duration(guesses(self.bits) / GUESSES_PER_SECOND_VAULT)


def guesses(bits: float) -> float:
    """Expected guesses to find a secret with ``bits`` of entropy (half the space)."""
    try:
        return 2 ** min(bits, 1024.0) / 2
    except OverflowError:  # pragma: no cover
        return float("inf")


def format_duration(seconds: float) -> str:
    if seconds != seconds or seconds == float("inf"):  # NaN or inf
        return "longer than the age of the universe"
    units = (
        (1, "second"), (60, "minute"), (3600, "hour"), (86400, "day"),
        (86400 * 30, "month"), (86400 * 365, "year"), (86400 * 365 * 1000, "millennium"),
    )
    if seconds < 1:
        return "instantly"
    if seconds > 86400 * 365 * 1e9:
        return "longer than the age of the universe"
    label, size = "second", 1
    for size_candidate, label_candidate in units:
        if seconds >= size_candidate:
            size, label = size_candidate, label_candidate
    value = seconds / size
    plural = "" if 0.95 <= value < 1.05 else "s"
    if label == "millennium":
        return f"{value:,.0f} millennia"
    return f"{value:,.1f} {label}{plural}" if value < 10 else f"{value:,.0f} {label}{plural}"


def charset_size(password: str) -> int:
    """Size of the alphabet an attacker would have to search for this password."""
    size = 0
    if any(c in LOWER for c in password):
        size += 26
    if any(c in UPPER for c in password):
        size += 26
    if any(c in DIGITS for c in password):
        size += 10
    if any(c in SYMBOLS for c in password):
        size += len(SYMBOLS)
    extra = {c for c in password if c not in LOWER + UPPER + DIGITS + SYMBOLS}
    size += len(extra) if extra else 0
    return max(size, 1)


@lru_cache(maxsize=1)
def _dictionary() -> dict[str, float]:
    """Token -> cost in bits for the segmentation estimate.

    The list is intentionally larger than the passphrase word list: an attacker
    guessing word-based passwords uses a big dictionary, so pricing words with a
    small one would flatter every passphrase.
    """
    try:
        with open(COMMON_WORDS_PATH, "r", encoding="ascii") as handle:
            words = [line.strip() for line in handle if line.strip()]
    except OSError:  # pragma: no cover - the file ships with the package
        words = list(load_wordlist())
    cost = math.log2(max(len(words), 2))
    entries = {w: cost for w in words}
    for word, rank in COMMON_INDEX.items():
        entries[word] = min(entries.get(word, 99.0), math.log2(rank + 2))
    for separator in SEPARATORS:
        entries[separator] = math.log2(len(SEPARATORS))
    return entries


def _segmentation_bits(password: str) -> float:
    """Cheapest description as a sequence of dictionary words and stray characters.

    Dynamic programming over the password: at each position, either extend by one
    "random" character or consume a known word (also matching leetspeak and case
    variants, which cost a fraction of a bit each).
    """
    lowered = password.lower()
    deleeted = lowered.translate(LEET)
    words = _dictionary()
    char_cost = math.log2(charset_size(password))
    best = [0.0] + [math.inf] * len(password)
    for end in range(1, len(password) + 1):
        best[end] = best[end - 1] + char_cost
        for start in range(max(0, end - 12), end):
            for candidate in (lowered[start:end], deleeted[start:end]):
                cost = words.get(candidate)
                if cost is None:
                    continue
                segment = password[start:end]
                # capitalisation and leet substitution add a little, not a lot
                extra = 1.0 if segment != segment.lower() else 0.0
                extra += 1.0 if candidate == deleeted[start:end] and deleeted[start:end] != lowered[start:end] else 0.0
                best[end] = min(best[end], best[start] + cost + extra)
    return best[len(password)]


def _repeat_bits(password: str) -> float:
    """If the password is a short block repeated, price only the block."""
    length = len(password)
    for block in range(1, length // 2 + 1):
        if length % block == 0 and password[:block] * (length // block) == password:
            return block * math.log2(charset_size(password)) + math.log2(length)
    return math.inf


def _sequence_penalty(password: str) -> list[str]:
    warnings: list[str] = []
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for start in range(len(row) - 3):
            chunk = row[start : start + 4]
            if chunk in lowered or chunk[::-1] in lowered:
                warnings.append("contains a keyboard sequence")
                break
        if warnings:
            break
    runs = 0
    for i in range(len(password) - 2):
        a, b, c = password[i : i + 3]
        if ord(b) - ord(a) == ord(c) - ord(b) and abs(ord(b) - ord(a)) == 1:
            runs += 1
    if runs:
        warnings.append("contains sequential characters (abc / 321)")
    if re.search(r"(19|20)\d\d", password):
        warnings.append("contains something that looks like a year")
    if re.search(r"(.)\1{2,}", password):
        warnings.append("contains a repeated character run")
    return warnings


def estimate(password: str) -> Strength:
    """Estimate the strength of an arbitrary password."""
    if not password:
        return Strength(0.0, "very weak", ("password is empty",))

    lowered = password.lower()
    warnings: list[str] = []
    candidates = [len(password) * math.log2(charset_size(password)), _segmentation_bits(password),
                  _repeat_bits(password)]

    if lowered in COMMON_INDEX:
        candidates.append(math.log2(COMMON_INDEX[lowered] + 2))
        warnings.append("this is one of the most common passwords in existence")
    if lowered.translate(LEET) in COMMON_INDEX:
        warnings.append("this is a common password with characters substituted")

    bits = max(0.0, min(candidates))
    if len(password) < 12:
        warnings.append("shorter than 12 characters")
    if password.isdigit():
        warnings.append("digits only")
    if password.isalpha():
        warnings.append("letters only")
    warnings.extend(_sequence_penalty(password))

    label = next(name for threshold, name in LABELS if bits < threshold)
    return Strength(bits=bits, label=label, warnings=tuple(dict.fromkeys(warnings)))


# --------------------------------------------------------------------------- #
# Vault audit
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Finding:
    entry: str
    kind: str
    severity: str
    detail: str


def _fingerprint(password: str) -> str:
    """Stable, non-reversible key for grouping identical passwords."""
    return hashlib.blake2b(password.encode("utf-8"), digest_size=16).hexdigest()


def audit(
    vault: Vault,
    *,
    weak_bits: float = 60.0,
    old_days: float = 365.0,
    pwned_lookup: Callable[[str], int] | None = None,
) -> list[Finding]:
    """Check every entry for weak, reused, stale or breached passwords.

    ``pwned_lookup`` is optional and only supplied when the user explicitly asks
    for the online breach check; without it the audit is entirely offline.
    """
    findings: list[Finding] = []
    by_password: dict[str, list[Entry]] = {}

    for entry in vault:
        if not entry.password:
            findings.append(Finding(entry.name, "empty", "medium", "entry has no password stored"))
            continue
        by_password.setdefault(_fingerprint(entry.password), []).append(entry)

        strength = estimate(entry.password)
        if strength.bits < weak_bits:
            detail = f"{strength.bits:.0f} bits ({strength.label})"
            if strength.warnings:
                detail += " - " + "; ".join(strength.warnings[:2])
            severity = "critical" if strength.bits < 40 else "high"
            findings.append(Finding(entry.name, "weak", severity, detail))

        age = age_days(entry.password_changed_at)
        if age is not None and age > old_days:
            findings.append(Finding(entry.name, "old", "low", f"unchanged for {age:.0f} days"))

        if any(h.get("password") == entry.password for h in entry.history):
            findings.append(Finding(entry.name, "recycled", "medium", "current password was used before"))

    for group in by_password.values():
        if len(group) > 1:
            for entry in group:
                others = ", ".join(sorted(e.name for e in group if e.id != entry.id))
                findings.append(Finding(entry.name, "reused", "high", f"same password as: {others}"))

    if pwned_lookup is not None:
        for entry in vault:
            if not entry.password:
                continue
            count = pwned_lookup(entry.password)
            if count > 0:
                findings.append(
                    Finding(entry.name, "breached", "critical", f"appears in {count:,} known breach records")
                )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.entry.casefold(), f.kind))
    return findings


def summarise(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.kind] = counts.get(finding.kind, 0) + 1
    return counts
