"""Optional breach check against Have I Been Pwned, k-anonymity style.

Only the **first five hex characters** of the password's SHA-1 hash leave the
machine.  The service answers with every suffix sharing that prefix (hundreds of
them) and the match is done locally, so the server never learns which password
-- or even which of its own candidates -- was being checked.

This is the single feature in pwman that touches the network, it is off by
default, and it must be requested explicitly with ``--pwned``.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from typing import Callable

from .errors import PwmanError

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "pwman-password-manager"
TIMEOUT = 10

Fetcher = Callable[[str], str]


def _http_fetch(prefix: str) -> str:
    request = urllib.request.Request(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},  # padding hides the true response size
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise PwmanError(f"breach check failed: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise PwmanError(f"breach check failed: {exc}") from None


def prefix_and_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range_response(body: str, suffix: str) -> int:
    """Find our suffix in the ``SUFFIX:COUNT`` list.  0 means "not found"."""
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            try:
                return int(count.replace(",", ""))
            except ValueError:
                return 1
    return 0


def check(password: str, *, fetch: Fetcher | None = None) -> int:
    """Return how often this password appears in known breaches (0 = not found)."""
    if not password:
        return 0
    prefix, suffix = prefix_and_suffix(password)
    body = (fetch or _http_fetch)(prefix)
    return parse_range_response(body, suffix)


def make_cached_checker(fetch: Fetcher | None = None) -> Callable[[str], int]:
    """A checker that fetches each hash prefix at most once per run."""
    cache: dict[str, str] = {}
    fetcher = fetch or _http_fetch

    def checker(password: str) -> int:
        if not password:
            return 0
        prefix, suffix = prefix_and_suffix(password)
        if prefix not in cache:
            cache[prefix] = fetcher(prefix)
        return parse_range_response(cache[prefix], suffix)

    return checker
