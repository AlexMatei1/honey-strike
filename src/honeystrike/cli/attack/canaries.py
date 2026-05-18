"""CTF canary strings — single source of truth.

These constants are:
  - **Embedded** in the honeypot's fake responses (HTTP /.env, fake SSH `cat`).
  - **Looked for** by `defend flags-found` to spot when an attacker grabbed
    them.
  - **Used** by attacker scenarios to know what to extract during recon.

If you add a new canary, register it in `ALL_CANARIES` and update the
honeypot templates + `defend flags-found`'s filter list.

⚠ These strings are PUBLIC by design — they leak in fake responses. Don't
treat them as secrets. The whole point is to learn what an attacker reads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class Canary:
    """One marker we seed in honeypot output. `pattern` is a precompiled regex
    so payload scans can be done in one pass.

    `trigger_uris` / `trigger_commands` describe what the attacker must
    request / type to receive the canary. The defender's `flags-found`
    command uses these to spot captures (the honeypot records requests, not
    responses — see docs/08), so a captured request to a trigger URI is the
    proxy for "attacker grabbed this canary".
    """
    slug: str
    description: str
    needle: str
    pattern: re.Pattern[str]
    trigger_uris: tuple[str, ...] = ()
    trigger_commands: tuple[str, ...] = ()


def _compile(needle: str) -> re.Pattern[str]:
    return re.compile(re.escape(needle))


# ---- The canary library ---------------------------------------------------
# Deliberately distinctive prefixes so they DON'T look like real credentials
# (operator's wider intel-pipeline tests etc. won't accidentally clobber them).

FAKE_AWS_KEY = Canary(
    slug="aws-key",
    description="Fake AWS access key embedded in HTTP /.env + SSH ~/.aws/credentials.",
    needle="AKIA0HONEYSTRIKECANARY",
    pattern=_compile("AKIA0HONEYSTRIKECANARY"),
    trigger_uris=("/.env",),
    trigger_commands=("cat .aws/credentials", "cat ~/.aws/credentials",
                       "cat /root/.aws/credentials"),
)

FAKE_PASSWD_LINE = Canary(
    slug="passwd",
    description="Canary user line in fake `cat /etc/passwd` output.",
    needle="canary-user:x:9999:9999:HoneyStrike Canary:/home/canary:/bin/bash",
    pattern=_compile("canary-user:x:9999:9999"),
    trigger_commands=("cat /etc/passwd",),
)

FAKE_ADMIN_TOKEN = Canary(
    slug="admin-token",
    description="HTML-comment admin token in fake /admin login page.",
    needle="hs-canary-token-deadbeefcafe",
    pattern=_compile("hs-canary-token-deadbeefcafe"),
    trigger_uris=("/admin", "/administrator", "/login"),
)


ALL_CANARIES: tuple[Canary, ...] = (
    FAKE_AWS_KEY,
    FAKE_PASSWD_LINE,
    FAKE_ADMIN_TOKEN,
)


def contains_canary(text: str | bytes) -> str | None:
    """Return the slug of the canary present in `text`, or None.

    Used by attacker scenarios to spot what they grabbed and by the defender
    to spot what the attacker grabbed.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="ignore")
    for c in ALL_CANARIES:
        if c.pattern.search(text):
            return c.slug
    return None


def all_needles() -> tuple[str, ...]:
    """All literal needles — for SQL `LIKE %needle%` filtering."""
    return tuple(c.needle for c in ALL_CANARIES)
