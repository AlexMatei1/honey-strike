"""Per-IP SSH authentication attempt counter (Redis-backed).

Real scanners (Hydra, Medusa, Nmap brute auxiliaries) typically open one TCP
connection per credential. A per-connection counter never trips for them.
We track attempts in Redis keyed by source IP with a sliding TTL so the
threshold can fire across many short-lived connections.

Key shape:   `ssh:attempts:{src_ip}`
Value:       integer count
TTL:         refreshed on every increment; defaults to 1 hour

The counter is intentionally simple — no expiry-based decay, no per-bucket
buckets. After the TTL elapses with no activity from the IP, the counter
resets. By then the attacker has either succeeded into the fake shell or
moved on, and a fresh threshold for repeat visitors is desirable.
"""

from __future__ import annotations

from typing import Protocol

import redis.asyncio as aioredis


class AttemptCheck(Protocol):
    """Callable contract the Paramiko ServerInterface depends on.

    Called once per auth attempt with the source IP. Returns
    `(cumulative_count, should_grant)`. The caller decides what to do with
    `should_grant` — typically: return AUTH_SUCCESSFUL and flip the shell flag.
    """

    def __call__(self, src_ip: str) -> tuple[int, bool]: ...


class IPAttemptCounter:
    """Async Redis helper. Wrap with a sync adapter for the Paramiko thread."""

    DEFAULT_TTL_SECONDS = 3600  # 1h sliding window

    def __init__(
        self,
        client: aioredis.Redis,
        *,
        threshold: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        key_prefix: str = "ssh:attempts",
    ) -> None:
        self._client = client
        self._threshold = max(1, threshold)
        self._ttl = ttl_seconds
        self._prefix = key_prefix

    def _key(self, src_ip: str) -> str:
        return f"{self._prefix}:{src_ip}"

    async def increment_and_check(self, src_ip: str) -> tuple[int, bool]:
        """INCR + EXPIRE in one round-trip; return (count, grant_now)."""
        key = self._key(src_ip)
        pipe = self._client.pipeline(transaction=False)
        pipe.incr(key)
        pipe.expire(key, self._ttl)
        results = await pipe.execute()
        count = int(results[0])
        return count, count >= self._threshold

    async def reset(self, src_ip: str) -> None:
        """Clear the counter for a given IP (used by tests and ops tooling)."""
        await self._client.delete(self._key(src_ip))
