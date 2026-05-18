"""Tests for the Redis-backed IP blocklist used by the multiplayer game."""

from __future__ import annotations

import pytest

from honeystrike.core import blocklist


class _FakeRedis:
    """In-memory stand-in covering the subset of redis.asyncio used by blocklist."""

    def __init__(self) -> None:
        self.store: dict[str, tuple[str, int | None]] = {}
        self.fail = False

    async def set(self, key, value, ex=None):
        if self.fail:
            raise RuntimeError("redis down")
        self.store[key] = (value, ex)

    async def delete(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        self.store.pop(key, None)

    async def exists(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        return 1 if key in self.store else 0

    async def ttl(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        return self.store.get(key, (None, -2))[1] or -2


@pytest.mark.asyncio
async def test_add_then_is_blocked_returns_true() -> None:
    r = _FakeRedis()
    await blocklist.add(r, "1.2.3.4", ttl_seconds=60, reason="test")
    assert await blocklist.is_blocked(r, "1.2.3.4") is True
    assert await blocklist.is_blocked(r, "5.6.7.8") is False


@pytest.mark.asyncio
async def test_remove_clears_the_block() -> None:
    r = _FakeRedis()
    await blocklist.add(r, "1.2.3.4", ttl_seconds=60)
    await blocklist.remove(r, "1.2.3.4")
    assert await blocklist.is_blocked(r, "1.2.3.4") is False


@pytest.mark.asyncio
async def test_ttl_returned_in_seconds() -> None:
    r = _FakeRedis()
    await blocklist.add(r, "1.2.3.4", ttl_seconds=300)
    ttl = await blocklist.ttl(r, "1.2.3.4")
    assert ttl == 300


@pytest.mark.asyncio
async def test_is_blocked_fails_open_when_redis_breaks() -> None:
    r = _FakeRedis()
    r.fail = True
    # Honeypot accept-time guard MUST NOT take the listener offline on Redis errors.
    assert await blocklist.is_blocked(r, "1.2.3.4") is False


@pytest.mark.asyncio
async def test_add_swallows_redis_errors() -> None:
    r = _FakeRedis()
    r.fail = True
    # Caller shouldn't see the exception — we log + move on.
    await blocklist.add(r, "1.2.3.4", ttl_seconds=10)
