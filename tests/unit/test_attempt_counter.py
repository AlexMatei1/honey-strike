"""Tests for the Redis-backed per-IP attempt counter."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from honeystrike.services.ssh.attempt_counter import IPAttemptCounter

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[aioredis.Redis]:
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


@pytest.mark.asyncio
async def test_increment_and_check_trips_at_threshold(
    redis_client: aioredis.Redis,
) -> None:
    # Unique key per test run so concurrent tests don't collide.
    prefix = f"test:attempts:{uuid.uuid4().hex}"
    counter = IPAttemptCounter(
        redis_client, threshold=3, key_prefix=prefix, ttl_seconds=30
    )
    ip = "203.0.113.7"

    assert await counter.increment_and_check(ip) == (1, False)
    assert await counter.increment_and_check(ip) == (2, False)
    assert await counter.increment_and_check(ip) == (3, True)
    assert await counter.increment_and_check(ip) == (4, True)

    await counter.reset(ip)
    assert await counter.increment_and_check(ip) == (1, False)


@pytest.mark.asyncio
async def test_separate_ips_have_separate_counters(
    redis_client: aioredis.Redis,
) -> None:
    prefix = f"test:attempts:{uuid.uuid4().hex}"
    counter = IPAttemptCounter(
        redis_client, threshold=2, key_prefix=prefix, ttl_seconds=30
    )

    assert await counter.increment_and_check("1.1.1.1") == (1, False)
    assert await counter.increment_and_check("2.2.2.2") == (1, False)
    assert await counter.increment_and_check("1.1.1.1") == (2, True)
    # IP #2 is still on its own count.
    assert await counter.increment_and_check("2.2.2.2") == (2, True)


@pytest.mark.asyncio
async def test_ttl_is_set_on_first_increment(
    redis_client: aioredis.Redis,
) -> None:
    prefix = f"test:attempts:{uuid.uuid4().hex}"
    counter = IPAttemptCounter(
        redis_client, threshold=100, key_prefix=prefix, ttl_seconds=42
    )
    await counter.increment_and_check("9.9.9.9")
    ttl = await redis_client.ttl(f"{prefix}:9.9.9.9")
    assert 30 <= int(ttl) <= 42
