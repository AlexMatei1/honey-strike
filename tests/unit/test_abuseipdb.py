"""Tests for the AbuseIPDB client.

Uses `httpx.MockTransport` so we never hit the real API. Exercises cache hit,
fresh fetch, daily-quota exhaustion, network error, and HTTP 4xx fail-open.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from honeystrike.workers.intel.abuseipdb import AbuseIPDBClient, AbuseRecord

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[aioredis.Redis]:
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


def _ok_payload(score: int = 88) -> dict:
    return {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": 142,
            "lastReportedAt": "2026-05-15T22:11:00+00:00",
            "countryCode": "CN",
            "usageType": "Data Center/Web Hosting/Transit",
            "isWhitelisted": False,
        }
    }


def _mock_transport(payload: dict, *, status: int = 200) -> httpx.MockTransport:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)
    return httpx.MockTransport(handler)


def _make_client(
    redis_client: aioredis.Redis,
    transport: httpx.MockTransport,
    *,
    api_key: str = "test-key",
    daily_quota: int = 1000,
) -> AbuseIPDBClient:
    return AbuseIPDBClient(
        api_key=api_key,
        redis_client=redis_client,
        http_client=httpx.AsyncClient(transport=transport),
        cache_ttl_seconds=60,
        daily_quota=daily_quota,
        cache_key_prefix=f"test:abuseipdb:{uuid.uuid4().hex}",
        quota_key_prefix=f"test:abuseipdb:quota:{uuid.uuid4().hex}",
    )


@pytest.mark.asyncio
async def test_check_returns_record_and_caches(
    redis_client: aioredis.Redis,
) -> None:
    call_count = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json=_ok_payload(75))

    client = _make_client(redis_client, httpx.MockTransport(handler))
    try:
        r1 = await client.check("1.2.3.4")
        assert r1 == AbuseRecord(
            ip="1.2.3.4", abuse_score=75, total_reports=142,
            last_reported_at="2026-05-15T22:11:00+00:00",
            country_code="CN", usage_type="Data Center/Web Hosting/Transit",
            is_whitelisted=False,
        )
        # Second call hits cache.
        r2 = await client.check("1.2.3.4")
        assert r2 == r1
        assert call_count["n"] == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_check_returns_none_when_unconfigured(
    redis_client: aioredis.Redis,
) -> None:
    client = _make_client(redis_client, _mock_transport({}), api_key="")
    try:
        assert client.is_configured is False
        assert await client.check("1.2.3.4") is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_quota_exhaustion_fails_open(
    redis_client: aioredis.Redis,
) -> None:
    client = _make_client(redis_client, _mock_transport(_ok_payload()), daily_quota=2)
    try:
        assert (await client.check("9.9.9.1")) is not None
        assert (await client.check("9.9.9.2")) is not None
        # Third unique IP exceeds the quota; quota_reserve refuses.
        assert (await client.check("9.9.9.3")) is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_http_4xx_returns_none(redis_client: aioredis.Redis) -> None:
    transport = _mock_transport({"errors": [{"detail": "bad key"}]}, status=401)
    client = _make_client(redis_client, transport)
    try:
        assert await client.check("1.2.3.4") is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_network_error_returns_none(redis_client: aioredis.Redis) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns lookup failed")
    client = _make_client(redis_client, httpx.MockTransport(handler))
    try:
        assert await client.check("1.2.3.4") is None
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_response_with_missing_fields_returns_partial_record(
    redis_client: aioredis.Redis,
) -> None:
    transport = _mock_transport({"data": {"abuseConfidenceScore": 50}})
    client = _make_client(redis_client, transport)
    try:
        r = await client.check("5.5.5.5")
        assert r is not None
        assert r.abuse_score == 50
        assert r.total_reports is None
        assert r.is_whitelisted is None
    finally:
        await client.aclose()
