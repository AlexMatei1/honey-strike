"""Tests for the MaxMind geo enrichment module.

We never ship the `.mmdb` files in the repo, so the readers are mocked. The
cache layer is exercised against a real Redis (already required by other
integration-flavoured unit tests).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from unittest.mock import MagicMock

import geoip2.errors
import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from honeystrike.workers.intel.geo import GeoEnricher, GeoRecord

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[aioredis.Redis]:
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


def _make_enricher(redis_client: aioredis.Redis, *, ready: bool = True) -> GeoEnricher:
    prefix = f"test:geo:{uuid.uuid4().hex}"
    enricher = GeoEnricher(
        redis_client=redis_client,
        city_db_path="/no/such/city.mmdb",
        asn_db_path="/no/such/asn.mmdb",
        ttl_seconds=60,
        cache_key_prefix=prefix,
    )
    if ready:
        # Assign mock readers — `is_ready` returns True whenever both are set.
        enricher._city_reader = MagicMock()  # noqa: SLF001 — test patching
        enricher._asn_reader = MagicMock()   # noqa: SLF001
    return enricher


@pytest.mark.asyncio
async def test_geo_lookup_caches_and_returns_record(
    redis_client: aioredis.Redis,
) -> None:
    enricher = _make_enricher(redis_client)
    city_mock = enricher._city_reader  # noqa: SLF001
    asn_mock = enricher._asn_reader     # noqa: SLF001

    city_response = MagicMock()
    city_response.country.iso_code = "RO"
    city_response.country.name = "Romania"
    city_response.city.name = "Bucharest"
    city_response.location.latitude = 44.4268
    city_response.location.longitude = 26.1025
    city_mock.city.return_value = city_response

    asn_response = MagicMock()
    asn_response.autonomous_system_number = 8708
    asn_response.autonomous_system_organization = "RCS & RDS"
    asn_mock.asn.return_value = asn_response

    rec1 = await enricher.lookup("1.2.3.4")
    assert rec1 == GeoRecord(
        ip="1.2.3.4",
        country_iso="RO", country_name="Romania", city="Bucharest",
        lat=44.4268, lon=26.1025, asn=8708, org="RCS & RDS",
    )
    # Second call must come from Redis — readers untouched.
    city_mock.city.reset_mock()
    asn_mock.asn.reset_mock()
    rec2 = await enricher.lookup("1.2.3.4")
    assert rec2 == rec1
    city_mock.city.assert_not_called()
    asn_mock.asn.assert_not_called()


@pytest.mark.asyncio
async def test_geo_unknown_ip_returns_nulls_not_exception(
    redis_client: aioredis.Redis,
) -> None:
    enricher = _make_enricher(redis_client)
    enricher._city_reader.city.side_effect = geoip2.errors.AddressNotFoundError("nope")  # noqa: SLF001
    enricher._asn_reader.asn.side_effect = geoip2.errors.AddressNotFoundError("nope")    # noqa: SLF001

    rec = await enricher.lookup("203.0.113.99")
    assert rec.country_iso is None
    assert rec.asn is None


@pytest.mark.asyncio
async def test_geo_unready_returns_empty_record(
    redis_client: aioredis.Redis,
) -> None:
    enricher = GeoEnricher(
        redis_client=redis_client,
        city_db_path="/no/such/city.mmdb",
        asn_db_path="/no/such/asn.mmdb",
        ttl_seconds=60,
        cache_key_prefix=f"test:geo:{uuid.uuid4().hex}",
    )
    assert enricher.is_ready is False
    rec = await enricher.lookup("8.8.8.8")
    assert rec == GeoRecord(
        ip="8.8.8.8", country_iso=None, country_name=None, city=None,
        lat=None, lon=None, asn=None, org=None,
    )
