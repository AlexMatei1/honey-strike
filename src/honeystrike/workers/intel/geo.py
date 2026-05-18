"""MaxMind GeoLite2 enrichment with Redis caching.

Reads two local `.mmdb` databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`),
caches resolved records in Redis for 24h, and exposes a typed result.

The MaxMind files are NOT committed to the repo. Operators populate the
volume via `maxmindinc/geoipupdate` (see `infra/update_maxmind.sh`); workers
gracefully degrade if the files are absent (`GeoEnricher.is_ready` is False).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import geoip2.database
import geoip2.errors
import redis.asyncio as aioredis

from honeystrike.core.logging import get_logger

log = get_logger(__name__)


@dataclass(slots=True, frozen=True)
class GeoRecord:
    """Resolved geolocation + ASN. Fields can be None if MaxMind has no data."""

    ip: str
    country_iso: str | None
    country_name: str | None
    city: str | None
    lat: float | None
    lon: float | None
    asn: int | None
    org: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GeoEnricher:
    """Async-friendly wrapper around blocking MaxMind readers + Redis cache.

    The MaxMind readers are stdlib-style sync objects; we run lookups inside
    `asyncio.to_thread` so the event loop isn't blocked on disk seeks.
    """

    CACHE_TTL_DEFAULT = 24 * 3600
    CACHE_KEY_PREFIX = "geo"

    def __init__(
        self,
        *,
        redis_client: aioredis.Redis,
        city_db_path: str,
        asn_db_path: str,
        ttl_seconds: int = CACHE_TTL_DEFAULT,
        cache_key_prefix: str = CACHE_KEY_PREFIX,
    ) -> None:
        self._redis = redis_client
        self._city_path = Path(city_db_path)
        self._asn_path = Path(asn_db_path)
        self._ttl = ttl_seconds
        self._prefix = cache_key_prefix
        self._city_reader: geoip2.database.Reader | None = None
        self._asn_reader: geoip2.database.Reader | None = None

    # ----- lifecycle -------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """True once both MaxMind readers are loaded.

        Lazily loads from disk on the first read so callers don't have to
        remember to call `open()`. Returns False if either .mmdb is missing.
        """
        if self._city_reader is not None and self._asn_reader is not None:
            return True
        if self._city_path.is_file() and self._asn_path.is_file():
            self.open()
            return self._city_reader is not None and self._asn_reader is not None
        return False

    def open(self) -> None:
        """Open the readers. Idempotent. Silently no-ops if the dbs are missing."""
        if not (self._city_path.is_file() and self._asn_path.is_file()):
            log.warning(
                "geo.databases_missing",
                city_path=str(self._city_path),
                asn_path=str(self._asn_path),
            )
            return
        if self._city_reader is None:
            self._city_reader = geoip2.database.Reader(str(self._city_path))
        if self._asn_reader is None:
            self._asn_reader = geoip2.database.Reader(str(self._asn_path))
        log.info("geo.readers_opened")

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                reader.close()
        self._city_reader = None
        self._asn_reader = None

    # ----- public API ------------------------------------------------------

    async def lookup(self, ip: str) -> GeoRecord:
        """Resolve an IP. Cache-through; returns an all-None record on miss."""
        cached = await self._cache_get(ip)
        if cached is not None:
            return cached

        if not self.is_ready:
            return GeoRecord(ip=ip, country_iso=None, country_name=None, city=None,
                             lat=None, lon=None, asn=None, org=None)

        if self._city_reader is None or self._asn_reader is None:
            self.open()

        record = await asyncio.to_thread(self._blocking_lookup, ip)
        await self._cache_set(ip, record)
        return record

    # ----- internals -------------------------------------------------------

    def _blocking_lookup(self, ip: str) -> GeoRecord:
        country_iso = country_name = city = None
        lat = lon = None
        asn = None
        org = None

        try:
            assert self._city_reader is not None  # noqa: S101 — guarded above
            r = self._city_reader.city(ip)
            country_iso = r.country.iso_code
            country_name = r.country.name
            city = r.city.name
            lat = float(r.location.latitude) if r.location.latitude is not None else None
            lon = float(r.location.longitude) if r.location.longitude is not None else None
        except geoip2.errors.AddressNotFoundError:
            pass
        except (ValueError, OSError) as exc:
            log.warning("geo.city_lookup_failed", ip=ip, error=str(exc))

        try:
            assert self._asn_reader is not None  # noqa: S101 — guarded above
            r_asn = self._asn_reader.asn(ip)
            asn = int(r_asn.autonomous_system_number) if r_asn.autonomous_system_number else None
            org = r_asn.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            pass
        except (ValueError, OSError) as exc:
            log.warning("geo.asn_lookup_failed", ip=ip, error=str(exc))

        return GeoRecord(
            ip=ip,
            country_iso=country_iso,
            country_name=country_name,
            city=city,
            lat=lat,
            lon=lon,
            asn=asn,
            org=org,
        )

    def _key(self, ip: str) -> str:
        return f"{self._prefix}:{ip}"

    async def _cache_get(self, ip: str) -> GeoRecord | None:
        try:
            raw = await self._redis.get(self._key(ip))
        except Exception as exc:
            log.warning("geo.cache_get_failed", ip=ip, error=str(exc))
            return None
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return GeoRecord(**data)
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("geo.cache_decode_failed", ip=ip, error=str(exc))
            return None

    async def _cache_set(self, ip: str, record: GeoRecord) -> None:
        try:
            await self._redis.set(
                self._key(ip),
                json.dumps(record.to_dict()),
                ex=self._ttl,
            )
        except Exception as exc:
            log.warning("geo.cache_set_failed", ip=ip, error=str(exc))
