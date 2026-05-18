"""AbuseIPDB v2 client — async, rate-limited, Redis-cached, fail-open.

AbuseIPDB free tier is 1000 requests/day. We protect that quota with:

  - A Redis-backed cache (default 6h TTL) keyed by IP.
  - A daily request budget counter; once exhausted we fail-open (return None)
    until UTC midnight rolls over.
  - On any HTTP / network error we ALSO fail-open — enrichment is best-effort.
    The session capture path must never be blocked on a flaky third party.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import redis.asyncio as aioredis

from honeystrike.core.logging import get_logger

log = get_logger(__name__)


_API_URL = "https://api.abuseipdb.com/api/v2/check"


@dataclass(slots=True, frozen=True)
class AbuseRecord:
    """Subset of AbuseIPDB /check that we persist on a fingerprint row."""

    ip: str
    abuse_score: int | None         # 0-100
    total_reports: int | None
    last_reported_at: str | None    # ISO 8601, kept as string for portability
    country_code: str | None        # AbuseIPDB also returns geo; we keep it for crosscheck
    usage_type: str | None
    is_whitelisted: bool | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AbuseIPDBClient:
    """Async client with rate-limit + cache. Use one instance per worker process."""

    CACHE_TTL_DEFAULT = 6 * 3600       # 6h per docs/01 §M2
    DAILY_QUOTA_DEFAULT = 1000          # free-tier cap

    CACHE_KEY_PREFIX = "abuseipdb"
    QUOTA_KEY_PREFIX = "abuseipdb:quota"

    def __init__(
        self,
        *,
        api_key: str,
        redis_client: aioredis.Redis,
        http_client: httpx.AsyncClient | None = None,
        cache_ttl_seconds: int = CACHE_TTL_DEFAULT,
        daily_quota: int = DAILY_QUOTA_DEFAULT,
        cache_key_prefix: str = CACHE_KEY_PREFIX,
        quota_key_prefix: str = QUOTA_KEY_PREFIX,
        request_timeout: float = 5.0,
    ) -> None:
        self._api_key = api_key
        self._redis = redis_client
        self._http = http_client or httpx.AsyncClient(timeout=request_timeout)
        self._owns_http = http_client is None
        self._cache_ttl = cache_ttl_seconds
        self._daily_quota = daily_quota
        self._cache_prefix = cache_key_prefix
        self._quota_prefix = quota_key_prefix

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # ----- public API ------------------------------------------------------

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def check(self, ip: str) -> AbuseRecord | None:
        """Return a cached or fresh AbuseIPDB record for `ip`, or None.

        None is returned when:
          - the client has no API key (caller never configured one)
          - the daily quota has been reached
          - the HTTP request fails for any reason
        Callers MUST treat None as "no data available" and continue.
        """
        if not self.is_configured:
            return None

        cached = await self._cache_get(ip)
        if cached is not None:
            return cached

        if not await self._quota_reserve():
            log.info("abuseipdb.quota_exhausted", ip=ip)
            return None

        record = await self._fetch(ip)
        if record is not None:
            await self._cache_set(ip, record)
        return record

    # ----- internals -------------------------------------------------------

    async def _fetch(self, ip: str) -> AbuseRecord | None:
        try:
            resp = await self._http.get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
        except httpx.RequestError as exc:
            log.warning("abuseipdb.network_error", ip=ip, error=str(exc))
            return None

        if resp.status_code == 429:
            log.warning("abuseipdb.rate_limited_by_server", ip=ip)
            return None
        if resp.status_code >= 400:
            log.warning(
                "abuseipdb.http_error",
                ip=ip,
                status=resp.status_code,
                body=resp.text[:200],
            )
            return None

        try:
            data = resp.json().get("data") or {}
        except json.JSONDecodeError as exc:
            log.warning("abuseipdb.bad_json", ip=ip, error=str(exc))
            return None

        return AbuseRecord(
            ip=ip,
            abuse_score=_int_or_none(data.get("abuseConfidenceScore")),
            total_reports=_int_or_none(data.get("totalReports")),
            last_reported_at=data.get("lastReportedAt"),
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            is_whitelisted=data.get("isWhitelisted"),
        )

    def _cache_key(self, ip: str) -> str:
        return f"{self._cache_prefix}:{ip}"

    def _quota_key(self) -> str:
        # UTC day bucket so the counter naturally resets at midnight.
        today = datetime.now(UTC).strftime("%Y%m%d")
        return f"{self._quota_prefix}:{today}"

    async def _cache_get(self, ip: str) -> AbuseRecord | None:
        try:
            raw = await self._redis.get(self._cache_key(ip))
        except Exception as exc:
            log.warning("abuseipdb.cache_get_failed", ip=ip, error=str(exc))
            return None
        if not raw:
            return None
        try:
            return AbuseRecord(**json.loads(raw))
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("abuseipdb.cache_decode_failed", ip=ip, error=str(exc))
            return None

    async def _cache_set(self, ip: str, record: AbuseRecord) -> None:
        try:
            await self._redis.set(
                self._cache_key(ip),
                json.dumps(record.to_dict()),
                ex=self._cache_ttl,
            )
        except Exception as exc:
            log.warning("abuseipdb.cache_set_failed", ip=ip, error=str(exc))

    async def _quota_reserve(self) -> bool:
        """Atomically increment + check the daily counter. False = exhausted."""
        key = self._quota_key()
        try:
            pipe = self._redis.pipeline(transaction=False)
            pipe.incr(key)
            # Expire 25h from first set so we have a safety margin past UTC midnight.
            pipe.expire(key, 90_000)
            results = await pipe.execute()
            count = int(results[0])
        except Exception as exc:
            log.warning("abuseipdb.quota_failed", error=str(exc))
            # Fail-open on quota tracker failure — don't lose enrichment because
            # Redis hiccupped. The cache TTL still limits real calls.
            return True
        return count <= self._daily_quota


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
