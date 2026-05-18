"""Redis-backed IP block list used by the multiplayer game's defender side.

Defender labels a TTP correctly → `defender.label` calls `block(ip)` → every
honeypot listener calls `is_blocked(ip)` at connection-accept time and
refuses connections from blocked IPs until TTL expires.

Design choices:
  - **One Redis key per IP** (`honeypot:blocked:{ip}`) with `EXPIRE` — Redis
    handles TTL natively, no janitor needed.
  - **Idempotent**: re-blocking refreshes the TTL.
  - **Fail-open**: any Redis error returns False from `is_blocked()` so a
    transient Redis outage doesn't take honeypots offline.

Used by:
  - `services/ssh/__main__.py` — accept-loop guard.
  - `services/http/server.py` — FastAPI middleware.
  - `services/ftp/handler.py` — `on_connect` hook.
  - `services/rdp/__main__.py` — accept-loop guard.
  - `services/tls_sniffer/__main__.py` — accept-loop guard.
  - `api/routers/defender.py` — `POST /api/defender/block`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from honeystrike.core.logging import get_logger

if TYPE_CHECKING:                                          # pragma: no cover
    import redis.asyncio as aioredis

log = get_logger(__name__)

KEY_PREFIX = "honeypot:blocked"
DEFAULT_TTL_SECONDS = 300


def _key(ip: str) -> str:
    return f"{KEY_PREFIX}:{ip}"


async def add(
    redis_client: "aioredis.Redis",
    ip: str,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    reason: str | None = None,
) -> None:
    """Add `ip` to the block list with `ttl_seconds` lifetime."""
    try:
        await redis_client.set(_key(ip), reason or "blocked", ex=ttl_seconds)
        log.info("blocklist.added", ip=ip, ttl_seconds=ttl_seconds, reason=reason)
    except Exception as exc:                                # noqa: BLE001
        log.warning("blocklist.add_failed", ip=ip, error=str(exc))


async def remove(redis_client: "aioredis.Redis", ip: str) -> None:
    try:
        await redis_client.delete(_key(ip))
        log.info("blocklist.removed", ip=ip)
    except Exception as exc:                                # noqa: BLE001
        log.warning("blocklist.remove_failed", ip=ip, error=str(exc))


async def is_blocked(redis_client: "aioredis.Redis", ip: str) -> bool:
    """Fail-open lookup. Returns False on Redis errors so honeypot accept-loops
    don't go offline when Redis hiccups."""
    try:
        return bool(await redis_client.exists(_key(ip)))
    except Exception as exc:                                # noqa: BLE001
        log.warning("blocklist.check_failed", ip=ip, error=str(exc))
        return False


async def ttl(redis_client: "aioredis.Redis", ip: str) -> int | None:
    """Seconds remaining on the block, or None if not blocked / no TTL."""
    try:
        value = await redis_client.ttl(_key(ip))
    except Exception:                                       # noqa: BLE001
        return None
    return int(value) if value and value > 0 else None
