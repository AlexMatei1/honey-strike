"""Health endpoint — public, no auth required.

Probes the DB and Redis dependencies so an external monitor can distinguish
"process up" from "fully wired". Returns 200 even when a dependency is
degraded; the JSON body reflects which one is unhealthy. A separate liveness
endpoint that returns 503 lives in Phase 5 hardening if needed.
"""

from __future__ import annotations

from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import get_db
from honeystrike.api.schemas import HealthOut
from honeystrike.config import get_settings

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("", response_model=HealthOut)
async def health(db: Annotated[AsyncSession, Depends(get_db)]) -> HealthOut:
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:           # noqa: BLE001
        db_status = "down"

    redis_status = "ok"
    try:
        client = aioredis.from_url(get_settings().redis_url)
        try:
            await client.ping()
        finally:
            await client.aclose()
    except Exception:           # noqa: BLE001
        redis_status = "down"

    return HealthOut(
        status="ok" if db_status == "ok" and redis_status == "ok" else "degraded",
        version="0.1.0",
        db=db_status,
        redis=redis_status,
    )
