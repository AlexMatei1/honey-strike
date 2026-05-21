"""Redis pub/sub channel for the dashboard live feed.

The WebSocket `/api/ws/live` used to poll Postgres every couple of seconds
*per connected client* — fine for one operator, but the per-client query load
grows linearly with open tabs (War Room on a wall screen + several laptops).

Instead, the FingerprintWorker publishes one compact JSON message to the
`honeystrike:live` channel the moment a session is scored, and every
WebSocket connection just subscribes. Fan-out is O(1) DB work regardless of
how many clients are watching — Redis handles the duplication.

The message shape matches what the dashboard JS already consumes, so the map,
sidebar, War Room ticker, threat border, and defend arena all keep working
unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis

LIVE_CHANNEL = "honeystrike:live"


async def publish_live(redis: aioredis.Redis, message: dict[str, Any]) -> None:
    """Publish one live-session message. Never raises into the caller — a
    pub/sub hiccup must not break enrichment."""
    try:
        await redis.publish(LIVE_CHANNEL, json.dumps(message, separators=(",", ":")))
    except Exception:       # noqa: BLE001 — best-effort, swallow
        pass
