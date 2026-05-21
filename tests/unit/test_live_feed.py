"""Unit tests for the live-feed pub/sub helper."""

from __future__ import annotations

import json

import pytest

from honeystrike.core import live_feed


class _FakeRedis:
    def __init__(self, *, raise_on_publish: bool = False) -> None:
        self.published: list[tuple[str, str]] = []
        self._raise = raise_on_publish

    async def publish(self, channel: str, message: str) -> int:
        if self._raise:
            raise ConnectionError("redis down")
        self.published.append((channel, message))
        return 1


@pytest.mark.asyncio
async def test_publish_live_sends_json_to_channel() -> None:
    r = _FakeRedis()
    msg = {"type": "session", "service": "ssh", "threat_score": 82}
    await live_feed.publish_live(r, msg)
    assert len(r.published) == 1
    channel, payload = r.published[0]
    assert channel == live_feed.LIVE_CHANNEL
    assert json.loads(payload) == msg


@pytest.mark.asyncio
async def test_publish_live_swallows_redis_errors() -> None:
    # A pub/sub hiccup must never propagate into the enrichment path.
    r = _FakeRedis(raise_on_publish=True)
    await live_feed.publish_live(r, {"type": "session"})   # must not raise
