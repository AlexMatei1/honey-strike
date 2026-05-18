"""HTTP honeypot listener — uvicorn programmatic entry."""

from __future__ import annotations

import asyncio
import os

import uvicorn

from honeystrike.config import get_settings
from honeystrike.core.db import dispose_engine
from honeystrike.core.event_bus import EventBus
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.services.http.server import create_app

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("HTTP_LISTEN_PORT", "80"))

log = get_logger("honeystrike.services.http")


async def main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    app = create_app(bus=bus, local_port=LISTEN_PORT)
    config = uvicorn.Config(
        app,
        host=LISTEN_HOST,
        port=LISTEN_PORT,
        log_level=settings.log_level.lower(),
        access_log=False,                # we log via structlog in the middleware
        server_header=False,             # we set our own "nginx" header
        proxy_headers=False,             # ignore X-Forwarded-For — attacker-controlled
        forwarded_allow_ips="",
    )
    server = uvicorn.Server(config)

    log.info("http.listening", host=LISTEN_HOST, port=LISTEN_PORT)
    try:
        await server.serve()
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
