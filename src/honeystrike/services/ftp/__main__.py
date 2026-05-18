"""FTP honeypot listener.

pyftpdlib's `FTPServer` is asyncore-based and blocks. We run it in a worker
thread, exposing a tiny asyncio-compatible bridge so the handler can persist
events on the main event loop (where the DB engine + Redis client live).
"""

from __future__ import annotations

import asyncio
import os
import threading
import uuid
from typing import Any

from pyftpdlib.servers import FTPServer

from honeystrike.config import get_settings
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.session_manager import SessionManager
from honeystrike.services.ftp.handler import configure_handler_class

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("FTP_LISTEN_PORT", "21"))

log = get_logger("honeystrike.services.ftp")


async def _open_session(
    src_ip: str, src_port: int, bus: EventBus
) -> uuid.UUID:
    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        return await mgr.open(
            service=Service.FTP,
            src_ip=src_ip,
            src_port=src_port,
            local_port=LISTEN_PORT,
        )


async def _close_session(
    *,
    session_id: uuid.UUID,
    service: Service,
    src_ip: str,
    src_port: int,
    event_count: int,
    duration_ms: int,
    close_reason: str,
    bus: EventBus,
) -> None:
    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        await mgr.close(
            session_id=session_id,
            service=service,
            src_ip=src_ip,
            src_port=src_port,
            event_count=event_count,
            duration_ms=duration_ms,
            close_reason=close_reason,
        )


async def _record_event(
    *,
    session_id: uuid.UUID,
    event_type: EventType,
    service: Service,
    src_ip: str,
    src_port: int,
    payload: dict[str, Any],
    bus: EventBus,
) -> None:
    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        await mgr.record_event(
            session_id=session_id,
            event_type=event_type,
            service=service,
            src_ip=src_ip,
            src_port=src_port,
            payload=payload,
        )


async def main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    loop = asyncio.get_running_loop()
    banner = os.getenv("FTP_BANNER", "220 FTP server ready.")

    # The handler module needs to call back into the asyncio loop, so close
    # over `bus` here and forward to the SessionManager helpers above.
    async def open_cb(src_ip: str, src_port: int) -> uuid.UUID:
        return await _open_session(src_ip, src_port, bus)

    async def close_cb(**kw: Any) -> None:
        await _close_session(bus=bus, **kw)

    async def record_cb(**kw: Any) -> None:
        await _record_event(bus=bus, **kw)

    handler_cls = configure_handler_class(
        bus=bus,
        asyncio_loop=loop,
        local_port=LISTEN_PORT,
        session_open_cb=open_cb,
        session_close_cb=close_cb,
        record_event_cb=record_cb,
        banner=banner,
    )

    # Pin passive port range so pyftpdlib doesn't pick arbitrary ports.
    # The data ports are *not* exposed to the host — transfers will fail at
    # the data-channel stage, which is fine: we already captured the command.
    pasv_from = int(os.getenv("FTP_PASSIVE_PORT_FROM", "30000"))
    pasv_to = int(os.getenv("FTP_PASSIVE_PORT_TO", "30009"))
    handler_cls.passive_ports = range(pasv_from, pasv_to + 1)

    server = FTPServer((LISTEN_HOST, LISTEN_PORT), handler_cls)
    server.max_cons = 256
    server.max_cons_per_ip = 32

    log.info("ftp.listening", host=LISTEN_HOST, port=LISTEN_PORT, banner=banner)

    stop_event = asyncio.Event()

    def _serve_forever() -> None:
        try:
            server.serve_forever(timeout=1, blocking=False)
            # `blocking=False` returns immediately; loop until stopped.
            while not stop_event.is_set():
                server.serve_forever(timeout=1, blocking=False)
        except Exception as exc:
            log.error("ftp.server_error", error=str(exc))

    thread = threading.Thread(
        target=_serve_forever, daemon=True, name="ftp-server"
    )
    thread.start()

    try:
        await stop_event.wait()
    finally:
        server.close_all()
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
