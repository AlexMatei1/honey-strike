"""SMTP honeypot listener.

Asyncio TCP server on :25. Speaks enough ESMTP to keep open-relay and spam
scanners engaged, recording every command (HELO/EHLO/MAIL/RCPT/AUTH/…) as an
SMTP_COMMAND event. RCPT TO an external domain is flagged as a relay attempt
but always refused (554) — we never actually send mail.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time

from honeystrike.config import get_settings
from honeystrike.core import blocklist
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.session_manager import SessionManager
from honeystrike.services.smtp import protocol as proto

log = get_logger("honeystrike.services.smtp")

LISTEN_HOST = "0.0.0.0"                                    # noqa: S104 — honeypot
LISTEN_PORT = int(os.getenv("SMTP_LISTEN_PORT", "25"))
READ_TIMEOUT = float(os.getenv("SMTP_READ_TIMEOUT_SECONDS", "30.0"))
MAX_COMMANDS = int(os.getenv("SMTP_MAX_COMMANDS", "25"))


async def _handle_connection(
    bus: EventBus,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = str(peer[0]), int(peer[1])
    started = time.perf_counter()

    if await blocklist.is_blocked(bus.client, src_ip):
        log.info("smtp.connection_blocked", src_ip=src_ip)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return

    commands = 0
    relay_attempts = 0
    helo_seen = False

    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        session_id = await mgr.open(
            service=Service.SMTP, src_ip=src_ip, src_port=src_port,
            local_port=LISTEN_PORT,
        )
        with contextlib.suppress(Exception):
            writer.write(proto.BANNER.encode())
            await writer.drain()

        try:
            while commands < MAX_COMMANDS:
                line = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
                if not line:
                    break
                verb, arg = proto.parse_command(line)
                reply, should_close, is_relay = proto.reply_for(
                    verb, arg, helo_seen=helo_seen,
                )
                if verb in ("HELO", "EHLO"):
                    helo_seen = True
                if is_relay:
                    relay_attempts += 1
                commands += 1
                await mgr.record_event(
                    session_id=session_id,
                    event_type=EventType.SMTP_COMMAND,
                    service=Service.SMTP, src_ip=src_ip, src_port=src_port,
                    payload={
                        "command": verb,
                        "argument": arg,
                        "relay_attempt": is_relay,
                        "seq": commands,
                    },
                )
                writer.write(reply.encode())
                await writer.drain()
                if should_close:
                    break
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass

        duration_ms = int((time.perf_counter() - started) * 1000)
        await mgr.close(
            session_id=session_id, service=Service.SMTP,
            src_ip=src_ip, src_port=src_port,
            event_count=commands, duration_ms=duration_ms,
            close_reason="relay_probe" if relay_attempts else "client_left",
        )

    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()

    log.info("smtp.session_captured", src_ip=src_ip, commands=commands,
             relay_attempts=relay_attempts, duration_ms=duration_ms)


async def main() -> None:                                  # pragma: no cover
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")
    bus = await EventBus(
        settings.redis_url, stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    async def _on_conn(reader, writer):
        try:
            await _handle_connection(bus, reader, writer)
        except Exception as exc:        # noqa: BLE001
            log.exception("smtp.connection_failed", error=str(exc))

    server = await asyncio.start_server(_on_conn, LISTEN_HOST, LISTEN_PORT)
    log.info("smtp.listening", host=LISTEN_HOST, port=LISTEN_PORT)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":                                 # pragma: no cover
    asyncio.run(main())
