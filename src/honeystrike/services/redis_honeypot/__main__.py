"""Redis honeypot listener.

Asyncio TCP server on :6379. Speaks enough RESP to keep an attacker probing
an "unauthenticated Redis" engaged, recording every command as a
REDIS_COMMAND event. The CONFIG SET dir/dbfilename pattern (used to drop SSH
keys or cron jobs via an exposed Redis) is flagged as an RCE attempt — but
nothing is ever executed; we only answer plausibly and log.
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
from honeystrike.services.redis_honeypot import protocol as proto

log = get_logger("honeystrike.services.redis")

LISTEN_HOST = "0.0.0.0"                                    # noqa: S104 — honeypot
LISTEN_PORT = int(os.getenv("REDIS_HP_LISTEN_PORT", "6379"))
READ_TIMEOUT = float(os.getenv("REDIS_HP_READ_TIMEOUT_SECONDS", "30.0"))
MAX_COMMANDS = int(os.getenv("REDIS_HP_MAX_COMMANDS", "50"))
MAX_BUFFER = 64 * 1024


async def _handle_connection(
    bus: EventBus,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = str(peer[0]), int(peer[1])
    started = time.perf_counter()

    if await blocklist.is_blocked(bus.client, src_ip):
        log.info("redis.connection_blocked", src_ip=src_ip)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return

    commands = 0
    rce_attempts = 0
    buf = b""

    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        session_id = await mgr.open(
            service=Service.REDIS, src_ip=src_ip, src_port=src_port,
            local_port=LISTEN_PORT,
        )
        try:
            while commands < MAX_COMMANDS:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_BUFFER:
                    buf = buf[-MAX_BUFFER:]
                # Drain every complete command in the buffer.
                while True:
                    args, rest = proto.parse_command(buf)
                    if args is None:
                        break
                    buf = rest
                    reply, should_close, is_rce = proto.reply_for(args)
                    if is_rce:
                        rce_attempts += 1
                    commands += 1
                    await mgr.record_event(
                        session_id=session_id,
                        event_type=EventType.REDIS_COMMAND,
                        service=Service.REDIS, src_ip=src_ip, src_port=src_port,
                        payload={
                            "command": args[0].upper() if args and args[0] else "",
                            "args": args[1:][:8],         # cap recorded args
                            "rce_attempt": is_rce,
                            "seq": commands,
                        },
                    )
                    with contextlib.suppress(Exception):
                        writer.write(reply)
                        await writer.drain()
                    if should_close or commands >= MAX_COMMANDS:
                        break
                if commands >= MAX_COMMANDS:
                    break
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass

        duration_ms = int((time.perf_counter() - started) * 1000)
        await mgr.close(
            session_id=session_id, service=Service.REDIS,
            src_ip=src_ip, src_port=src_port,
            event_count=commands, duration_ms=duration_ms,
            close_reason="rce_probe" if rce_attempts else "client_left",
        )

    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()

    log.info("redis.session_captured", src_ip=src_ip, commands=commands,
             rce_attempts=rce_attempts, duration_ms=duration_ms)


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
            log.exception("redis.connection_failed", error=str(exc))

    server = await asyncio.start_server(_on_conn, LISTEN_HOST, LISTEN_PORT)
    log.info("redis.listening", host=LISTEN_HOST, port=LISTEN_PORT)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":                                 # pragma: no cover
    asyncio.run(main())
