"""Telnet honeypot listener.

Asyncio TCP server on :23. Presents a realistic `login:` / `Password:`
sequence and records every credential pair as a TELNET_AUTH_ATTEMPT event.
Auth always fails (after a small delay, like a real box under load) and the
attacker is re-prompted until they give up or hit the attempt cap.

Telnet brute force is one of the most common things on the internet — Mirai
and its descendants spread almost entirely over :23 — so this listener
captures a huge slice of real botnet traffic.
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
from honeystrike.services.telnet import protocol as proto

log = get_logger("honeystrike.services.telnet")

LISTEN_HOST = "0.0.0.0"                                    # noqa: S104 — honeypot
LISTEN_PORT = int(os.getenv("TELNET_LISTEN_PORT", "23"))
READ_TIMEOUT = float(os.getenv("TELNET_READ_TIMEOUT_SECONDS", "30.0"))
MAX_ATTEMPTS = int(os.getenv("TELNET_MAX_ATTEMPTS", "6"))
FAIL_DELAY = float(os.getenv("TELNET_FAIL_DELAY_SECONDS", "1.0"))


async def _readline(reader: asyncio.StreamReader) -> bytes:
    """Read one line (up to LF), bounded. Returns raw bytes incl. IAC."""
    return await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)


async def _handle_connection(
    bus: EventBus,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = str(peer[0]), int(peer[1])
    started = time.perf_counter()

    if await blocklist.is_blocked(bus.client, src_ip):
        log.info("telnet.connection_blocked", src_ip=src_ip)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return

    attempts: list[tuple[str, str]] = []

    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        session_id = await mgr.open(
            service=Service.TELNET, src_ip=src_ip, src_port=src_port,
            local_port=LISTEN_PORT,
        )

        with contextlib.suppress(Exception):
            writer.write(proto.BANNER.encode())
            await writer.drain()

        try:
            while len(attempts) < MAX_ATTEMPTS:
                # login:
                writer.write(proto.LOGIN_PROMPT.encode())
                await writer.drain()
                raw_user = await _readline(reader)
                if not raw_user:
                    break
                opt_reply = proto.refuse_options(raw_user)
                if opt_reply:
                    writer.write(opt_reply)
                    await writer.drain()
                username = proto.clean_credential(raw_user)

                # Password:
                writer.write(proto.PASSWORD_PROMPT.encode())
                await writer.drain()
                raw_pass = await _readline(reader)
                password = proto.clean_credential(raw_pass)

                attempts.append((username, password))
                await mgr.record_event(
                    session_id=session_id,
                    event_type=EventType.TELNET_AUTH_ATTEMPT,
                    service=Service.TELNET, src_ip=src_ip, src_port=src_port,
                    payload={
                        "username": username,
                        "password": password,
                        "success": False,
                        "attempt": len(attempts),
                    },
                )
                await asyncio.sleep(FAIL_DELAY)
                writer.write(proto.FAIL_MESSAGE.encode())
                await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass

        duration_ms = int((time.perf_counter() - started) * 1000)
        await mgr.close(
            session_id=session_id, service=Service.TELNET,
            src_ip=src_ip, src_port=src_port,
            event_count=len(attempts), duration_ms=duration_ms,
            close_reason="max_attempts" if len(attempts) >= MAX_ATTEMPTS else "client_left",
        )

    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()

    log.info("telnet.session_captured", src_ip=src_ip, attempts=len(attempts),
             duration_ms=duration_ms)


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
            log.exception("telnet.connection_failed", error=str(exc))

    server = await asyncio.start_server(_on_conn, LISTEN_HOST, LISTEN_PORT)
    log.info("telnet.listening", host=LISTEN_HOST, port=LISTEN_PORT)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":                                 # pragma: no cover
    asyncio.run(main())
