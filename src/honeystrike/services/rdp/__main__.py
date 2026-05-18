"""RDP honeypot listener — asyncio TCP server.

Per-connection flow:

  1. Read the first ~4 KB (typical CR PDU is < 200 bytes).
  2. Parse the X.224 Connection Request → capture mstshash cookie + requested
     security protocols.
  3. Send back a valid Connection Confirm advertising PROTOCOL_SSL so the
     client advances to its TLS ClientHello stage.
  4. Best-effort read of the following bytes (whatever the client sends after
     CC) — log them raw as `post_confirm_bytes_hex` so the operator can see
     the start of the next stage's payload (often a TLS ClientHello, which
     we can later fingerprint with JA3 once Caddy/TLS is wired up).
  5. Close the connection.

Total session capped at 5s — RDP scanners are fast and we don't want to
keep many sockets open against us.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from typing import Any

from honeystrike.config import get_settings
from honeystrike.core import blocklist
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.session_manager import SessionManager
from honeystrike.services.rdp.pdu import (
    PROTOCOL_HYBRID,
    PROTOCOL_HYBRID_EX,
    PROTOCOL_RDSTLS,
    PROTOCOL_SSL,
    build_connection_confirm,
    parse_connection_request,
)

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.getenv("RDP_LISTEN_PORT", "3389"))
SESSION_MAX_SECONDS = 5
READ_CAP_BYTES = 8192   # CR PDU + a bit of post-CC bytes

log = get_logger("honeystrike.services.rdp")


def _decode_protocols(flags: int) -> list[str]:
    names: list[str] = []
    if flags == 0:
        names.append("PROTOCOL_RDP")
    if flags & PROTOCOL_SSL:
        names.append("PROTOCOL_SSL")
    if flags & PROTOCOL_HYBRID:
        names.append("PROTOCOL_HYBRID")
    if flags & PROTOCOL_RDSTLS:
        names.append("PROTOCOL_RDSTLS")
    if flags & PROTOCOL_HYBRID_EX:
        names.append("PROTOCOL_HYBRID_EX")
    return names


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    bus: EventBus,
) -> None:
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "0.0.0.0"  # noqa: S104 — fallback only
    src_port = peer[1] if peer else 0
    start = time.monotonic()

    # Phase 6 blocking — drop defender-blocked IPs.
    if await blocklist.is_blocked(bus.client, src_ip):
        log.info("rdp.connection_blocked", src_ip=src_ip, src_port=src_port)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return

    log.info("rdp.connection_accepted", src_ip=src_ip, src_port=src_port)

    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        session_id = await mgr.open(
            service=Service.RDP,
            src_ip=src_ip,
            src_port=src_port,
            local_port=LISTEN_PORT,
        )

    event_count = 0
    close_reason = "client_disconnect"

    try:
        # Read the initial CR PDU (bounded by time + bytes).
        try:
            initial = await asyncio.wait_for(
                reader.read(READ_CAP_BYTES), timeout=SESSION_MAX_SECONDS
            )
        except TimeoutError:
            close_reason = "timeout"
            initial = b""

        cr = parse_connection_request(initial) if initial else None
        if cr is None:
            payload: dict[str, Any] = {
                "parse_status": "unparseable" if initial else "no_data",
                "raw_bytes_hex": initial[:512].hex(),
                "raw_length": len(initial),
            }
        else:
            payload = {
                "parse_status": "ok",
                "cookie": cr.cookie_raw,
                "mstshash": cr.mstshash,
                "requested_protocols": cr.requested_protocols,
                "requested_protocols_names": _decode_protocols(cr.requested_protocols),
                "raw_bytes_hex": initial[: cr.raw_length].hex(),
                "raw_length": cr.raw_length,
            }

            # Reply with a structurally valid CC so the client advances.
            try:
                writer.write(build_connection_confirm(selected_protocol=PROTOCOL_SSL))
                await writer.drain()
            except (ConnectionError, OSError):
                close_reason = "broken_pipe"

            # Best-effort read of post-CC bytes (often the start of a TLS
            # ClientHello if the client speaks RDP-over-TLS).
            remaining = max(0, SESSION_MAX_SECONDS - (time.monotonic() - start))
            if remaining > 0:
                try:
                    post = await asyncio.wait_for(
                        reader.read(READ_CAP_BYTES), timeout=remaining
                    )
                except TimeoutError:
                    post = b""
                if post:
                    payload["post_confirm_bytes_hex"] = post[:1024].hex()
                    payload["post_confirm_length"] = len(post)

        async with session_scope() as db:
            mgr = SessionManager(db, bus)
            await mgr.record_event(
                session_id=session_id,
                event_type=EventType.RDP_CONNECT,
                service=Service.RDP,
                src_ip=src_ip,
                src_port=src_port,
                payload=payload,
            )
        event_count += 1

    except Exception as exc:
        log.exception("rdp.handler_error", error=str(exc), src_ip=src_ip)
        close_reason = "error"
    finally:
        with contextlib.suppress(Exception):
            writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except (TimeoutError, OSError, AttributeError):
            pass

        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            async with session_scope() as db:
                mgr = SessionManager(db, bus)
                await mgr.close(
                    session_id=session_id,
                    service=Service.RDP,
                    src_ip=src_ip,
                    src_port=src_port,
                    event_count=event_count,
                    duration_ms=duration_ms,
                    close_reason=close_reason,
                )
        except Exception as exc:
            log.error("rdp.close_failed", error=str(exc), session_id=str(session_id))


async def main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    async def _client_cb(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await _handle_connection(reader, writer, bus)

    server = await asyncio.start_server(_client_cb, LISTEN_HOST, LISTEN_PORT)
    log.info("rdp.listening", host=LISTEN_HOST, port=LISTEN_PORT)

    try:
        async with server:
            await server.serve_forever()
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
