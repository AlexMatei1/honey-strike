"""TLS-fingerprint sniffer listener entrypoint.

Asyncio TCP server. For each connection:
  1. Read the first TLS record header (5 bytes), confirm Handshake/ClientHello.
  2. Slurp the rest of the record (up to ~16 KiB).
  3. Compute JA3 via `services.http.ja3.compute_ja3`.
  4. Open a session (service='tls'), record TLS_CLIENT_HELLO event with the
     JA3 hash, SNI, cipher list, etc., then close the session.
  5. Send a `close_notify` alert (or just drop the connection if the peer
     never sent a valid record) so the client doesn't hang.

The whole flow is bounded by `TLS_HANDSHAKE_TIMEOUT_SECONDS` (default 5s) —
attackers who connect but never send bytes (port scanners on syn-only mode)
time out and produce no session row.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from datetime import UTC, datetime

from honeystrike.config import get_settings
from honeystrike.core import blocklist
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.session_manager import SessionManager
from honeystrike.services.http.ja3 import JA3Fingerprint, compute_ja3

log = get_logger("honeystrike.services.tls")

LISTEN_HOST = "0.0.0.0"                                    # noqa: S104 — honeypot
LISTEN_PORT = int(os.getenv("TLS_LISTEN_PORT", "443"))
HANDSHAKE_TIMEOUT = float(os.getenv("TLS_HANDSHAKE_TIMEOUT_SECONDS", "5.0"))
MAX_RECORD_BYTES = 16_384                                  # TLS record max len


# Minimal TLS alert: close_notify (warning level, alert 0).
_CLOSE_NOTIFY = bytes([
    0x15,                   # ContentType: alert
    0x03, 0x03,             # legacy_version: TLS 1.2
    0x00, 0x02,             # length
    0x01, 0x00,             # level: warning (1), description: close_notify (0)
])


async def _read_client_hello(reader: asyncio.StreamReader) -> bytes:
    """Read up to one full TLS record. Returns whatever we got."""
    header = await reader.readexactly(5)
    record_len = int.from_bytes(header[3:5], "big")
    record_len = min(record_len, MAX_RECORD_BYTES - 5)
    body = await reader.readexactly(record_len) if record_len > 0 else b""
    return header + body


async def _handle_connection(
    bus: EventBus,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = str(peer[0]), int(peer[1])
    started = time.perf_counter()

    # Phase 6 blocking — refuse defender-blocked IPs.
    if await blocklist.is_blocked(bus.client, src_ip):
        log.info("tls.connection_blocked", src_ip=src_ip, src_port=src_port)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return

    fp: JA3Fingerprint | None = None
    raw_len = 0
    try:
        record = await asyncio.wait_for(
            _read_client_hello(reader), timeout=HANDSHAKE_TIMEOUT
        )
        raw_len = len(record)
        fp = compute_ja3(record)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        # No ClientHello in the budget — fall through and close. We still
        # record a session row so the operator can see syn-only scanners.
        pass

    duration_ms = int((time.perf_counter() - started) * 1000)

    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        session_id = await mgr.open(
            service=Service.TLS,
            src_ip=src_ip,
            src_port=src_port,
            local_port=LISTEN_PORT,
        )

        payload: dict = {
            "raw_record_bytes": raw_len,
            "parseable": fp is not None,
        }
        if fp is not None:
            payload.update(
                {
                    "ja3_hash": fp.ja3_hash,
                    "ja3_string": fp.ja3_string,
                    "tls_version": fp.tls_version,
                    "sni": fp.sni,
                    "ciphers": fp.ciphers,
                    "extensions": fp.extensions,
                    "elliptic_curves": fp.elliptic_curves,
                    "ec_point_formats": fp.ec_point_formats,
                }
            )

        await mgr.record_event(
            session_id=session_id,
            event_type=EventType.TLS_CLIENT_HELLO,
            service=Service.TLS,
            src_ip=src_ip,
            src_port=src_port,
            payload=payload,
        )
        await mgr.close(
            session_id=session_id,
            service=Service.TLS,
            src_ip=src_ip,
            src_port=src_port,
            event_count=1,
            duration_ms=duration_ms,
            close_reason="ja3_captured" if fp else "no_client_hello",
        )

    with contextlib.suppress(Exception):
        writer.write(_CLOSE_NOTIFY)
        await writer.drain()
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()

    log.info(
        "tls.connection_captured",
        src_ip=src_ip,
        src_port=src_port,
        ja3_hash=fp.ja3_hash if fp else None,
        sni=fp.sni if fp else None,
        duration_ms=duration_ms,
    )


async def main() -> None:                                  # pragma: no cover
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    async def _on_conn(reader, writer):
        try:
            await _handle_connection(bus, reader, writer)
        except Exception as exc:        # noqa: BLE001
            log.exception("tls.connection_failed", error=str(exc))

    server = await asyncio.start_server(_on_conn, LISTEN_HOST, LISTEN_PORT)
    log.info("tls.listening", host=LISTEN_HOST, port=LISTEN_PORT)
    try:
        async with server:
            await server.serve_forever()
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":                                 # pragma: no cover
    asyncio.run(main())
