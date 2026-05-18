"""SSH honeypot listener.

Binds an asyncio TCP server on `0.0.0.0:22` (inside the container; remapped
to a high host port on Windows). Each accepted connection is handed off to a
worker thread because Paramiko's API is blocking.

The worker thread:
  1. Wraps the socket in a paramiko.Transport
  2. Captures the client banner / KEX details
  3. Drives `HoneypotSSHServer.start_server()` to accept authentication
  4. If a shell was granted, runs `FakeShell`
  5. On disconnect / timeout, persists all captured events and closes the session

Cross-thread persistence is done via `asyncio.run_coroutine_threadsafe()` so
that DB and Redis I/O all stay on the main event loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import threading
import time
import uuid
from typing import Any

import paramiko

from honeystrike.config import get_settings
from honeystrike.core import blocklist
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.session_manager import SessionManager
from honeystrike.services.ssh.attempt_counter import IPAttemptCounter
from honeystrike.services.ssh.host_key import load_or_create_host_key
from honeystrike.services.ssh.server import HoneypotSSHServer
from honeystrike.services.ssh.shell import FakeShell

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 22
HOST_KEY_DIR = os.getenv("SSH_HOST_KEY_DIR", "/var/lib/honeystrike/ssh")

log = get_logger("honeystrike.services.ssh")


async def _persist_captures(
    captures: list[dict[str, Any]],
    *,
    session_id: uuid.UUID,
    src_ip: str,
    src_port: int,
    bus: EventBus,
) -> None:
    """Drain the in-memory capture buffer into PG + Redis."""
    if not captures:
        return
    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        for entry in captures:
            await mgr.record_event(
                session_id=session_id,
                event_type=entry["event_type"],
                service=Service.SSH,
                src_ip=src_ip,
                src_port=src_port,
                payload=entry["payload"],
            )


async def _open_session(
    src_ip: str, src_port: int, bus: EventBus
) -> uuid.UUID:
    async with session_scope() as db:
        mgr = SessionManager(db, bus)
        return await mgr.open(
            service=Service.SSH,
            src_ip=src_ip,
            src_port=src_port,
            local_port=LISTEN_PORT,
        )


async def _close_session(
    *,
    session_id: uuid.UUID,
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
            service=Service.SSH,
            src_ip=src_ip,
            src_port=src_port,
            event_count=event_count,
            duration_ms=duration_ms,
            close_reason=close_reason,
        )


def _handle_connection_blocking(
    client_sock: socket.socket,
    addr: tuple[str, int],
    host_key: paramiko.PKey,
    loop: asyncio.AbstractEventLoop,
    bus: EventBus,
    counter: IPAttemptCounter,
    *,
    banner: str,
    max_duration_seconds: int,
) -> None:
    """Blocking handler — runs on a worker thread."""
    src_ip, src_port = addr[0], addr[1]
    start = time.monotonic()

    # Open the session row on the main event loop.
    session_future = asyncio.run_coroutine_threadsafe(
        _open_session(src_ip, src_port, bus), loop
    )
    try:
        session_id = session_future.result(timeout=10)
    except Exception as exc:
        log.error("ssh.session_open_failed", error=str(exc), src_ip=src_ip)
        with contextlib.suppress(Exception):
            client_sock.close()
        return

    # Sync adapter for the Paramiko thread → async IPAttemptCounter on the loop.
    def attempt_check(ip: str) -> tuple[int, bool]:
        fut = asyncio.run_coroutine_threadsafe(
            counter.increment_and_check(ip), loop
        )
        return fut.result(timeout=5)

    transport: paramiko.Transport | None = None
    server: HoneypotSSHServer | None = None
    captures: list[dict[str, Any]] = []
    close_reason = "client_disconnect"

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = banner
        transport.add_server_key(host_key)
        server = HoneypotSSHServer(
            session_id=session_id,
            src_ip=src_ip,
            src_port=src_port,
            attempt_check=attempt_check,
        )

        try:
            transport.start_server(server=server)
        except paramiko.SSHException as exc:
            # Most scanners drop after the banner without negotiating KEX.
            client_version = (
                transport.remote_version
                if transport.remote_version
                else "unknown"
            )
            captures.append(
                {
                    "event_type": EventType.SSH_BANNER_GRAB,
                    "payload": {
                        "client_version": client_version,
                        "reason": str(exc),
                        "kex_algorithms": [],
                    },
                }
            )
            close_reason = "no_auth"
            return

        # KEX completed — record the client banner + KEX with what we know now.
        client_version = transport.remote_version or "unknown"
        captures.append(
            {
                "event_type": EventType.SSH_BANNER_GRAB,
                "payload": {
                    "client_version": client_version,
                    # Paramiko negotiates KEX internally; expose the chosen one.
                    "kex_algorithm": transport.get_security_options().kex[0]
                    if transport.get_security_options().kex
                    else None,
                },
            }
        )

        # Wait for auth + shell request (Paramiko fires events from its thread).
        channel = transport.accept(timeout=30)
        if channel is None:
            close_reason = "no_shell"
            return

        # Drain any auth-attempt captures that accumulated during handshake.
        captures.extend(server.captured)
        server.captured.clear()

        # Wait briefly for shell/exec request flag.
        server.shell_event.wait(timeout=10)

        # Drain again — exec_request may have fired between the two clears.
        captures.extend(server.captured)
        server.captured.clear()

        if server.shell_granted:
            shell = FakeShell(channel, max_duration_seconds=max_duration_seconds)
            for cmd in shell.run():
                captures.append(
                    {
                        "event_type": EventType.SSH_COMMAND,
                        "payload": {"raw": cmd.raw, "tokens": cmd.tokens},
                    }
                )
            close_reason = "shell_end"
        else:
            close_reason = "auth_failed"

    except Exception as exc:
        log.exception("ssh.handler_error", error=str(exc), src_ip=src_ip)
        close_reason = "error"
    finally:
        if server is not None:
            captures.extend(server.captured)
        with contextlib.suppress(Exception):
            if transport is not None:
                transport.close()
        with contextlib.suppress(Exception):
            client_sock.close()

        duration_ms = int((time.monotonic() - start) * 1000)
        # Persist captures and close session — all on the main loop.
        try:
            asyncio.run_coroutine_threadsafe(
                _persist_captures(
                    captures,
                    session_id=session_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    bus=bus,
                ),
                loop,
            ).result(timeout=10)
            asyncio.run_coroutine_threadsafe(
                _close_session(
                    session_id=session_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    event_count=len(captures),
                    duration_ms=duration_ms,
                    close_reason=close_reason,
                    bus=bus,
                ),
                loop,
            ).result(timeout=10)
        except Exception as exc:
            log.error(
                "ssh.persist_failed",
                error=str(exc),
                session_id=str(session_id),
            )


async def _accept_loop(
    *,
    bus: EventBus,
    counter: IPAttemptCounter,
    host_key: paramiko.PKey,
    banner: str,
    max_duration_seconds: int,
) -> None:
    loop = asyncio.get_running_loop()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(100)
    server_sock.setblocking(False)
    log.info("ssh.listening", host=LISTEN_HOST, port=LISTEN_PORT, banner=banner)

    try:
        while True:
            client_sock, addr = await loop.sock_accept(server_sock)
            # Phase 6 blocking check — if the defender has blocked this IP
            # via `defend label`, refuse the connection immediately.
            if await blocklist.is_blocked(bus.client, addr[0]):
                log.info("ssh.connection_blocked", src_ip=addr[0], src_port=addr[1])
                with contextlib.suppress(OSError):
                    client_sock.close()
                continue
            log.info("ssh.connection_accepted", src_ip=addr[0], src_port=addr[1])
            thread = threading.Thread(
                target=_handle_connection_blocking,
                args=(client_sock, addr, host_key, loop, bus, counter),
                kwargs={
                    "banner": banner,
                    "max_duration_seconds": max_duration_seconds,
                },
                daemon=True,
                name=f"ssh-conn-{addr[0]}:{addr[1]}",
            )
            thread.start()
    finally:
        server_sock.close()


async def main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    bus = await EventBus(
        settings.redis_url,
        stream=settings.redis_stream,
        maxlen=settings.redis_stream_maxlen,
    ).connect()

    host_key = load_or_create_host_key(HOST_KEY_DIR)
    banner = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    allow_after = int(os.getenv("SSH_ALLOW_AFTER_N_ATTEMPTS", "3"))
    counter_ttl = int(os.getenv("SSH_ATTEMPT_COUNTER_TTL_SECONDS", "3600"))
    counter = IPAttemptCounter(
        bus.client, threshold=allow_after, ttl_seconds=counter_ttl
    )

    try:
        await _accept_loop(
            bus=bus,
            counter=counter,
            host_key=host_key,
            banner=banner,
            max_duration_seconds=settings.session_max_duration_seconds,
        )
    finally:
        await bus.close()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
