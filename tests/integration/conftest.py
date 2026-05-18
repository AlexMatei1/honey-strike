"""Shared fixtures for live-stack integration tests.

These tests probe the **running compose stack** through its host ports — they
do NOT boot listeners in-process. That keeps the test surface identical to
what an attacker would hit and avoids duplicating production wiring.

A test is automatically skipped if its target port isn't reachable, so the
unit suite still runs in environments where the stack is down. CI spins the
stack up before running the integration job.

Environment overrides:
  HONEYSTRIKE_HOST       — DNS / IP of the host running compose (default 127.0.0.1).
                           Used as fallback when per-service hostnames are not set.
  HONEYPOT_{SSH,HTTP,FTP,RDP}_HOST  — per-service hostname override. Set when running
                           tests inside a Docker network where each honeypot has its
                           own container name (e.g. HONEYPOT_SSH_HOST=ssh-honeypot).
  HONEYPOT_SSH_PORT      — default 2222
  HONEYPOT_HTTP_PORT     — default 18080
  HONEYPOT_FTP_PORT      — default 2221
  HONEYPOT_RDP_PORT      — default 33389
  DATABASE_URL           — async URL to the same Postgres the stack writes to
  REDIS_URL              — same Redis the stack writes to
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

HOST = os.getenv("HONEYSTRIKE_HOST", "127.0.0.1")
SSH_HOST = os.getenv("HONEYPOT_SSH_HOST", HOST)
HTTP_HOST = os.getenv("HONEYPOT_HTTP_HOST", HOST)
FTP_HOST = os.getenv("HONEYPOT_FTP_HOST", HOST)
RDP_HOST = os.getenv("HONEYPOT_RDP_HOST", HOST)
TLS_HOST = os.getenv("HONEYPOT_TLS_HOST", HOST)
SSH_PORT = int(os.getenv("HONEYPOT_SSH_PORT", "2222"))
HTTP_PORT = int(os.getenv("HONEYPOT_HTTP_PORT", "18080"))
FTP_PORT = int(os.getenv("HONEYPOT_FTP_PORT", "2221"))
RDP_PORT = int(os.getenv("HONEYPOT_RDP_PORT", "33389"))
TLS_PORT = int(os.getenv("HONEYPOT_TLS_PORT", "8443"))
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://honeystrike:change-me-honeystrike@127.0.0.1:5432/honeystrike",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")


def _port_open(host: str, port: int, *, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Service reachability — fixtures that skip the test when their target is down.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ssh_endpoint() -> tuple[str, int]:
    if not _port_open(SSH_HOST, SSH_PORT):
        pytest.skip(f"SSH honeypot not reachable at {SSH_HOST}:{SSH_PORT}")
    return SSH_HOST, SSH_PORT


@pytest.fixture(scope="session")
def http_endpoint() -> str:
    if not _port_open(HTTP_HOST, HTTP_PORT):
        pytest.skip(f"HTTP honeypot not reachable at {HTTP_HOST}:{HTTP_PORT}")
    return f"http://{HTTP_HOST}:{HTTP_PORT}"


@pytest.fixture(scope="session")
def ftp_endpoint() -> tuple[str, int]:
    if not _port_open(FTP_HOST, FTP_PORT):
        pytest.skip(f"FTP honeypot not reachable at {FTP_HOST}:{FTP_PORT}")
    return FTP_HOST, FTP_PORT


@pytest.fixture(scope="session")
def rdp_endpoint() -> tuple[str, int]:
    if not _port_open(RDP_HOST, RDP_PORT):
        pytest.skip(f"RDP honeypot not reachable at {RDP_HOST}:{RDP_PORT}")
    return RDP_HOST, RDP_PORT


# ---------------------------------------------------------------------------
# DB / Redis client fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(DATABASE_URL)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def redis_client() -> AsyncIterator[aioredis.Redis]:
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    yield client
    await client.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _wait_for(
    predicate: Callable[[], Any], *, timeout: float = 5.0, interval: float = 0.2
) -> Any:
    """Poll an async predicate until it returns truthy or times out."""
    deadline = time.monotonic() + timeout
    while True:
        result = await predicate()
        if result:
            return result
        if time.monotonic() > deadline:
            return result
        await asyncio.sleep(interval)


@pytest.fixture
def wait_for():
    """Expose `_wait_for` to tests."""
    return _wait_for
