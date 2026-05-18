"""Cross-service capture test.

Hits all four honeypots in quick succession from a single client process
and asserts each landed as its own correctly-tagged session row, with the
Redis stream receiving entries from all of them.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import time

import httpx
import paramiko
import pytest
from sqlalchemy import func, select

from honeystrike.core.models import Session


def _ssh_probe(host: str, port: int) -> None:
    sock = socket.create_connection((host, port), timeout=10)
    t = paramiko.Transport(sock)
    t.start_client(timeout=10)
    with contextlib.suppress(paramiko.AuthenticationException):
        t.auth_password("root", "x")
    t.close()


def _ftp_probe(host: str, port: int) -> None:
    import ftplib
    f = ftplib.FTP()
    f.connect(host, port, timeout=10)
    with contextlib.suppress(Exception):
        f.login("root", "toor")
    with contextlib.suppress(Exception):
        f.quit()


def _rdp_probe(host: str, port: int) -> None:
    s = socket.create_connection((host, port), timeout=5)
    cookie = b"Cookie: mstshash=CrossSvc\r\n"
    neg = struct.pack("<BBHI", 0x01, 0x00, 8, 0x01)
    payload = cookie + neg
    x224 = bytes([6 + len(payload), 0xE0, 0, 0, 0, 0, 0]) + payload
    s.sendall(bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(x224)) + x224)
    with contextlib.suppress(socket.timeout):
        s.recv(4096)
    s.close()


@pytest.mark.asyncio
async def test_single_client_hits_all_four_services(
    ssh_endpoint, http_endpoint, ftp_endpoint, rdp_endpoint,
    db, redis_client, wait_for,
) -> None:
    ssh_host, ssh_port = ssh_endpoint
    ftp_host, ftp_port = ftp_endpoint
    rdp_host, rdp_port = rdp_endpoint

    start_redis = int(await redis_client.xlen("honeystrike:events"))

    # Baseline session counts per service.
    async def _counts() -> dict[str, int]:
        rows = (
            await db.execute(
                select(Session.service, func.count(Session.id)).group_by(Session.service)
            )
        ).all()
        return {svc: int(n) for svc, n in rows}

    before = await _counts()

    # Fire one probe per service.
    t_start = time.time()
    _ssh_probe(ssh_host, ssh_port)
    async with httpx.AsyncClient(timeout=10) as client:
        await client.get(f"{http_endpoint}/wp-login.php")
    _ftp_probe(ftp_host, ftp_port)
    _rdp_probe(rdp_host, rdp_port)
    elapsed = time.time() - t_start

    # All four probes complete fast enough that the test stays snappy.
    assert elapsed < 15, f"probes took {elapsed:.1f}s"

    async def _all_services_grew() -> bool:
        after = await _counts()
        for svc in ("ssh", "http", "ftp", "rdp"):
            if after.get(svc, 0) <= before.get(svc, 0):
                return False
        return True

    ok = await wait_for(_all_services_grew, timeout=15.0)
    assert ok, "expected every service's session count to grow by at least 1"

    after_redis = int(await redis_client.xlen("honeystrike:events"))
    # Each probe contributes at minimum SESSION_OPEN + SESSION_CLOSE + ≥1 event;
    # 4 probes × ≥3 entries = ≥12 stream entries.
    assert (after_redis - start_redis) >= 12, (
        f"Redis stream grew by only {after_redis - start_redis}"
    )
