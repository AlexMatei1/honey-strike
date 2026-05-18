"""Live WebSocket integration test.

Opens a WS against the running dashboard-api, asserts the initial seed
arrives, then drives a fresh attack and confirms the worker-produced
fingerprint surfaces on the same connection within the polling window.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket

import httpx
import pytest
import websockets

API_HOST = os.getenv("DASHBOARD_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("DASHBOARD_API_PORT", "8001"))
HTTP_HOST = os.getenv("HONEYPOT_HTTP_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("HONEYPOT_HTTP_PORT", "18080"))
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "change-me-strong-password")


def _port_open(host: str, port: int, *, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def api_base() -> str:
    if not _port_open(API_HOST, API_PORT):
        pytest.skip(f"dashboard-api not reachable at {API_HOST}:{API_PORT}")
    return f"http://{API_HOST}:{API_PORT}"


async def _login(base: str) -> str:
    async with httpx.AsyncClient(base_url=base, timeout=10) as client:
        r = await client.post(
            "/api/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )
        r.raise_for_status()
        return r.json()["access_token"]


@pytest.mark.asyncio
async def test_ws_rejects_without_token(api_base: str) -> None:
    url = f"ws://{API_HOST}:{API_PORT}/api/ws/live"
    with pytest.raises(Exception):
        async with websockets.connect(url) as _ws:
            pass


@pytest.mark.asyncio
async def test_ws_seeds_recent_sessions(api_base: str) -> None:
    token = await _login(api_base)
    url = f"ws://{API_HOST}:{API_PORT}/api/ws/live?token={token}&poll=1"
    seed_messages = []
    seed_complete = False
    async with websockets.connect(url) as ws:
        # Read until we see seed_complete; tolerate empty seed (no fingerprints).
        try:
            while not seed_complete:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                if msg.get("type") == "seed_complete":
                    seed_complete = True
                elif msg.get("type") == "session":
                    seed_messages.append(msg)
        except asyncio.TimeoutError:
            pytest.fail("WS did not produce a seed_complete in time")
    assert seed_complete


@pytest.mark.asyncio
async def test_ws_streams_new_session(api_base: str) -> None:
    if not _port_open(HTTP_HOST, HTTP_PORT):
        pytest.skip(f"http-honeypot not reachable at {HTTP_HOST}:{HTTP_PORT}")
    token = await _login(api_base)
    url = f"ws://{API_HOST}:{API_PORT}/api/ws/live?token={token}&poll=1"

    async with websockets.connect(url) as ws:
        # Drain seed first.
        while True:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            if msg.get("type") == "seed_complete":
                break

        # Probe the HTTP honeypot — a scored fingerprint should follow within
        # ~30s (event flush + worker tick + WS poll).
        async with httpx.AsyncClient(timeout=10) as client:
            await client.get(
                f"http://{HTTP_HOST}:{HTTP_PORT}/wp-login.php",
                headers={"User-Agent": "sqlmap/1.7.8#stable"},
            )

        delivered = None
        try:
            while True:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=45))
                if msg.get("type") == "session":
                    delivered = msg
                    break
        except asyncio.TimeoutError:
            pytest.fail("WS did not deliver a fresh session within 45s")

    assert delivered is not None
    for key in ("session_id", "src_ip", "service", "severity", "threat_score"):
        assert key in delivered
