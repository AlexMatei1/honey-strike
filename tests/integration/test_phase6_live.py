"""Live integration test for Phase 6 — lobby + blocklist + canaries.

Runs against the running compose stack (lobby on :8002, dashboard-api on
:8001, HTTP honeypot on :18080). Verifies:

  - Two registrations land + show up under /lobby/players.
  - Invite + accept flow + match retrieval works.
  - POST /api/defender/block actually refuses subsequent connections at the
    HTTP honeypot.
  - http-recon-style probes to /.env are surfaced by `defend flags-found`.
"""

from __future__ import annotations

import asyncio
import os
import socket

import httpx
import pytest

LOBBY_BASE = os.getenv("LOBBY_BASE", "http://127.0.0.1:8002")
API_BASE = os.getenv("DASHBOARD_API_BASE", "http://127.0.0.1:8001")
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


def _lobby_host_port() -> tuple[str, int]:
    """Strip http:// from the LOBBY_BASE for plain socket check."""
    rest = LOBBY_BASE.split("://", 1)[1]
    host, port_s = rest.rsplit(":", 1)
    return host, int(port_s.rstrip("/"))


@pytest.fixture(scope="module")
def lobby_url() -> str:
    host, port = _lobby_host_port()
    if not _port_open(host, port):
        pytest.skip(f"lobby not reachable at {LOBBY_BASE}")
    return LOBBY_BASE


@pytest.mark.asyncio
async def test_lobby_register_listed_in_players(lobby_url: str) -> None:
    handle_a = f"itest-alice-{os.urandom(4).hex()}"
    handle_b = f"itest-bob-{os.urandom(4).hex()}"

    async with httpx.AsyncClient(base_url=lobby_url, timeout=10) as c:
        r = await c.post("/lobby/register", json={
            "handle": handle_a,
            "public_endpoints": {"ssh": "alice.example:2222"},
        })
        assert r.status_code == 200, r.text
        token_a = r.json()["token"]
        r = await c.post("/lobby/register", json={
            "handle": handle_b,
            "public_endpoints": {"http": "bob.example:18080"},
        })
        assert r.status_code == 200, r.text
        token_b = r.json()["token"]

        # Heartbeat so both show as online.
        await c.post("/lobby/heartbeat",
                     headers={"Authorization": f"Bearer {token_a}"})
        await c.post("/lobby/heartbeat",
                     headers={"Authorization": f"Bearer {token_b}"})

        r = await c.get("/lobby/players")
        handles = {p["handle"] for p in r.json()}
        assert handle_a in handles
        assert handle_b in handles


@pytest.mark.asyncio
async def test_invite_accept_creates_a_match(lobby_url: str) -> None:
    a = f"itest-att-{os.urandom(4).hex()}"
    b = f"itest-def-{os.urandom(4).hex()}"

    async with httpx.AsyncClient(base_url=lobby_url, timeout=10) as c:
        ta = (await c.post("/lobby/register", json={
            "handle": a, "public_endpoints": {"ssh": "a:22"},
        })).json()["token"]
        tb = (await c.post("/lobby/register", json={
            "handle": b, "public_endpoints": {"http": "b:80"},
        })).json()["token"]

        # Attacker invites defender.
        r = await c.post(
            "/lobby/invite",
            headers={"Authorization": f"Bearer {ta}"},
            json={"to_handle": b, "scenario": "apt28", "duration_seconds": 60},
        )
        assert r.status_code == 200, r.text
        invite_code = r.json()["invite_code"]

        # Defender sees it.
        r = await c.get(
            f"/lobby/invites/{b}",
            headers={"Authorization": f"Bearer {tb}"},
        )
        assert any(i["invite_code"] == invite_code for i in r.json())

        # Defender accepts.
        r = await c.post(
            "/lobby/accept",
            headers={"Authorization": f"Bearer {tb}"},
            json={"invite_code": invite_code},
        )
        assert r.status_code == 200, r.text
        match = r.json()
        assert match["scenario"] == "apt28"
        assert match["attacker_handle"] == a
        assert match["defender_handle"] == b


@pytest.mark.asyncio
async def test_block_via_api_refuses_subsequent_http_requests() -> None:
    if not _port_open(HTTP_HOST, HTTP_PORT):
        pytest.skip("HTTP honeypot not reachable")
    if not _port_open(API_BASE.split("://")[1].split(":")[0],
                      int(API_BASE.rsplit(":", 1)[1])):
        pytest.skip("dashboard-api not reachable")

    async with httpx.AsyncClient(base_url=API_BASE, timeout=30) as api:
        r = await api.post("/api/auth/login",
                           json={"username": ADMIN_USER, "password": ADMIN_PASS})
        assert r.status_code == 200
        token = r.json()["access_token"]
        hdr = {"Authorization": f"Bearer {token}"}

        # Confirm normal HTTP first.
        async with httpx.AsyncClient(timeout=10) as probe:
            r = await probe.get(f"http://{HTTP_HOST}:{HTTP_PORT}/wp-login.php")
            assert r.status_code == 200
            # The src_ip the honeypot saw is now in `sessions`. We can't
            # introspect it easily without DB access here; instead, find it
            # via the dashboard API.
            r = await api.get(
                "/api/sessions",
                headers=hdr,
                params={"limit": 1, "service": "http"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["items"], "no http sessions yet"
            src_ip = r.json()["items"][0]["src_ip"]

        # Block that IP for 30s and confirm next request returns 403.
        r = await api.post(
            "/api/defender/block",
            headers=hdr,
            json={"ip": src_ip, "ttl_seconds": 30, "reason": "phase6-test"},
        )
        assert r.status_code == 200, r.text
        await asyncio.sleep(0.5)
        async with httpx.AsyncClient(timeout=10) as probe:
            r = await probe.get(f"http://{HTTP_HOST}:{HTTP_PORT}/wp-login.php")
        assert r.status_code == 403, f"expected 403, got {r.status_code}"

        # Unblock.
        bare_ip = src_ip.rsplit("/", 1)[0]
        await api.delete(f"/api/defender/block/{bare_ip}", headers=hdr)
        await asyncio.sleep(0.3)
        async with httpx.AsyncClient(timeout=10) as probe:
            r = await probe.get(f"http://{HTTP_HOST}:{HTTP_PORT}/wp-login.php")
        assert r.status_code == 200, f"expected 200 after unblock, got {r.status_code}"


@pytest.mark.asyncio
async def test_http_env_response_contains_canary() -> None:
    """Sanity: the seeded /.env page actually contains the AWS-key canary
    we look for in `defend flags-found`."""
    if not _port_open(HTTP_HOST, HTTP_PORT):
        pytest.skip("HTTP honeypot not reachable")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"http://{HTTP_HOST}:{HTTP_PORT}/.env")
    from honeystrike.cli.attack import canaries
    assert canaries.FAKE_AWS_KEY.needle in r.text


@pytest.mark.asyncio
async def test_http_admin_html_carries_admin_token_canary() -> None:
    if not _port_open(HTTP_HOST, HTTP_PORT):
        pytest.skip("HTTP honeypot not reachable")
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"http://{HTTP_HOST}:{HTTP_PORT}/admin")
    from honeystrike.cli.attack import canaries
    assert canaries.FAKE_ADMIN_TOKEN.needle in r.text
