"""Live API integration test.

Hits the running dashboard-api container through its host port. Asserts:

  - unauthenticated requests are rejected with 401
  - the bootstrap admin can log in
  - a Bearer token unlocks the protected list/detail/stats endpoints
  - the analytics rollup returns the shape documented in API contracts
"""

from __future__ import annotations

import os
import socket
import uuid

import httpx
import pytest

API_HOST = os.getenv("DASHBOARD_API_HOST", os.getenv("HONEYSTRIKE_HOST", "127.0.0.1"))
API_PORT = int(os.getenv("DASHBOARD_API_PORT", "8001"))
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


@pytest.fixture
async def access_token(api_base: str) -> str:
    async with httpx.AsyncClient(base_url=api_base, timeout=10) as client:
        r = await client.post(
            "/api/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )
        assert r.status_code == 200, r.text
        return r.json()["access_token"]


@pytest.mark.asyncio
async def test_health_is_public_and_reports_ok(api_base: str) -> None:
    async with httpx.AsyncClient(base_url=api_base, timeout=5) as client:
        r = await client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["db"] == "ok"
    assert body["redis"] == "ok"


@pytest.mark.asyncio
async def test_protected_endpoints_reject_without_token(api_base: str) -> None:
    async with httpx.AsyncClient(base_url=api_base, timeout=5) as client:
        r = await client.get("/api/sessions")
        assert r.status_code == 401
        r = await client.get("/api/stats/overview")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(api_base: str) -> None:
    async with httpx.AsyncClient(base_url=api_base, timeout=5) as client:
        r = await client.post(
            "/api/auth/login",
            json={"username": ADMIN_USER, "password": "nope-nope-nope"},
        )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_sessions_list_returns_paginated_shape(
    api_base: str, access_token: str
) -> None:
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=10,
        headers={"Authorization": f"Bearer {access_token}"},
    ) as client:
        r = await client.get("/api/sessions", params={"limit": 5})
    assert r.status_code == 200, r.text
    body = r.json()
    for key in ("total", "page", "limit", "items"):
        assert key in body
    assert body["limit"] == 5
    for item in body["items"]:
        for key in ("id", "src_ip", "service", "threat_score", "severity", "ttp_count"):
            assert key in item


@pytest.mark.asyncio
async def test_sessions_detail_includes_fingerprint_ttps_events(
    api_base: str, access_token: str
) -> None:
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=10,
        headers={"Authorization": f"Bearer {access_token}"},
    ) as client:
        listing = await client.get(
            "/api/sessions", params={"limit": 5, "min_score": 50}
        )
        assert listing.status_code == 200
        items = listing.json()["items"]
        if not items:
            pytest.skip("no high-severity session available for detail test")
        sid = items[0]["id"]
        # Verify it's a real uuid (Pydantic should have already validated).
        uuid.UUID(sid)

        detail = await client.get(f"/api/sessions/{sid}")
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["id"] == sid
    assert "events" in body and "preview" in body["events"]
    assert isinstance(body["ttps"], list)


@pytest.mark.asyncio
async def test_sessions_detail_404_for_unknown_id(
    api_base: str, access_token: str
) -> None:
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=5,
        headers={"Authorization": f"Bearer {access_token}"},
    ) as client:
        r = await client.get(f"/api/sessions/{uuid.uuid4()}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_stats_overview_matches_documented_shape(
    api_base: str, access_token: str
) -> None:
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=10,
        headers={"Authorization": f"Bearer {access_token}"},
    ) as client:
        r = await client.get("/api/stats/overview", params={"days": 7})
    assert r.status_code == 200, r.text
    body = r.json()
    for key in (
        "period_days",
        "total_sessions",
        "unique_ips",
        "sessions_by_service",
        "severity_breakdown",
        "top_countries",
        "top_ttps",
        "avg_threat_score",
    ):
        assert key in body
    assert body["period_days"] == 7


@pytest.mark.asyncio
async def test_stats_ttps_returns_list_with_pct(
    api_base: str, access_token: str
) -> None:
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=10,
        headers={"Authorization": f"Bearer {access_token}"},
    ) as client:
        r = await client.get("/api/stats/ttps", params={"limit": 5, "days": 30})
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    if body:
        for item in body:
            assert {"technique_id", "name", "tactic", "count", "pct"} <= set(item)
