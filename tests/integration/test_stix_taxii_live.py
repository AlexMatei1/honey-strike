"""Live STIX 2.1 + TAXII 2.1 endpoint integration test.

Confirms that with real session data in the DB, both surfaces serve a
valid STIX bundle through their respective routes. Auth-less hits 401.
"""

from __future__ import annotations

import os
import socket

import httpx
import pytest

API_HOST = os.getenv("DASHBOARD_API_HOST", "127.0.0.1")
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


async def _login(base: str) -> str:
    async with httpx.AsyncClient(base_url=base, timeout=30) as client:
        r = await client.post(
            "/api/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )
        r.raise_for_status()
        return r.json()["access_token"]


@pytest.mark.asyncio
async def test_stix_stats_requires_auth(api_base: str) -> None:
    async with httpx.AsyncClient(base_url=api_base, timeout=10) as client:
        r = await client.get("/api/stix/stats")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_stix_bundle_returns_well_formed_stix(api_base: str) -> None:
    token = await _login(api_base)
    # Bundle build is mostly STIX-object construction in Python; for a DB
    # with hundreds of matching sessions it can take a few seconds. Give
    # the request plenty of headroom — failure here means a real regression.
    async with httpx.AsyncClient(
        base_url=api_base, timeout=60,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get("/api/stix/bundle", params={"days": 30, "min_score": 50, "limit": 25})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == "bundle"
    assert body["id"].startswith("bundle--")
    obj_types = {o["type"] for o in body["objects"]}
    assert "identity" in obj_types


@pytest.mark.asyncio
async def test_taxii_discovery_returns_taxii_content_type(api_base: str) -> None:
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get("/taxii2/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/taxii+json")
    body = r.json()
    assert body["default"] == "/taxii2/v1/"


@pytest.mark.asyncio
async def test_taxii_collection_lists_high_severity(api_base: str) -> None:
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get("/taxii2/v1/collections/")
    assert r.status_code == 200
    coll = r.json()["collections"][0]
    assert coll["id"] == "honeystrike-high-severity"
    assert coll["can_read"] is True
    assert coll["can_write"] is False


@pytest.mark.asyncio
async def test_taxii_objects_returns_stix_bundle(api_base: str) -> None:
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base, timeout=30,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get(
            "/taxii2/v1/collections/honeystrike-high-severity/objects/",
            params={"days": 30, "min_score": 50, "limit": 10},
        )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/stix+json")
    body = r.json()
    assert body["type"] == "bundle"


@pytest.mark.asyncio
async def test_taxii_404_on_unknown_collection(api_base: str) -> None:
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get("/taxii2/v1/collections/nonexistent/")
    assert r.status_code == 404
