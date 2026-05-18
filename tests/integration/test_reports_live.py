"""Live end-to-end report pipeline test.

Asserts the full chain: API trigger → Redis stream → ReportWorker → file on
disk → `reports` row → `GET /api/sessions/{id}/report` streams the file back.
"""

from __future__ import annotations

import os
import socket
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.models import Report, Session

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
    # Cold-start argon2 verification can take up to ~15s on the first call
    # after the container boots; subsequent logins are <1s. Allow generously.
    async with httpx.AsyncClient(base_url=base, timeout=30) as client:
        r = await client.post(
            "/api/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )
        r.raise_for_status()
        return r.json()["access_token"]


async def _latest_scored_session_id(db: AsyncSession) -> uuid.UUID | None:
    row = (
        (
            await db.execute(
                select(Session)
                .where(Session.threat_score >= 50)
                .order_by(Session.started_at.desc())
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    return row.id if row else None


@pytest.mark.asyncio
async def test_trigger_endpoint_queues_a_job_and_returns_202(
    api_base: str, db: AsyncSession
) -> None:
    sid = await _latest_scored_session_id(db)
    if sid is None:
        pytest.skip("no scored session in DB to report on")
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.post(f"/api/sessions/{sid}/report", params={"format": "pdf"})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "queued"
    assert "report_id" in body


@pytest.mark.asyncio
async def test_trigger_then_download_pdf_roundtrip(
    api_base: str, db: AsyncSession, wait_for
) -> None:
    sid = await _latest_scored_session_id(db)
    if sid is None:
        pytest.skip("no scored session in DB to report on")
    token = await _login(api_base)
    before = datetime.now(UTC)

    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        # Kick the worker.
        r = await client.post(f"/api/sessions/{sid}/report", params={"format": "pdf"})
        assert r.status_code == 202, r.text

        # Wait for the worker to write the row.
        async def _row_ready() -> Report | None:
            await db.commit()           # avoid Postgres MVCC snapshot staleness
            row = (
                (
                    await db.execute(
                        select(Report)
                        .where(Report.session_id == sid)
                        .where(Report.format == "pdf")
                        .where(Report.generated_at >= before)
                        .order_by(Report.generated_at.desc())
                        .limit(1)
                    )
                )
                .scalars()
                .first()
            )
            return row if row and row.file_path else None

        row = await wait_for(_row_ready, timeout=30.0)
        assert row is not None, "report-worker did not persist a row within 30s"
        assert row.file_size_bytes is not None and row.file_size_bytes >= 1024

        # And now stream the file through the API.
        download = await client.get(
            f"/api/sessions/{sid}/report", params={"format": "pdf"}
        )
    assert download.status_code == 200, download.text
    assert download.headers["content-type"] == "application/pdf"
    body = download.content
    assert body.startswith(b"%PDF-")
    assert b"%%EOF" in body[-1024:]


@pytest.mark.asyncio
async def test_download_404_when_no_report_exists(
    api_base: str
) -> None:
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=5,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get(
            f"/api/sessions/{uuid.uuid4()}/report", params={"format": "pdf"}
        )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_trigger_rejects_invalid_format(api_base: str, db: AsyncSession) -> None:
    sid = await _latest_scored_session_id(db)
    if sid is None:
        pytest.skip("no scored session")
    token = await _login(api_base)
    async with httpx.AsyncClient(
        base_url=api_base,
        timeout=5,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.post(
            f"/api/sessions/{sid}/report", params={"format": "docx"}
        )
    assert r.status_code == 422
