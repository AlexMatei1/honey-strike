"""Tests for the tool-signature library."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from honeystrike.core.events import EventType
from honeystrike.workers.intel.signatures import (
    SessionContext,
    evaluate,
)


def _ssh_attempt(username: str, password: str, ts: datetime) -> dict:
    return {
        "event_type": EventType.SSH_AUTH_ATTEMPT.value,
        "ts": ts,
        "payload": {
            "auth_type": "password",
            "username": username,
            "password": password,
            "success": False,
        },
    }


def _ssh_banner(version: str, ts: datetime) -> dict:
    return {
        "event_type": EventType.SSH_BANNER_GRAB.value,
        "ts": ts,
        "payload": {"client_version": version},
    }


def test_ssh_banner_rule_matches_libssh() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0,
        events=[_ssh_banner("SSH-2.0-libssh_0.9.6", t0)],
    )
    matches = evaluate(ctx)
    names = [m.name for m in matches]
    assert "libssh-based tool" in names


def test_ssh_cred_wordlist_rule_matches_hydra_pattern() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        _ssh_attempt("root", "root", t0),
        _ssh_attempt("root", "toor", t0 + timedelta(milliseconds=20)),
        _ssh_attempt("admin", "admin", t0 + timedelta(milliseconds=40)),
        _ssh_attempt("test", "test", t0 + timedelta(milliseconds=60)),
    ]
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0, events=events
    )
    matches = evaluate(ctx)
    hydra_match = next(m for m in matches if m.name == "Hydra")
    assert hydra_match.confidence >= 0.65


def test_ssh_attempt_burst_rule_flags_high_rate() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    # 6 attempts in 200ms = 30 attempts/sec → "high-rate"
    events = [_ssh_attempt(f"user{i}", "pw", t0 + timedelta(milliseconds=i * 40))
              for i in range(6)]
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0, events=events
    )
    matches = evaluate(ctx)
    burst = next(m for m in matches if "brute-force" in m.name)
    assert burst.confidence > 0.5


def test_ftp_cred_wordlist_rule_matches_paired_user_pass() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = []
    for i, (u, p) in enumerate([("root", "root"), ("root", "toor"), ("admin", "admin")]):
        events.append({
            "event_type": EventType.FTP_COMMAND.value,
            "ts": t0 + timedelta(milliseconds=i * 100),
            "payload": {"command": "USER", "argument": u},
        })
        events.append({
            "event_type": EventType.FTP_COMMAND.value,
            "ts": t0 + timedelta(milliseconds=i * 100 + 50),
            "payload": {"command": "PASS", "argument": p},
        })
    ctx = SessionContext(
        service="ftp", src_ip="1.2.3.4", started_at=t0, events=events
    )
    matches = evaluate(ctx)
    assert any("Hydra" in m.name for m in matches)


def test_http_user_agent_rule_delegates_to_detectors() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {
            "event_type": EventType.HTTP_REQUEST.value,
            "ts": t0,
            "payload": {
                "method": "GET",
                "uri": "/.env",
                "headers": {"User-Agent": "sqlmap/1.7.8"},
            },
        }
    ]
    ctx = SessionContext(
        service="http", src_ip="1.2.3.4", started_at=t0, events=events
    )
    matches = evaluate(ctx)
    assert any(m.name == "sqlmap" for m in matches)


def test_multi_service_scan_rule_fires_on_three_services_in_window() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    siblings = [
        {"src_ip": "1.2.3.4", "service": "ssh",
         "started_at": t0 + timedelta(seconds=5)},
        {"src_ip": "1.2.3.4", "service": "ftp",
         "started_at": t0 + timedelta(seconds=12)},
        # Different IP shouldn't contribute.
        {"src_ip": "9.9.9.9", "service": "rdp",
         "started_at": t0 + timedelta(seconds=8)},
    ]
    ctx = SessionContext(
        service="http", src_ip="1.2.3.4", started_at=t0, events=[],
        sibling_sessions=siblings,
    )
    matches = evaluate(ctx)
    assert any("Masscan" in m.name or "Multi-service" in m.name for m in matches)


def test_rdp_protocols_rule_fires_for_PROTOCOL_RDP_only() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {
            "event_type": EventType.RDP_CONNECT.value,
            "ts": t0,
            "payload": {"mstshash": "guest", "requested_protocols": 0},
        }
    ]
    ctx = SessionContext(
        service="rdp", src_ip="1.2.3.4", started_at=t0, events=events
    )
    matches = evaluate(ctx)
    assert any("Internet-wide" in m.name for m in matches)


def test_clean_session_produces_no_matches() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0,
        events=[_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", t0)],
    )
    matches = evaluate(ctx)
    # OpenSSH-vanilla banner shouldn't match any tool rule.
    assert matches == []


def test_evaluate_dedups_by_tool_name_keeping_higher_confidence() -> None:
    """Multiple rules can label the same tool; the higher-confidence wins."""
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    # Two distinct rule paths to "Hydra" — banner + cred wordlist.
    events = [
        _ssh_banner("SSH-2.0-libssh_0.9.6 hydra", t0),  # matches hydra (0.95)
        _ssh_attempt("root", "root", t0),
        _ssh_attempt("root", "toor", t0 + timedelta(milliseconds=10)),
        _ssh_attempt("admin", "admin", t0 + timedelta(milliseconds=20)),
    ]
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0, events=events
    )
    matches = evaluate(ctx)
    hydra_matches = [m for m in matches if m.name == "Hydra"]
    # Banner rule's direct "Hydra" match wins over the wordlist rule's variant.
    assert len(hydra_matches) == 1
    assert hydra_matches[0].confidence == 0.95
