"""Tests for the TTP rules framework + STIX bundle loader."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from honeystrike.core.events import EventType
from honeystrike.workers.intel.signatures import SessionContext
from honeystrike.workers.intel.ttp_rules import (
    BUILTIN_RULES,
    EMBEDDED_TECHNIQUES,
    TTPRule,
    evaluate,
    load_attack_bundle,
    validate_rules,
)


# ---------------------------------------------------------------------------
# Embedded table sanity
# ---------------------------------------------------------------------------

def test_builtin_rules_validate_against_embedded_table() -> None:
    """Every BUILTIN_RULES.technique_id must exist in the embedded table."""
    validate_rules(BUILTIN_RULES, EMBEDDED_TECHNIQUES)


def test_validate_rules_raises_on_unknown_technique() -> None:
    bogus = TTPRule(
        technique_id="T9999",
        name="bogus",
        description="",
        confidence=0.5,
        match_fn=lambda _ctx: None,
    )
    with pytest.raises(ValueError, match="T9999"):
        validate_rules((bogus,), EMBEDDED_TECHNIQUES)


# ---------------------------------------------------------------------------
# Password-guessing rule
# ---------------------------------------------------------------------------

def _ssh_auth(ts: datetime) -> dict:
    return {
        "event_type": EventType.SSH_AUTH_ATTEMPT.value,
        "ts": ts,
        "payload": {"auth_type": "password", "username": "root", "password": "x"},
    }


def test_password_guessing_fires_over_threshold() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0,
        events=[_ssh_auth(t0 + timedelta(milliseconds=i * 20)) for i in range(7)],
    )
    matches = evaluate(ctx)
    ids = {m.technique_id for m in matches}
    assert "T1110.001" in ids


def test_password_guessing_silent_below_threshold() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0,
        events=[_ssh_auth(t0 + timedelta(milliseconds=i * 20)) for i in range(3)],
    )
    matches = evaluate(ctx)
    assert all(m.technique_id != "T1110.001" for m in matches)


def test_password_guessing_for_ftp_uses_PASS_commands() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = []
    for i in range(7):
        events.append({
            "event_type": EventType.FTP_COMMAND.value,
            "ts": t0 + timedelta(milliseconds=i * 100),
            "payload": {"command": "USER", "argument": "root"},
        })
        events.append({
            "event_type": EventType.FTP_COMMAND.value,
            "ts": t0 + timedelta(milliseconds=i * 100 + 30),
            "payload": {"command": "PASS", "argument": f"pw{i}"},
        })
    ctx = SessionContext(
        service="ftp", src_ip="1.2.3.4", started_at=t0, events=events,
    )
    matches = evaluate(ctx)
    assert any(m.technique_id == "T1110.001" for m in matches)


# ---------------------------------------------------------------------------
# Multi-service scan rule
# ---------------------------------------------------------------------------

def test_multi_service_scan_rule_fires_with_two_services() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    ctx = SessionContext(
        service="http", src_ip="1.2.3.4", started_at=t0, events=[],
        sibling_sessions=[
            {"src_ip": "1.2.3.4", "service": "ssh",
             "started_at": t0 + timedelta(seconds=10)},
        ],
    )
    matches = evaluate(ctx)
    assert any(m.technique_id == "T1595.001" for m in matches)


def test_multi_service_scan_silent_without_siblings() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    ctx = SessionContext(
        service="http", src_ip="1.2.3.4", started_at=t0, events=[],
    )
    matches = evaluate(ctx)
    assert all(m.technique_id != "T1595.001" for m in matches)


# ---------------------------------------------------------------------------
# STIX loader
# ---------------------------------------------------------------------------

def test_load_attack_bundle_with_missing_path_returns_embedded() -> None:
    table = load_attack_bundle(None)
    assert "T1110.001" in table
    assert table["T1110.001"].tactic == "Credential Access"


def test_load_attack_bundle_with_nonexistent_file_returns_embedded() -> None:
    table = load_attack_bundle("/no/such/path.json")
    assert "T1110.001" in table


def test_load_attack_bundle_parses_valid_stix(tmp_path: Path) -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Brute Force: Password Guessing",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1110.001"},
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
                ],
            },
            # An object we should skip.
            {"type": "marking-definition"},
        ],
    }
    path = tmp_path / "stix.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    table = load_attack_bundle(path)
    assert "T1110.001" in table
    assert table["T1110.001"].name == "Brute Force: Password Guessing"
    assert table["T1110.001"].tactic == "Credential Access"


def test_load_attack_bundle_with_malformed_json_falls_back(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not json at all", encoding="utf-8")
    table = load_attack_bundle(path)
    # Fallback table is non-empty.
    assert "T1110.001" in table


# ---------------------------------------------------------------------------
# Evaluate dedup
# ---------------------------------------------------------------------------

def test_evaluate_dedups_by_technique_id() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_ssh_auth(t0 + timedelta(milliseconds=i * 20)) for i in range(8)]
    ctx = SessionContext(
        service="ssh", src_ip="1.2.3.4", started_at=t0, events=events,
        sibling_sessions=[
            {"src_ip": "1.2.3.4", "service": "ftp",
             "started_at": t0 + timedelta(seconds=15)},
        ],
    )
    matches = evaluate(ctx)
    technique_ids = [m.technique_id for m in matches]
    # Sorted by confidence descending — scan-IP (0.95) before brute-force (0.90).
    assert technique_ids.index("T1595.001") < technique_ids.index("T1110.001")


# ---------------------------------------------------------------------------
# T1110.004 — Credential Stuffing
# ---------------------------------------------------------------------------

def _ssh_auth_with_user(ts: datetime, username: str) -> dict:
    return {
        "event_type": EventType.SSH_AUTH_ATTEMPT.value,
        "ts": ts,
        "payload": {"auth_type": "password", "username": username, "password": "x"},
    }


def test_credential_stuffing_fires_with_many_distinct_users() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    users = ["root", "admin", "oracle", "ubuntu", "postgres"]
    events = [
        _ssh_auth_with_user(t0 + timedelta(milliseconds=i * 30), u)
        for i, u in enumerate(users)
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1110.004" in ids


def test_credential_stuffing_silent_with_one_username_only() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_ssh_auth_with_user(t0 + timedelta(milliseconds=i * 30), "root") for i in range(7)]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1110.004" not in ids


# ---------------------------------------------------------------------------
# T1190 — Exploit Public-Facing Application
# ---------------------------------------------------------------------------

def _http_request(ts: datetime, **payload) -> dict:
    return {
        "event_type": EventType.HTTP_REQUEST.value,
        "ts": ts,
        "payload": payload,
    }


def test_exploit_public_app_fires_on_cve_signature() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_http_request(t0, uri="/api/v1/health", cve_signature="CVE-2021-44228")]
    ctx = SessionContext(service="http", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1190" in ids


def test_exploit_public_app_fires_on_sqli_pattern() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_http_request(t0, uri="/login", sqli_pattern=True)]
    ctx = SessionContext(service="http", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1190" in ids


def test_exploit_public_app_silent_on_benign_request() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_http_request(t0, uri="/", sqli_pattern=False, cve_signature=None)]
    ctx = SessionContext(service="http", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1190" not in ids


# ---------------------------------------------------------------------------
# T1083 — File and Directory Discovery
# ---------------------------------------------------------------------------

def test_file_discovery_fires_on_http_path_traversal() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_http_request(t0, uri="/files?path=../../etc/passwd", path_traversal=True)]
    ctx = SessionContext(service="http", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1083" in ids


def test_file_discovery_fires_on_ssh_recon_command() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {"event_type": EventType.SSH_COMMAND.value, "ts": t0,
         "payload": {"raw": "ls -la /root"}},
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1083" in ids


def test_file_discovery_silent_on_non_recon_command() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {"event_type": EventType.SSH_COMMAND.value, "ts": t0,
         "payload": {"raw": "exit"}},
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1083" not in ids


# ---------------------------------------------------------------------------
# T1592 — Gather Victim Host Information
# ---------------------------------------------------------------------------

def test_victim_host_info_fires_on_env_path() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_http_request(t0, uri="/.env", uri_decoded="/.env")]
    ctx = SessionContext(service="http", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1592" in ids


def test_victim_host_info_fires_on_uname_command() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {"event_type": EventType.SSH_COMMAND.value, "ts": t0,
         "payload": {"raw": "uname -a"}},
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1592" in ids


def test_victim_host_info_silent_on_homepage_request() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [_http_request(t0, uri="/", uri_decoded="/")]
    ctx = SessionContext(service="http", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1592" not in ids


# ---------------------------------------------------------------------------
# T1078 — Valid Accounts
# ---------------------------------------------------------------------------

def test_valid_accounts_fires_on_granted_auth_plus_command() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {"event_type": EventType.SSH_AUTH_ATTEMPT.value, "ts": t0,
         "payload": {"username": "root", "auth_type": "password", "success": True}},
        {"event_type": EventType.SSH_COMMAND.value, "ts": t0 + timedelta(seconds=1),
         "payload": {"raw": "whoami"}},
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1078" in ids


def test_valid_accounts_silent_without_grant() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {"event_type": EventType.SSH_AUTH_ATTEMPT.value, "ts": t0,
         "payload": {"username": "root", "auth_type": "password", "success": False}},
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1078" not in ids


def test_valid_accounts_silent_without_post_auth_command() -> None:
    t0 = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)
    events = [
        {"event_type": EventType.SSH_AUTH_ATTEMPT.value, "ts": t0,
         "payload": {"username": "root", "auth_type": "password", "success": True}},
    ]
    ctx = SessionContext(service="ssh", src_ip="1.2.3.4", started_at=t0, events=events)
    ids = {m.technique_id for m in evaluate(ctx)}
    assert "T1078" not in ids
