"""Tests for the TLS_CLIENT_HELLO → ja3_hash extraction in the FingerprintWorker."""

from __future__ import annotations

from honeystrike.core.events import EventType
from honeystrike.workers.intel.fingerprint import _extract_ja3_hash


def test_extract_ja3_picks_first_client_hello() -> None:
    rows = [
        {"event_type": EventType.SESSION_OPEN.value, "payload": {}},
        {
            "event_type": EventType.TLS_CLIENT_HELLO.value,
            "payload": {"ja3_hash": "abc123", "sni": "evil.example"},
        },
        {
            "event_type": EventType.TLS_CLIENT_HELLO.value,
            "payload": {"ja3_hash": "later-overrides-shouldnt-win"},
        },
    ]
    assert _extract_ja3_hash(rows) == "abc123"


def test_extract_ja3_returns_none_when_unparseable_record() -> None:
    rows = [
        {
            "event_type": EventType.TLS_CLIENT_HELLO.value,
            "payload": {"parseable": False, "raw_record_bytes": 0},
        }
    ]
    assert _extract_ja3_hash(rows) is None


def test_extract_ja3_returns_none_for_non_tls_sessions() -> None:
    rows = [
        {"event_type": EventType.SSH_AUTH_ATTEMPT.value, "payload": {"username": "root"}},
        {"event_type": EventType.HTTP_REQUEST.value, "payload": {"uri": "/"}},
    ]
    assert _extract_ja3_hash(rows) is None


def test_extract_ja3_tolerates_missing_payload_dict() -> None:
    rows = [{"event_type": EventType.TLS_CLIENT_HELLO.value}]
    assert _extract_ja3_hash(rows) is None
