"""Smoke tests for the domain event envelope (round-trip through Redis fields)."""

from __future__ import annotations

from honeystrike.core.events import (
    AttackEvent,
    EventEnvelope,
    EventType,
    Service,
)


def test_envelope_roundtrip_via_stream_fields() -> None:
    env = EventEnvelope(
        event_type=EventType.SSH_AUTH_ATTEMPT,
        session_id="11111111-1111-1111-1111-111111111111",
        service=Service.SSH,
        src_ip="1.2.3.4",
        src_port=58221,
        payload={"username": "root", "password": "123456", "success": False},
    )

    fields = env.to_stream_fields()
    restored = EventEnvelope.from_stream_fields(fields)

    assert restored.id == env.id
    assert restored.event_type is EventType.SSH_AUTH_ATTEMPT
    assert restored.service is Service.SSH
    assert restored.src_port == 58221
    assert restored.payload == env.payload
    assert restored.schema_ver == "1.0"


def test_attack_event_from_envelope() -> None:
    env = EventEnvelope(
        event_type=EventType.SESSION_OPEN,
        session_id="22222222-2222-2222-2222-222222222222",
        service=Service.HTTP,
        src_ip="8.8.8.8",
        src_port=443,
        payload={"local_port": 443},
    )
    evt = AttackEvent.from_envelope(env)
    assert evt.id == env.id
    assert evt.payload == {"local_port": 443}
    assert evt.timestamp.tzinfo is not None
