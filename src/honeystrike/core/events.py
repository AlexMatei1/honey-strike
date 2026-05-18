"""Domain event types — mirrors `docs/03_Domain_Events.md`.

Every captured attacker interaction is serialised as an `EventEnvelope` and
written to the Redis stream `honeystrike:events`. Workers consume the stream
via consumer groups (`intel`, `report`, `dashboard`).

`schema_ver` is bumped per the rules in doc 03 §"Schema Versioning".
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

SCHEMA_VERSION = "1.0"


class Service(StrEnum):
    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    RDP = "rdp"
    TLS = "tls"


class EventType(StrEnum):
    SESSION_OPEN = "SESSION_OPEN"
    SESSION_CLOSE = "SESSION_CLOSE"
    SSH_BANNER_GRAB = "SSH_BANNER_GRAB"
    SSH_AUTH_ATTEMPT = "SSH_AUTH_ATTEMPT"
    SSH_COMMAND = "SSH_COMMAND"
    HTTP_REQUEST = "HTTP_REQUEST"
    FTP_COMMAND = "FTP_COMMAND"
    RDP_CONNECT = "RDP_CONNECT"
    TLS_CLIENT_HELLO = "TLS_CLIENT_HELLO"
    TTP_MATCHED = "TTP_MATCHED"
    ALERT_DISPATCHED = "ALERT_DISPATCHED"


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


@dataclass(slots=True, frozen=True)
class EventEnvelope:
    """Wire format for every event published to the Redis stream."""

    event_type: EventType
    session_id: str
    service: Service
    src_ip: str
    src_port: int
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_utcnow_iso)
    schema_ver: str = SCHEMA_VERSION

    def to_stream_fields(self) -> dict[str, str]:
        """Flatten to Redis Streams field/value map (all strings)."""
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "session_id": self.session_id,
            "service": self.service.value,
            "src_ip": self.src_ip,
            "src_port": str(self.src_port),
            "timestamp": self.timestamp,
            "schema_ver": self.schema_ver,
            "payload": json.dumps(self.payload, separators=(",", ":")),
        }

    @classmethod
    def from_stream_fields(cls, fields: dict[str, str]) -> Self:
        return cls(
            id=fields["id"],
            event_type=EventType(fields["event_type"]),
            session_id=fields["session_id"],
            service=Service(fields["service"]),
            src_ip=fields["src_ip"],
            src_port=int(fields["src_port"]),
            timestamp=fields["timestamp"],
            schema_ver=fields.get("schema_ver", SCHEMA_VERSION),
            payload=json.loads(fields["payload"]) if fields.get("payload") else {},
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["service"] = self.service.value
        return d


@dataclass(slots=True, frozen=True)
class AttackEvent:
    """In-process representation of an event (no transport concerns).

    Used by workers as the canonical type after deserialising from the stream.
    `payload` is decoded as a dict, not a JSON string.
    """

    id: str
    event_type: EventType
    session_id: str
    service: Service
    src_ip: str
    src_port: int
    timestamp: datetime
    payload: dict[str, Any]
    schema_ver: str = SCHEMA_VERSION

    @classmethod
    def from_envelope(cls, env: EventEnvelope) -> Self:
        return cls(
            id=env.id,
            event_type=env.event_type,
            session_id=env.session_id,
            service=env.service,
            src_ip=env.src_ip,
            src_port=env.src_port,
            timestamp=datetime.fromisoformat(env.timestamp),
            payload=dict(env.payload),
            schema_ver=env.schema_ver,
        )
