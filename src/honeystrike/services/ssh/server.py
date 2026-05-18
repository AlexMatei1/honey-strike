"""Paramiko ServerInterface — the heart of the SSH honeypot.

Captures, in order:

  - client banner / version string             → SSH_BANNER_GRAB (if no auth)
  - KEX algorithm negotiation                  → enriches the BANNER_GRAB
  - every authentication attempt               → SSH_AUTH_ATTEMPT
  - granted shell session and command stream   → SSH_COMMAND (see shell.py)

Authentication policy: the *grant* decision is delegated to an injected
callback (`attempt_check`) so the listener can back it with whatever store
makes sense. Production wires it to a Redis per-IP counter so the threshold
trips across many short-lived TCP connections (typical of Hydra/Medusa
scanners). The per-connection `attempt_number` is still recorded in the
event payload for analytics, separate from the grant decision.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from typing import Any

import paramiko

from honeystrike.core.events import EventType
from honeystrike.core.logging import get_logger

log = get_logger(__name__)


_MAX_USERNAME = 256
_MAX_PASSWORD = 256

# AttemptCheck signature: (src_ip) -> (cumulative_count_for_ip, grant_now)
AttemptCheck = Callable[[str], tuple[int, bool]]


def _truncate(value: str | None, limit: int) -> str:
    if value is None:
        return ""
    return value[:limit]


def _never_grant(_src_ip: str) -> tuple[int, bool]:
    """Default callback — used by unit tests that drive the grant flag directly."""
    return 0, False


class HoneypotSSHServer(paramiko.ServerInterface):
    """Per-connection Paramiko ServerInterface.

    Paramiko drives this on a worker thread (one per TCP connection). The
    capture callbacks pass primitives back to the asyncio-driven listener,
    which is responsible for persisting them. We do **not** run async code
    on this thread — instead, we buffer captured artefacts on the instance
    and the listener drains them.

    `attempt_check` runs synchronously on this thread. In production it is a
    thin wrapper that calls `asyncio.run_coroutine_threadsafe(...).result()`
    against the listener's event loop, so it sees the shared Redis counter.
    """

    def __init__(
        self,
        *,
        session_id: uuid.UUID,
        src_ip: str,
        src_port: int,
        attempt_check: AttemptCheck = _never_grant,
    ) -> None:
        super().__init__()
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self._attempt_check = attempt_check

        self.captured: list[dict[str, Any]] = []   # ordered capture log
        self.attempt_count = 0                      # per-connection only
        self.ip_attempt_count = 0                   # last cumulative IP count
        self.shell_granted = False
        self.shell_event = threading.Event()
        self.granted_username: str | None = None

    # ----- helpers ----------------------------------------------------------

    def _capture(self, event_type: EventType, payload: dict[str, Any]) -> None:
        """Buffer a captured event for the listener to persist later."""
        self.captured.append({"event_type": event_type, "payload": payload})
        log.debug(
            "ssh.captured",
            event_type=event_type.value,
            session_id=str(self.session_id),
            src_ip=self.src_ip,
        )

    def _record_attempt(
        self,
        *,
        auth_type: str,
        username: str,
        password: str | None = None,
        key_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        self.attempt_count += 1
        payload: dict[str, Any] = {
            "auth_type": auth_type,
            "username": _truncate(username, _MAX_USERNAME),
            "attempt_number": self.attempt_count,  # in this TCP connection
            "success": False,
        }
        if password is not None:
            payload["password"] = _truncate(password, _MAX_PASSWORD)
        if key_fingerprint is not None:
            payload["key_fingerprint"] = key_fingerprint
        self._capture(EventType.SSH_AUTH_ATTEMPT, payload)
        return payload

    # ----- Paramiko callbacks ----------------------------------------------

    def get_allowed_auths(self, username: str) -> str:  # noqa: ARG002 — paramiko API
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        payload = self._record_attempt(
            auth_type="password", username=username, password=password
        )

        try:
            ip_count, grant = self._attempt_check(self.src_ip)
        except Exception as exc:
            # If the counter is unreachable we fail-closed (no grant).
            # Capture the failure so the operator can see it.
            log.warning(
                "ssh.attempt_check_failed",
                error=str(exc),
                src_ip=self.src_ip,
                session_id=str(self.session_id),
            )
            return paramiko.AUTH_FAILED

        self.ip_attempt_count = ip_count
        payload["ip_attempt_number"] = ip_count

        if grant:
            payload["success"] = True
            self.shell_granted = True
            self.granted_username = _truncate(username, _MAX_USERNAME)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Capture the fingerprint, not the key itself (per docs/08).
        try:
            fingerprint = key.get_fingerprint().hex()
        except Exception:
            fingerprint = "unknown"
        self._record_attempt(
            auth_type="publickey",
            username=username,
            key_fingerprint=fingerprint,
        )
        # Always reject pubkey — interesting data is the fingerprint itself.
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:  # noqa: ARG002
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(  # noqa: PLR0913 — paramiko API surface
        self,
        channel: paramiko.Channel,  # noqa: ARG002
        term: bytes,                # noqa: ARG002
        width: int,                 # noqa: ARG002
        height: int,                # noqa: ARG002
        pixelwidth: int,            # noqa: ARG002
        pixelheight: int,           # noqa: ARG002
        modes: bytes,               # noqa: ARG002
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:  # noqa: ARG002
        self.shell_event.set()
        return True

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes  # noqa: ARG002
    ) -> bool:
        """Single-command (`ssh user@host 'cmd'`) — capture and accept."""
        decoded = command.decode("utf-8", errors="replace")
        self._capture(
            EventType.SSH_COMMAND,
            {"raw": decoded, "tokens": decoded.split()},
        )
        self.shell_event.set()
        return True
