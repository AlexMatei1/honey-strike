"""Custom pyftpdlib handler that captures every FTP command.

Design notes:

  - pyftpdlib's `FTPHandler` runs in a single-threaded asyncore-style loop;
    callbacks fire on the main thread. We can call into the same asyncio
    event loop directly (no thread-bridging like SSH).
  - We override `on_connect`, `on_disconnect`, and `process_command` so we
    capture *every* command — including malformed ones the protocol stack
    would otherwise reject silently.
  - Auth policy: we ACCEPT every credential pair after the first PASS, so
    attackers see the same "230 Login successful" they would on a misconfigured
    real server. This maximises the post-auth tradecraft we collect (LIST,
    CWD, RETR paths). Credentials are still captured as the raw payload.
  - Path size cap: 1 KB per docs/08 §3.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from typing import Any

from pyftpdlib.handlers import FTPHandler

from honeystrike.core import blocklist
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import get_logger

log = get_logger(__name__)


# Path / argument caps from docs/08 §3.
_MAX_ARG_BYTES = 1024

_FAKE_HOME = "/tmp"
_FAKE_PERMS = "elradfmw"   # full permission string so LIST/RETR/STOR don't trip 550


class AcceptAllAuthorizer:
    """Authoriser that accepts every credential pair and reports full perms.

    Implements the minimum surface pyftpdlib calls. Attackers see "230 Login
    successful" regardless of credentials; LIST/RETR/STOR commands are still
    captured before the (intentionally unreachable) data channel times out.
    """

    def validate_authentication(self, username: str, password: str, handler: Any) -> None:  # noqa: ARG002, D401
        return None  # always succeed

    def has_user(self, username: str) -> bool:  # noqa: ARG002
        return True

    def has_perm(self, username: str, perm: str, path: str | None = None) -> bool:  # noqa: ARG002
        return True

    def get_home_dir(self, username: str) -> str:  # noqa: ARG002
        return _FAKE_HOME

    def get_perms(self, username: str) -> str:  # noqa: ARG002
        return _FAKE_PERMS

    def get_msg_login(self, username: str) -> str:  # noqa: ARG002
        return "Login successful."

    def get_msg_quit(self, username: str) -> str:  # noqa: ARG002
        return "Goodbye."

    def impersonate_user(self, username: str, password: str) -> None:  # noqa: ARG002
        return None

    def terminate_impersonation(self, username: str) -> None:  # noqa: ARG002
        return None


class HoneypotFTPHandler(FTPHandler):
    """One instance per FTP connection.

    pyftpdlib instantiates handlers via `connection_made` from its asyncore-
    style loop, so we receive shared dependencies through class attributes
    set up in `configure_handler_class()`. Attempts to inject via __init__
    fight the framework.
    """

    # ---- class-level injected deps (filled by configure_handler_class) -----
    bus: EventBus
    asyncio_loop: asyncio.AbstractEventLoop
    local_port: int
    session_open_cb: Any           # async (src_ip, src_port) -> uuid.UUID
    session_close_cb: Any          # async (**kw) -> None
    record_event_cb: Any           # async (...) -> None

    # ---- per-connection state ----------------------------------------------
    _session_id: uuid.UUID | None = None
    _start_time: float = 0.0
    _event_count: int = 0
    _captured_username: str | None = None

    # ----- lifecycle --------------------------------------------------------

    def on_connect(self) -> None:
        self._start_time = time.monotonic()
        self._event_count = 0
        self._captured_username = None

        src_ip = self.remote_ip
        src_port = self.remote_port

        # Phase 6 blocking — refuse defender-blocked IPs.
        try:
            blocked = asyncio.run_coroutine_threadsafe(
                blocklist.is_blocked(self.bus.client, src_ip), self.asyncio_loop
            ).result(timeout=5)
        except Exception:                                   # noqa: BLE001
            blocked = False
        if blocked:
            log.info("ftp.connection_blocked", src_ip=src_ip, src_port=src_port)
            with contextlib.suppress(Exception):
                self.close_when_done()
            return

        try:
            self._session_id = asyncio.run_coroutine_threadsafe(
                self.session_open_cb(src_ip, src_port), self.asyncio_loop
            ).result(timeout=10)
        except Exception as exc:
            log.error("ftp.session_open_failed", error=str(exc), src_ip=src_ip)
            with contextlib.suppress(Exception):
                self.close_when_done()

    def on_disconnect(self) -> None:
        if self._session_id is None:
            return
        duration_ms = int((time.monotonic() - self._start_time) * 1000)
        try:
            asyncio.run_coroutine_threadsafe(
                self.session_close_cb(
                    session_id=self._session_id,
                    service=Service.FTP,
                    src_ip=self.remote_ip,
                    src_port=self.remote_port,
                    event_count=self._event_count,
                    duration_ms=duration_ms,
                    close_reason="client_disconnect",
                ),
                self.asyncio_loop,
            ).result(timeout=10)
        except Exception as exc:
            log.error(
                "ftp.session_close_failed",
                error=str(exc),
                session_id=str(self._session_id),
            )

    # ----- command capture --------------------------------------------------

    def process_command(self, cmd: str, *args: Any, **kwargs: Any) -> None:
        """Capture every command before pyftpdlib dispatches it.

        We DO call super().process_command() so the protocol pipeline still
        sends realistic responses. Capture happens first so even commands
        that pyftpdlib later rejects (bad syntax) are recorded.
        """
        argument = args[0] if args else ""
        argument_str = argument if isinstance(argument, str) else str(argument)

        # Truncate per docs/08.
        argument_clipped = argument_str[:_MAX_ARG_BYTES]

        payload: dict[str, Any] = {
            "command": cmd,
            "argument": argument_clipped,
        }
        # Special handling: capture creds inline rather than rely on the user
        # eventually authenticating.
        cmd_upper = cmd.upper()
        if cmd_upper == "USER":
            self._captured_username = argument_clipped
            payload["captured_username"] = argument_clipped
        elif cmd_upper == "PASS":
            payload["captured_password"] = argument_clipped
            payload["paired_username"] = self._captured_username

        self._emit(payload)

        try:
            super().process_command(cmd, *args, **kwargs)
        except Exception as exc:
            log.warning("ftp.process_command_error", cmd=cmd, error=str(exc))

    # ----- helpers ----------------------------------------------------------

    def _emit(self, payload: dict[str, Any]) -> None:
        if self._session_id is None:
            return
        self._event_count += 1
        try:
            asyncio.run_coroutine_threadsafe(
                self.record_event_cb(
                    session_id=self._session_id,
                    event_type=EventType.FTP_COMMAND,
                    service=Service.FTP,
                    src_ip=self.remote_ip,
                    src_port=self.remote_port,
                    payload=payload,
                ),
                self.asyncio_loop,
            ).result(timeout=5)
        except Exception as exc:
            log.error(
                "ftp.event_persist_failed",
                error=str(exc),
                session_id=str(self._session_id),
                cmd=payload.get("command"),
            )


def configure_handler_class(
    *,
    bus: EventBus,
    asyncio_loop: asyncio.AbstractEventLoop,
    local_port: int,
    session_open_cb: Any,
    session_close_cb: Any,
    record_event_cb: Any,
    banner: str,
) -> type[HoneypotFTPHandler]:
    """Build a configured handler subclass for pyftpdlib's FTPServer.

    Returns a *new* subclass so multiple listeners (e.g. in tests) don't share
    state through class-level attributes.
    """
    name = f"ConfiguredHoneypotFTPHandler_{id(asyncio_loop)}"
    subclass: type[HoneypotFTPHandler] = type(  # type: ignore[assignment]
        name,
        (HoneypotFTPHandler,),
        {
            "bus": bus,
            "asyncio_loop": asyncio_loop,
            "local_port": local_port,
            "session_open_cb": staticmethod(session_open_cb),
            "session_close_cb": staticmethod(session_close_cb),
            "record_event_cb": staticmethod(record_event_cb),
            "banner": banner,
            "authorizer": AcceptAllAuthorizer(),
        },
    )
    return subclass
