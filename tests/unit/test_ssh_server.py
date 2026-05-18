"""Pure logic tests for the SSH ServerInterface — no Paramiko transport needed."""

from __future__ import annotations

import uuid

import paramiko

from honeystrike.core.events import EventType
from honeystrike.services.ssh.server import HoneypotSSHServer


def _stub_attempt_check(threshold: int):
    """Stand-in for the production Redis-backed per-IP counter."""
    counter = {"n": 0}

    def _check(src_ip: str) -> tuple[int, bool]:
        counter["n"] += 1
        return counter["n"], counter["n"] >= threshold

    return _check


def _make_server(threshold: int = 3) -> HoneypotSSHServer:
    return HoneypotSSHServer(
        session_id=uuid.uuid4(),
        src_ip="10.0.0.1",
        src_port=51234,
        attempt_check=_stub_attempt_check(threshold),
    )


def test_first_passwords_fail_until_threshold() -> None:
    srv = _make_server(threshold=3)

    assert srv.check_auth_password("root", "123456") == paramiko.AUTH_FAILED
    assert srv.check_auth_password("root", "password") == paramiko.AUTH_FAILED
    # Third attempt is granted.
    assert srv.check_auth_password("root", "qwerty") == paramiko.AUTH_SUCCESSFUL

    assert srv.shell_granted is True
    assert srv.granted_username == "root"
    assert srv.attempt_count == 3
    assert srv.ip_attempt_count == 3

    # All three are recorded as SSH_AUTH_ATTEMPT.
    events = [c for c in srv.captured if c["event_type"] is EventType.SSH_AUTH_ATTEMPT]
    assert len(events) == 3
    assert events[-1]["payload"]["success"] is True
    assert events[0]["payload"]["success"] is False
    # Each event carries both counters for analytics.
    assert events[-1]["payload"]["attempt_number"] == 3
    assert events[-1]["payload"]["ip_attempt_number"] == 3


def test_publickey_attempt_records_fingerprint_not_key() -> None:
    srv = _make_server()
    key = paramiko.RSAKey.generate(2048)
    result = srv.check_auth_publickey("admin", key)

    # Pubkey is always rejected (per design — we only want the fingerprint).
    assert result == paramiko.AUTH_FAILED
    assert srv.captured[0]["payload"]["auth_type"] == "publickey"
    assert srv.captured[0]["payload"]["key_fingerprint"] == key.get_fingerprint().hex()
    assert "password" not in srv.captured[0]["payload"]


def test_password_truncation_at_256_chars() -> None:
    srv = _make_server(threshold=10)
    huge_pw = "A" * 1024
    srv.check_auth_password("u", huge_pw)
    assert len(srv.captured[0]["payload"]["password"]) == 256


def test_exec_request_records_command() -> None:
    srv = _make_server()
    channel = None  # unused inside the callback
    accepted = srv.check_channel_exec_request(channel, b"cat /etc/passwd")
    assert accepted is True
    assert srv.shell_event.is_set()
    cmds = [c for c in srv.captured if c["event_type"] is EventType.SSH_COMMAND]
    assert cmds[0]["payload"]["raw"] == "cat /etc/passwd"
    assert cmds[0]["payload"]["tokens"] == ["cat", "/etc/passwd"]


def test_channel_request_only_session_allowed() -> None:
    srv = _make_server()
    assert srv.check_channel_request("session", 0) == paramiko.OPEN_SUCCEEDED
    assert (
        srv.check_channel_request("direct-tcpip", 0)
        == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    )


def test_attempt_check_failure_fails_closed() -> None:
    """If the Redis counter is unreachable, never grant — log and reject."""

    def _broken(_src_ip: str) -> tuple[int, bool]:
        raise RuntimeError("redis down")

    srv = HoneypotSSHServer(
        session_id=uuid.uuid4(),
        src_ip="10.0.0.1",
        src_port=1234,
        attempt_check=_broken,
    )
    assert srv.check_auth_password("root", "x") == paramiko.AUTH_FAILED
    # The attempt is still captured for the analytics pipeline.
    assert len(srv.captured) == 1
    assert srv.captured[0]["payload"]["success"] is False


def test_default_attempt_check_never_grants() -> None:
    """No-argument tests should never trip the threshold accidentally."""
    srv = HoneypotSSHServer(
        session_id=uuid.uuid4(), src_ip="10.0.0.1", src_port=1234
    )
    for _ in range(10):
        assert srv.check_auth_password("root", "x") == paramiko.AUTH_FAILED
    assert srv.shell_granted is False
