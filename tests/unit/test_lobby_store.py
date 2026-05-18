"""Tests for the lobby's SQLite-backed store.

No Docker needed — `lobby.store` uses stdlib `sqlite3` against a per-test
file in the pytest `tmp_path` fixture, so the suite runs anywhere.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from honeystrike.lobby import store


def _path(tmp_path: Path) -> Path:
    return tmp_path / "lobby.db"


def test_register_or_refresh_creates_then_refreshes(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid_a, tok_a = store.register_or_refresh(
        handle="alice", public_endpoints={"ssh": "1.2.3.4:22"},
        discord_webhook=None, path=p,
    )
    pid_b, tok_b = store.register_or_refresh(
        handle="alice", public_endpoints={"ssh": "1.2.3.4:22", "http": "1.2.3.4:80"},
        discord_webhook="https://discord.example/hook", path=p,
    )
    # Refresh keeps the player_id stable but rotates the token.
    assert pid_a == pid_b
    assert tok_a != tok_b


def test_player_by_token_returns_record_after_register(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid, tok = store.register_or_refresh(
        handle="bob", public_endpoints={}, discord_webhook=None, path=p,
    )
    found = store.player_by_token(tok, path=p)
    assert found is not None
    assert found["id"] == pid
    assert found["handle"] == "bob"


def test_player_by_token_returns_none_for_unknown(tmp_path: Path) -> None:
    p = _path(tmp_path)
    store.init_schema(p)
    assert store.player_by_token("never-issued", path=p) is None


def test_online_players_filters_by_heartbeat_grace(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid, tok = store.register_or_refresh(
        handle="cara", public_endpoints={"ssh": "c.example:22"},
        discord_webhook=None, path=p,
    )
    # Fresh — still online.
    online = store.online_players(path=p)
    assert any(o["handle"] == "cara" for o in online)

    # Simulate going stale: backdate last_heartbeat past the grace window.
    import sqlite3
    conn = sqlite3.connect(str(p))
    try:
        conn.execute(
            "UPDATE players SET last_heartbeat = ? WHERE handle = 'cara'",
            (time.time() - store.HEARTBEAT_GRACE_SECONDS - 30,),
        )
        conn.commit()
    finally:
        conn.close()
    online = store.online_players(path=p)
    assert all(o["handle"] != "cara" for o in online)


def test_invite_accept_flow_creates_match(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid_a, _ = store.register_or_refresh(
        handle="att", public_endpoints={"ssh": "a:22"}, discord_webhook=None, path=p,
    )
    pid_b, _ = store.register_or_refresh(
        handle="def", public_endpoints={"http": "b:80"}, discord_webhook=None, path=p,
    )
    code = store.create_invite(
        from_id=pid_a, to_id=pid_b, scenario="apt28", duration_seconds=120, path=p,
    )
    inv = store.get_invite(code, path=p)
    assert inv is not None
    assert inv["status"] == "pending"
    assert inv["scenario"] == "apt28"

    match = store.accept_invite(code, pid_b, path=p)
    assert match is not None
    assert match["attacker_handle"] == "att"
    assert match["defender_handle"] == "def"

    refetched = store.get_invite(code, path=p)
    assert refetched is not None
    assert refetched["status"] == "accepted"
    assert refetched["match_id"] == match["match_id"]


def test_accept_invite_rejects_wrong_recipient(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid_a, _ = store.register_or_refresh(
        handle="att2", public_endpoints={}, discord_webhook=None, path=p,
    )
    pid_b, _ = store.register_or_refresh(
        handle="def2", public_endpoints={}, discord_webhook=None, path=p,
    )
    pid_c, _ = store.register_or_refresh(
        handle="bystander", public_endpoints={}, discord_webhook=None, path=p,
    )
    code = store.create_invite(
        from_id=pid_a, to_id=pid_b, scenario="ssh-hydra",
        duration_seconds=60, path=p,
    )
    # `bystander` shouldn't be able to accept an invite intended for `def2`.
    assert store.accept_invite(code, pid_c, path=p) is None


def test_decline_invite_marks_status(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid_a, _ = store.register_or_refresh(handle="att3", public_endpoints={},
                                         discord_webhook=None, path=p)
    pid_b, _ = store.register_or_refresh(handle="def3", public_endpoints={},
                                         discord_webhook=None, path=p)
    code = store.create_invite(
        from_id=pid_a, to_id=pid_b, scenario="ssh-hydra",
        duration_seconds=60, path=p,
    )
    assert store.decline_invite(code, pid_b, path=p) is True
    inv = store.get_invite(code, path=p)
    assert inv is not None and inv["status"] == "declined"


def test_record_match_summary_persists_jsonb(tmp_path: Path) -> None:
    p = _path(tmp_path)
    pid_a, _ = store.register_or_refresh(handle="att4", public_endpoints={},
                                         discord_webhook=None, path=p)
    pid_b, _ = store.register_or_refresh(handle="def4", public_endpoints={},
                                         discord_webhook=None, path=p)
    code = store.create_invite(
        from_id=pid_a, to_id=pid_b, scenario="apt28",
        duration_seconds=60, path=p,
    )
    match = store.accept_invite(code, pid_b, path=p)
    assert match is not None

    summary = {
        "labels_correct": 3,
        "labels_total": 4,
        "first_block_at": time.time(),
        "expected_ttps": ["T1110.001", "T1190"],
    }
    store.record_match_summary(match["match_id"], summary, path=p)

    refetched = store.get_match(match["match_id"], path=p)
    assert refetched is not None
    assert refetched["summary"]["labels_correct"] == 3
    assert refetched["summary"]["expected_ttps"] == ["T1110.001", "T1190"]
