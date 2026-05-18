"""Tiny SQLite layer for the lobby. Sync stdlib `sqlite3` — the lobby is
low-traffic (a handful of friends), so async DB drivers are overkill.

Tables (one file, default `/data/lobby.db`):

  players(id PK, handle UNIQUE, token_hash, public_endpoints JSON,
          discord_webhook, last_heartbeat, created_at)
  invites(code PK, from_player, to_player, scenario, duration_seconds,
          expires_at, status, match_id, created_at)
  matches(id PK, attacker_id, defender_id, scenario, started_at, ends_at,
          summary JSON)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DEFAULT_PATH = Path(os.environ.get("LOBBY_DB_PATH", "/data/lobby.db"))
INVITE_TTL_SECONDS = 120
HEARTBEAT_GRACE_SECONDS = 60


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _now() -> float:
    return time.time()


@contextmanager
def _connect(path: Path = DEFAULT_PATH) -> Iterator[sqlite3.Connection]:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        conn.close()


def init_schema(path: Path = DEFAULT_PATH) -> None:
    with _connect(path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS players (
            id TEXT PRIMARY KEY,
            handle TEXT NOT NULL UNIQUE,
            token_hash TEXT NOT NULL,
            public_endpoints TEXT NOT NULL DEFAULT '{}',
            discord_webhook TEXT,
            last_heartbeat REAL NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY,
            from_player TEXT NOT NULL REFERENCES players(id),
            to_player TEXT NOT NULL REFERENCES players(id),
            scenario TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL DEFAULT 300,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            match_id TEXT,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_invites_to ON invites(to_player, status);
        CREATE TABLE IF NOT EXISTS matches (
            id TEXT PRIMARY KEY,
            attacker_id TEXT NOT NULL REFERENCES players(id),
            defender_id TEXT NOT NULL REFERENCES players(id),
            scenario TEXT NOT NULL,
            started_at REAL NOT NULL,
            ends_at REAL NOT NULL,
            summary TEXT
        );
        """)


# ---------------------------------------------------------------------------
# Players
# ---------------------------------------------------------------------------

def register_or_refresh(
    *,
    handle: str,
    public_endpoints: dict[str, str],
    discord_webhook: str | None,
    path: Path = DEFAULT_PATH,
) -> tuple[str, str]:
    """Returns `(player_id, plaintext_token)`. Idempotent — re-running for the
    same `handle` refreshes the token and endpoints."""
    init_schema(path)
    token = secrets.token_hex(32)
    th = _hash_token(token)
    pid = str(uuid.uuid4())
    now = _now()
    payload = json.dumps(public_endpoints)
    with _connect(path) as conn:
        existing = conn.execute(
            "SELECT id FROM players WHERE handle = ?", (handle,)
        ).fetchone()
        if existing:
            pid = existing["id"]
            conn.execute(
                "UPDATE players SET token_hash=?, public_endpoints=?, "
                "discord_webhook=?, last_heartbeat=? WHERE id=?",
                (th, payload, discord_webhook, now, pid),
            )
        else:
            conn.execute(
                "INSERT INTO players(id, handle, token_hash, public_endpoints, "
                "discord_webhook, last_heartbeat, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (pid, handle, th, payload, discord_webhook, now, now),
            )
    return pid, token


def heartbeat(player_id: str, *, path: Path = DEFAULT_PATH) -> None:
    with _connect(path) as conn:
        conn.execute("UPDATE players SET last_heartbeat=? WHERE id=?",
                     (_now(), player_id))


def player_by_token(token: str, *, path: Path = DEFAULT_PATH) -> dict[str, Any] | None:
    th = _hash_token(token)
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM players WHERE token_hash = ?", (th,),
        ).fetchone()
    if not row:
        return None
    return _row_to_player(row)


def player_by_handle(handle: str, *, path: Path = DEFAULT_PATH) -> dict[str, Any] | None:
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM players WHERE handle = ?", (handle,),
        ).fetchone()
    return _row_to_player(row) if row else None


def online_players(*, path: Path = DEFAULT_PATH) -> list[dict[str, Any]]:
    cutoff = _now() - HEARTBEAT_GRACE_SECONDS
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT * FROM players WHERE last_heartbeat >= ? "
            "ORDER BY last_heartbeat DESC",
            (cutoff,),
        ).fetchall()
    return [_row_to_player(r) for r in rows]


def _row_to_player(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "handle": row["handle"],
        "public_endpoints": json.loads(row["public_endpoints"] or "{}"),
        "discord_webhook": row["discord_webhook"],
        "last_heartbeat": row["last_heartbeat"],
    }


# ---------------------------------------------------------------------------
# Invites
# ---------------------------------------------------------------------------

def create_invite(
    *, from_id: str, to_id: str, scenario: str, duration_seconds: int,
    path: Path = DEFAULT_PATH,
) -> str:
    code = secrets.token_urlsafe(8)
    now = _now()
    with _connect(path) as conn:
        conn.execute(
            "INSERT INTO invites(code, from_player, to_player, scenario, "
            "duration_seconds, expires_at, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (code, from_id, to_id, scenario, duration_seconds,
             now + INVITE_TTL_SECONDS, "pending", now),
        )
    return code


def pending_invites_for(player_id: str, *, path: Path = DEFAULT_PATH) -> list[dict[str, Any]]:
    now = _now()
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT i.*, p.handle AS from_handle "
            "FROM invites i JOIN players p ON p.id = i.from_player "
            "WHERE i.to_player = ? AND i.status = 'pending' AND i.expires_at >= ? "
            "ORDER BY i.created_at DESC",
            (player_id, now),
        ).fetchall()
    return [
        {
            "invite_code": r["code"],
            "from_handle": r["from_handle"],
            "scenario": r["scenario"],
            "duration_seconds": r["duration_seconds"],
            "expires_at": r["expires_at"],
        } for r in rows
    ]


def get_invite(code: str, *, path: Path = DEFAULT_PATH) -> dict[str, Any] | None:
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT i.*, p.handle AS from_handle FROM invites i "
            "JOIN players p ON p.id = i.from_player WHERE i.code = ?", (code,),
        ).fetchone()
    if not row:
        return None
    return {
        "invite_code": row["code"],
        "from_handle": row["from_handle"],
        "from_player": row["from_player"],
        "to_player": row["to_player"],
        "scenario": row["scenario"],
        "duration_seconds": row["duration_seconds"],
        "expires_at": row["expires_at"],
        "status": row["status"],
        "match_id": row["match_id"],
    }


def accept_invite(code: str, accepter_id: str, *, path: Path = DEFAULT_PATH) -> dict[str, Any] | None:
    invite = get_invite(code, path=path)
    if not invite or invite["to_player"] != accepter_id:
        return None
    if invite["status"] != "pending" or invite["expires_at"] < _now():
        return None
    match_id = str(uuid.uuid4())
    started = _now()
    ends = started + invite["duration_seconds"]
    with _connect(path) as conn:
        conn.execute(
            "INSERT INTO matches(id, attacker_id, defender_id, scenario, "
            "started_at, ends_at) VALUES (?,?,?,?,?,?)",
            (match_id, invite["from_player"], invite["to_player"],
             invite["scenario"], started, ends),
        )
        conn.execute(
            "UPDATE invites SET status='accepted', match_id=? WHERE code=?",
            (match_id, code),
        )
    return get_match(match_id, path=path)


def decline_invite(code: str, decliner_id: str, *, path: Path = DEFAULT_PATH) -> bool:
    invite = get_invite(code, path=path)
    if not invite or invite["to_player"] != decliner_id or invite["status"] != "pending":
        return False
    with _connect(path) as conn:
        conn.execute("UPDATE invites SET status='declined' WHERE code=?", (code,))
    return True


# ---------------------------------------------------------------------------
# Matches
# ---------------------------------------------------------------------------

def get_match(match_id: str, *, path: Path = DEFAULT_PATH) -> dict[str, Any] | None:
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT m.*, "
            " pa.handle AS attacker_handle, pd.handle AS defender_handle, "
            " pa.public_endpoints AS attacker_endpoints, "
            " pd.public_endpoints AS defender_endpoints, "
            " pa.discord_webhook AS attacker_discord, "
            " pd.discord_webhook AS defender_discord "
            "FROM matches m "
            "JOIN players pa ON pa.id = m.attacker_id "
            "JOIN players pd ON pd.id = m.defender_id "
            "WHERE m.id = ?",
            (match_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "match_id": row["id"],
        "attacker_handle": row["attacker_handle"],
        "defender_handle": row["defender_handle"],
        "attacker_endpoint": json.loads(row["attacker_endpoints"] or "{}"),
        "defender_endpoint": json.loads(row["defender_endpoints"] or "{}"),
        "scenario": row["scenario"],
        "started_at": row["started_at"],
        "ends_at": row["ends_at"],
        "summary": json.loads(row["summary"]) if row["summary"] else None,
        "attacker_discord": row["attacker_discord"],
        "defender_discord": row["defender_discord"],
    }


def record_match_summary(match_id: str, summary: dict[str, Any],
                         *, path: Path = DEFAULT_PATH) -> None:
    with _connect(path) as conn:
        conn.execute(
            "UPDATE matches SET summary=? WHERE id=?",
            (json.dumps(summary), match_id),
        )
