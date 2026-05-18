"""Lobby HTTP API — invite-code matchmaking + Discord summary post.

Endpoints (all responses are application/json):

  POST /lobby/register        register / refresh a player
  POST /lobby/heartbeat       keepalive (call every 30s)
  GET  /lobby/players         list online players
  POST /lobby/invite          create an invite (Bearer auth = inviter)
  GET  /lobby/invites/{handle} pending invites for that handle (Bearer auth = recipient)
  POST /lobby/accept          accept an invite (Bearer auth = recipient)
  POST /lobby/decline         decline an invite
  GET  /lobby/invite/{code}   inspect a single invite (used by attacker to poll for accept)
  GET  /lobby/match/{id}      fetch match metadata
  POST /lobby/match/{id}/finish  record + (optionally) post summary to Discord

Auth: the Bearer token returned at `register` time. The token is hashed
in SQLite (sha256) and never logged in plaintext.
"""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from honeystrike.lobby import store

app = FastAPI(
    title="HoneyStrike Lobby",
    version="0.1.0",
    docs_url="/lobby/docs",
    openapi_url="/lobby/openapi.json",
)

_bearer = HTTPBearer(auto_error=False)


async def current_player(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, Any]:
    if creds is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    player = store.player_by_token(creds.credentials)
    if not player:
        raise HTTPException(status_code=401, detail="invalid token")
    # Treat the call itself as a heartbeat.
    store.heartbeat(player["id"])
    return player


# ---------------------------------------------------------------------------
# Pydantic IO
# ---------------------------------------------------------------------------

class RegisterIn(BaseModel):
    handle: str = Field(..., min_length=1, max_length=64)
    public_endpoints: dict[str, str] = Field(default_factory=dict)
    discord_webhook: str | None = None


class RegisterOut(BaseModel):
    player_id: str
    token: str


class InviteIn(BaseModel):
    to_handle: str
    scenario: str
    duration_seconds: int = Field(300, ge=30, le=3600)


class InviteOut(BaseModel):
    invite_code: str


class AcceptIn(BaseModel):
    invite_code: str


class DeclineIn(BaseModel):
    invite_code: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/lobby/register", response_model=RegisterOut)
async def register(body: RegisterIn) -> RegisterOut:
    pid, token = store.register_or_refresh(
        handle=body.handle,
        public_endpoints=body.public_endpoints,
        discord_webhook=body.discord_webhook,
    )
    return RegisterOut(player_id=pid, token=token)


@app.post("/lobby/heartbeat")
async def heartbeat(
    player: Annotated[dict[str, Any], Depends(current_player)],
) -> dict[str, bool]:
    return {"ok": True}


@app.get("/lobby/players")
async def players() -> list[dict[str, Any]]:
    out = []
    for p in store.online_players():
        out.append({
            "handle": p["handle"],
            "public_endpoints": p["public_endpoints"],
            "last_seen": p["last_heartbeat"],
            "online_for": _humanise(time.time() - p["last_heartbeat"]),
        })
    return out


@app.post("/lobby/invite", response_model=InviteOut)
async def post_invite(
    body: InviteIn,
    player: Annotated[dict[str, Any], Depends(current_player)],
) -> InviteOut:
    target = store.player_by_handle(body.to_handle)
    if not target:
        raise HTTPException(status_code=404, detail=f"no such handle {body.to_handle!r}")
    code = store.create_invite(
        from_id=player["id"], to_id=target["id"],
        scenario=body.scenario, duration_seconds=body.duration_seconds,
    )
    return InviteOut(invite_code=code)


@app.get("/lobby/invites/{handle}")
async def list_invites(
    handle: str,
    player: Annotated[dict[str, Any], Depends(current_player)],
) -> list[dict[str, Any]]:
    if player["handle"] != handle:
        raise HTTPException(status_code=403, detail="can only list your own invites")
    return store.pending_invites_for(player["id"])


@app.get("/lobby/invite/{code}")
async def get_invite_status(code: str) -> dict[str, Any]:
    inv = store.get_invite(code)
    if not inv:
        raise HTTPException(status_code=404, detail="unknown invite")
    out: dict[str, Any] = {
        "status": inv["status"],
        "scenario": inv["scenario"],
        "duration_seconds": inv["duration_seconds"],
    }
    if inv["status"] == "accepted" and inv["match_id"]:
        match = store.get_match(inv["match_id"])
        if match:
            out["match"] = match
    return out


@app.post("/lobby/accept")
async def accept(
    body: AcceptIn,
    player: Annotated[dict[str, Any], Depends(current_player)],
) -> dict[str, Any]:
    match = store.accept_invite(body.invite_code, player["id"])
    if not match:
        raise HTTPException(status_code=400, detail="invite is invalid, expired, or not for you")
    return match


@app.post("/lobby/decline")
async def decline(
    body: DeclineIn,
    player: Annotated[dict[str, Any], Depends(current_player)],
) -> dict[str, bool]:
    ok = store.decline_invite(body.invite_code, player["id"])
    if not ok:
        raise HTTPException(status_code=400, detail="cannot decline this invite")
    return {"ok": True}


@app.get("/lobby/match/{match_id}")
async def get_match(match_id: str) -> dict[str, Any]:
    match = store.get_match(match_id)
    if not match:
        raise HTTPException(status_code=404, detail="match not found")
    # Don't leak webhooks back to clients.
    match.pop("attacker_discord", None)
    match.pop("defender_discord", None)
    return match


@app.post("/lobby/match/{match_id}/finish")
async def finish_match(match_id: str, body: dict[str, Any]) -> dict[str, Any]:
    match = store.get_match(match_id)
    if not match:
        raise HTTPException(status_code=404, detail="match not found")
    store.record_match_summary(match_id, body)
    posted = []
    for hook in (match.get("attacker_discord"), match.get("defender_discord")):
        if hook:
            try:
                await _post_to_discord(hook, _format_summary(match, body))
                posted.append(True)
            except httpx.HTTPError:
                posted.append(False)
    return {"ok": True, "discord_posts": len([p for p in posted if p])}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _humanise(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    return f"{int(seconds // 3600)}h ago"


def _format_summary(match: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    """Build the Discord embed for a match summary."""
    correct = summary.get("labels_correct", 0)
    total = summary.get("labels_total", 0)
    first_block = summary.get("first_block_at")
    phases = summary.get("phases", "?")
    embed = {
        "title": f"🎮 HoneyStrike match {match['match_id'][:8]}",
        "description": (
            f"**Attacker:** {match['attacker_handle']}  →  "
            f"**Defender:** {match['defender_handle']}\n"
            f"Scenario: `{match['scenario']}`  ·  "
            f"phases fired: {phases}"
        ),
        "color": 0x58a6ff,
        "fields": [
            {"name": "Labels correct", "value": f"{correct} / {total}", "inline": True},
            {"name": "First block",
             "value": f"<t:{int(first_block)}:R>" if first_block else "—",
             "inline": True},
            {"name": "Expected TTPs",
             "value": ", ".join(summary.get("expected_ttps", [])) or "—",
             "inline": False},
        ],
    }
    return {"embeds": [embed]}


async def _post_to_discord(webhook_url: str, body: dict[str, Any]) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(webhook_url, json=body)
        r.raise_for_status()
