"""`honeystrike defend listen` — long-running multiplayer match listener.

Polls the lobby for incoming invites; on accept, enters match mode:
  1. attaches to the local `/api/ws/live` WebSocket
  2. for each scored session, prompts for a TTP label
  3. correct labels call `POST /api/defender/label` (which optionally blocks)
  4. at match end (timer expires or lobby reports finish) prints summary
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

import httpx
import typer
import websockets

from honeystrike.cli import auth
from honeystrike.cli.defend import defend_app
from honeystrike.cli.defend.tail import _ws_url
from honeystrike.cli.http_client import api_client, require_token
from honeystrike.cli.output import banner, console, error, info, success, warn


_DEFAULT_POLL_SECONDS = 5.0


async def _poll_invites(lobby_url: str, lobby_token: str, handle: str):
    """Yield each new invite dict as it arrives."""
    seen: set[str] = set()
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {lobby_token}"},
    ) as client:
        while True:
            try:
                r = await client.get(f"/lobby/invites/{handle}")
                if r.status_code == 200:
                    for inv in r.json():
                        code = inv["invite_code"]
                        if code in seen:
                            continue
                        seen.add(code)
                        yield inv
            except httpx.HTTPError:
                pass
            await asyncio.sleep(_DEFAULT_POLL_SECONDS)


async def _accept(lobby_url: str, lobby_token: str, code: str) -> dict | None:
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {lobby_token}"},
    ) as client:
        r = await client.post("/lobby/accept", json={"invite_code": code})
    if r.status_code == 200:
        return r.json()
    error(f"accept failed: HTTP {r.status_code} {r.text[:200]}")
    return None


async def _finish(lobby_url: str, lobby_token: str, match_id: str, summary: dict) -> None:
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {lobby_token}"},
    ) as client:
        await client.post(f"/lobby/match/{match_id}/finish", json=summary)


async def _match_loop(
    match: dict, *, api_token: str, label_timeout: int, block: bool,
) -> dict:
    """For each session-message, prompt for a label, dispatch via API."""
    ends_at = match.get("ends_at") or (time.time() + 300)
    url = _ws_url(api_token, poll=2.0)
    labels_correct = 0
    labels_total = 0
    blocked_at: float | None = None

    banner(f"🎮 Match {match['match_id'][:8]} — scenario={match['scenario']}")
    info(f"defending until {time.ctime(ends_at)}")

    async with websockets.connect(url) as ws:
        while time.time() < ends_at:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=max(1.0, ends_at - time.time()))
            except asyncio.TimeoutError:
                break
            msg = json.loads(raw)
            if msg.get("type") != "session":
                continue
            console.print(
                f"[bold]{msg['service'].upper()}[/bold] from {msg['src_ip']} "
                f"score={msg['threat_score']} {msg['severity']}"
            )
            try:
                guess = await asyncio.wait_for(
                    asyncio.to_thread(typer.prompt, "Label TTP (or 'skip')"),
                    timeout=label_timeout,
                )
            except asyncio.TimeoutError:
                warn("label timeout — moving on")
                continue
            if guess.strip().lower() == "skip" or not guess.strip():
                continue
            labels_total += 1
            async with api_client() as client:
                r = await client.post("/api/defender/label", json={
                    "session_id": msg["session_id"],
                    "technique_id": guess.strip().upper(),
                    "match_id": match["match_id"],
                    "block": block,
                    "ttl_seconds": 300,
                })
                data = r.json() if r.status_code < 400 else {}
            if data.get("correct"):
                labels_correct += 1
                success(f"✓ {guess.upper()} — attacker blocked")
                if blocked_at is None:
                    blocked_at = time.time()
            else:
                warn("wrong label")
                actual = data.get("actual_ttps") or []
                if actual:
                    info("session has: " + ", ".join(actual))
    return {
        "labels_total": labels_total,
        "labels_correct": labels_correct,
        "first_block_at": blocked_at,
    }


@defend_app.command("listen", help="Wait for and play incoming multiplayer matches.")
def listen_cmd(
    auto_accept: bool = typer.Option(False, "--auto-accept"),
    auto_accept_from: Optional[str] = typer.Option(
        None, "--auto-accept-from",
        help="Comma-separated handles to auto-accept; others still prompt.",
    ),
    label_timeout: int = typer.Option(30, "--label-timeout"),
    no_block: bool = typer.Option(False, "--no-block"),
    bell: bool = typer.Option(True, "--bell/--no-bell"),
) -> None:
    require_token()
    lob = auth.lobby_section()
    if not lob.get("url") or not lob.get("token") or not lob.get("handle"):
        error("not registered with a lobby — run `honeystrike register` first")
        raise SystemExit(1)

    info(f"listening as {lob['handle']!r} on {lob['url']} — Ctrl-C to stop")
    trusted = set((auto_accept_from or "").split(",")) if auto_accept_from else set()

    async def _loop() -> None:
        async for invite in _poll_invites(lob["url"], lob["token"], lob["handle"]):
            from_handle = invite["from_handle"]
            console.rule(f"🚨 {from_handle} challenges you ({invite['scenario']}, {invite.get('duration_seconds',300)}s)")
            if bell:
                console.bell()
            accept = (
                auto_accept
                or from_handle in trusted
                or typer.confirm("Accept?", default=True)
            )
            if not accept:
                info("declined")
                continue
            match = await _accept(lob["url"], lob["token"], invite["invite_code"])
            if match is None:
                continue
            auth.set_current_match(match["match_id"])
            try:
                summary = await _match_loop(
                    match,
                    api_token=auth.resolve_token() or "",
                    label_timeout=label_timeout,
                    block=not no_block,
                )
            finally:
                auth.set_current_match(None)
            await _finish(lob["url"], lob["token"], match["match_id"], summary)
            success(f"match done: {summary['labels_correct']}/{summary['labels_total']} correct")

    try:
        asyncio.run(_loop())
    except (asyncio.CancelledError, KeyboardInterrupt):
        info("stopped")
