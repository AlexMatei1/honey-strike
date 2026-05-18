"""`honeystrike register` — register with the multiplayer lobby."""

from __future__ import annotations

import asyncio
import os
from typing import Optional

import httpx
import typer

from honeystrike.cli import auth
from honeystrike.cli.output import error, info, success


async def _register(
    *, lobby_url: str, handle: str, endpoints: dict[str, str],
    discord_webhook: Optional[str],
) -> dict:
    payload = {
        "handle": handle,
        "public_endpoints": endpoints,
        "discord_webhook": discord_webhook,
    }
    async with httpx.AsyncClient(base_url=lobby_url, timeout=10) as client:
        r = await client.post("/lobby/register", json=payload)
        if r.status_code >= 400:
            raise SystemExit(f"register failed: HTTP {r.status_code} {r.text[:200]}")
        return r.json()


def register_cmd(
    lobby: Optional[str] = typer.Option(
        None, "--lobby", help="Lobby base URL (or $HONEYSTRIKE_LOBBY_URL)."),
    handle: Optional[str] = typer.Option(None, "--handle"),
    public_ssh: Optional[str] = typer.Option(None, "--public-ssh"),
    public_http: Optional[str] = typer.Option(None, "--public-http"),
    public_ftp: Optional[str] = typer.Option(None, "--public-ftp"),
    public_rdp: Optional[str] = typer.Option(None, "--public-rdp"),
    public_tls: Optional[str] = typer.Option(None, "--public-tls"),
    discord_webhook: Optional[str] = typer.Option(
        None, "--discord-webhook",
        help="Optional. Shared channel for match summaries.",
    ),
) -> None:
    """Register your handle + public endpoints with the lobby."""
    lobby = lobby or os.environ.get("HONEYSTRIKE_LOBBY_URL") or typer.prompt("Lobby URL")
    handle = handle or typer.prompt("Handle")
    endpoints = {
        "ssh": public_ssh,
        "http": public_http,
        "ftp": public_ftp,
        "rdp": public_rdp,
        "tls": public_tls,
    }
    endpoints = {k: v for k, v in endpoints.items() if v}
    discord = discord_webhook or os.environ.get("DISCORD_WEBHOOK_URL")

    info(f"→ POST {lobby}/lobby/register as {handle!r}")
    try:
        data = asyncio.run(_register(
            lobby_url=lobby, handle=handle, endpoints=endpoints,
            discord_webhook=discord,
        ))
    except SystemExit as exc:
        error(str(exc))
        raise

    auth.save_lobby(url=lobby, handle=handle, token=data["token"])
    auth.save_public_endpoints(endpoints)
    auth.save_discord_webhook(discord)
    success(f"Registered as {handle!r} (player_id={data.get('player_id','?')[:8]}).")
    info(f"Public endpoints: {endpoints}")
