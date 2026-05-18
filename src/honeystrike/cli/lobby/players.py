"""`honeystrike players` — list online lobby players."""

from __future__ import annotations

import asyncio
import json

import httpx
import typer

from honeystrike.cli import auth
from honeystrike.cli.output import console, error, make_table, out


async def _list(lobby_url: str, token: str) -> list[dict]:
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.get("/lobby/players")
        if r.status_code >= 400:
            raise SystemExit(f"list failed: HTTP {r.status_code} {r.text[:200]}")
        return r.json()


def players_cmd(
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    lob = auth.lobby_section()
    if not lob.get("url") or not lob.get("token"):
        error("not registered with a lobby — run `honeystrike register` first")
        raise SystemExit(1)
    try:
        rows = asyncio.run(_list(lob["url"], lob["token"]))
    except SystemExit as exc:
        error(str(exc))
        raise

    if as_json:
        out.print_json(json.dumps(rows))
        return
    if not rows:
        console.print("[dim]no players online[/dim]")
        return
    t = make_table("handle", "online_for", "services", "last_seen",
                   title="online players")
    for p in rows:
        services = ", ".join(sorted((p.get("public_endpoints") or {}).keys())) or "—"
        t.add_row(p["handle"], p.get("online_for", "—"), services,
                  p.get("last_seen", "—"))
    console.print(t)
