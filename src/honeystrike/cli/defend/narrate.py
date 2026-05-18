"""`honeystrike defend narrate` — natural-language stream over /api/ws/live."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
import websockets

from honeystrike.cli import auth
from honeystrike.cli.defend import defend_app
from honeystrike.cli.defend.tail import _ws_url
from honeystrike.cli.http_client import require_token
from honeystrike.cli.output import console, error, info


_SEVERITY_COLOR = {
    "low": "green",
    "medium": "yellow",
    "high": "orange3",
    "critical": "red",
}


def _format(msg: dict, template: str) -> str:
    sev = msg.get("severity", "low")
    color = _SEVERITY_COLOR.get(sev, "white")
    score = msg.get("threat_score", 0)
    src = msg.get("src_ip", "?")
    country = msg.get("country_iso") or "??"
    service = msg.get("service", "?")
    ts = (msg.get("started_at") or "")[11:19]
    if template == "long":
        return (
            f"[dim]{ts}[/dim] [{color}]{sev.upper():8}[/{color}] "
            f"score=[bold]{score}[/bold] — "
            f"{src} ([italic]{country}[/italic]) hit "
            f"[bold]{service.upper()}[/bold] · "
            f"events=[cyan]{msg.get('ttp_count',0)}[/cyan] TTPs · "
            f"sessionid=[dim]{(msg.get('session_id') or '')[:8]}[/dim]"
        )
    return (
        f"[dim]{ts}[/dim] [{color}]{sev.upper()}[/{color}] {score:3d} "
        f"— {src} ({country}) hit [bold]{service.upper()}[/bold] "
        f"· {msg.get('ttp_count', 0)} TTPs"
    )


async def _narrate(
    *, token: str, severity_filter: Optional[str],
    bell: bool, template: str, poll: float = 2.0,
) -> None:
    url = _ws_url(token, poll)
    info(f"connecting to {url.split('?')[0]} …")
    try:
        async with websockets.connect(url) as ws:
            info("connected — Ctrl-C to stop")
            while True:
                raw = await ws.recv()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if msg.get("type") != "session":
                    continue
                if severity_filter and msg.get("severity") != severity_filter:
                    continue
                console.print(_format(msg, template))
                if bell and msg.get("severity") == "critical":
                    console.bell()
    except (asyncio.CancelledError, KeyboardInterrupt):
        info("interrupted")
    except websockets.WebSocketException as exc:
        error(f"WebSocket failed: {exc}")
        raise SystemExit(1)


@defend_app.command("narrate", help="Natural-language live narration of attacks.")
def narrate_cmd(
    severity: Optional[str] = typer.Option(None, "--severity"),
    bell: bool = typer.Option(False, "--bell"),
    template: str = typer.Option("short", "--template",
                                 help="short | long"),
) -> None:
    token = require_token()
    asyncio.run(_narrate(
        token=token, severity_filter=severity, bell=bell, template=template,
    ))
