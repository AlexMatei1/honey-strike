"""`honeystrike defend tail` — live WebSocket stream of scored sessions."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
import websockets

from honeystrike.cli import auth
from honeystrike.cli.defend import defend_app
from honeystrike.cli.http_client import require_token
from honeystrike.cli.output import console, error, info, make_table, score_text, severity_text


def _ws_url(token: str, poll: float) -> str:
    base = auth.resolve_api_base()
    # http -> ws, https -> wss
    if base.startswith("https"):
        ws_base = "wss" + base[len("https"):]
    else:
        ws_base = "ws" + base[len("http"):]
    return f"{ws_base}/api/ws/live?token={token}&poll={poll}"


async def _tail_stream(
    *, token: str, poll: float, severity_filter: Optional[str],
    service_filter: Optional[str], rich: bool,
) -> None:
    url = _ws_url(token, poll)
    info(f"connecting to {url.split('?')[0]} …")
    try:
        async with websockets.connect(url) as ws:
            info("connected — Ctrl-C to stop")
            t = None
            if rich:
                t = make_table("time", "service", "src_ip", "country",
                               "ttps", "score", "severity",
                               title="live sessions")
            while True:
                raw = await ws.recv()
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if msg.get("type") != "session":
                    if msg.get("type") == "seed_complete":
                        info(f"seed: {msg.get('count', 0)} session(s)")
                    continue
                if severity_filter and msg.get("severity") != severity_filter:
                    continue
                if service_filter and msg.get("service") != service_filter:
                    continue
                if rich and t is not None:
                    t.add_row(
                        msg.get("started_at", "")[:19].replace("T", " "),
                        msg.get("service", ""),
                        msg.get("src_ip", ""),
                        msg.get("country_iso") or "—",
                        str(msg.get("ttp_count", 0)),
                        score_text(msg.get("threat_score")),
                        severity_text(msg.get("severity")),
                    )
                    console.clear()
                    console.print(t)
                else:
                    console.print(
                        f"[dim]{msg.get('started_at','')[:19]}[/dim] "
                        f"{msg.get('service','')[:4]:4} "
                        f"{msg.get('src_ip','')} "
                        f"score={msg.get('threat_score')} "
                        f"{msg.get('severity')}"
                    )
    except (asyncio.CancelledError, KeyboardInterrupt):
        info("interrupted")
    except websockets.WebSocketException as exc:
        error(f"WebSocket failed: {exc}")
        raise SystemExit(1)


@defend_app.command("tail", help="Live stream of newly-scored sessions.")
def tail_cmd(
    severity: Optional[str] = typer.Option(None, "--severity"),
    service: Optional[str] = typer.Option(None, "--service"),
    poll: float = typer.Option(2.0, "--poll", min=0.5, max=30.0),
    rich: bool = typer.Option(True, "--rich/--no-rich"),
) -> None:
    token = require_token()
    asyncio.run(_tail_stream(
        token=token, poll=poll,
        severity_filter=severity, service_filter=service, rich=rich,
    ))
