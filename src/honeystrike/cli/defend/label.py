"""`honeystrike defend label <session_id> <technique_id>` — one-shot TTP label.

Calls the dashboard API's `POST /api/defender/label` (new in Phase 6) which:
  - records the labelling event on the session
  - if the label matches an actual `ttp_matches.technique_id` for the session,
    optionally blocks the attacker's `src_ip` for `--ttl` seconds.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Optional

import typer

from honeystrike.cli.defend import defend_app
from honeystrike.cli.http_client import api_client, require_token, run_async
from honeystrike.cli.output import error, info, success, warn


@defend_app.command("label",
                    help="Label a session's TTP. Correct labels block the attacker.")
def label_cmd(
    session_id: uuid.UUID = typer.Argument(..., help="Session to label."),
    technique_id: str = typer.Argument(..., help="MITRE technique e.g. T1110.001"),
    match_id: Optional[str] = typer.Option(
        None, "--match-id",
        help="Match identifier — inferred from config.toml if omitted.",
    ),
    block: bool = typer.Option(True, "--block/--no-block",
                                help="Block the attacker's IP on correct label."),
    ttl: int = typer.Option(300, "--ttl",
                              help="Block TTL (seconds)."),
) -> None:
    require_token()

    async def _go() -> None:
        body = {
            "session_id": str(session_id),
            "technique_id": technique_id.upper(),
            "match_id": match_id,
            "block": block,
            "ttl_seconds": ttl,
        }
        async with api_client() as client:
            r = await client.post("/api/defender/label", json=body)
            if r.status_code == 401:
                error("not authenticated")
                raise SystemExit(1)
            if r.status_code == 404:
                error(f"session not found: {session_id}")
                raise SystemExit(1)
            if r.status_code >= 400:
                error(f"HTTP {r.status_code}: {r.text[:200]}")
                raise SystemExit(1)
            data = r.json()
        if data.get("correct"):
            success(f"✓ {technique_id} matched — attacker {data.get('blocked_ip')} "
                    f"blocked for {data.get('ttl_seconds')}s")
        else:
            warn(f"{technique_id} not attributed to this session")
            actual = data.get("actual_ttps") or []
            if actual:
                info("session has: " + ", ".join(actual))

    run_async(_go())
