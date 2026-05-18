"""`honeystrike defend campaign-score <campaign_id>` — TTP attribution grade.

Reads the campaign envelope written by `attack campaign` to Redis
(`hs:campaign:{uuid}`) and joins `ttp_matches` from `started_at..ended_at`
to compute coverage.
"""

from __future__ import annotations

import asyncio
import json

import redis.asyncio as aioredis
import typer
from sqlalchemy import distinct, func, select

from honeystrike.cli.defend import defend_app
from honeystrike.cli.output import console, error, info, make_table, severity_text
from honeystrike.config import get_settings
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.models import Session, TTPMatch


async def _envelope(campaign_id: str) -> dict | None:
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url)
    try:
        raw = await client.get(f"hs:campaign:{campaign_id}")
    finally:
        await client.aclose()
    return json.loads(raw) if raw else None


async def _detected_ttps(envelope: dict) -> tuple[set[str], int]:
    from datetime import UTC, datetime

    started = datetime.fromtimestamp(envelope["started_at"], tz=UTC)
    ended_ts = envelope.get("ended_at") or envelope["started_at"] + 600
    ended = datetime.fromtimestamp(ended_ts, tz=UTC)

    async with session_scope() as db:
        # Distinct techniques attributed within the window.
        techs = (
            await db.execute(
                select(distinct(TTPMatch.technique_id))
                .join(Session, Session.id == TTPMatch.session_id)
                .where(Session.started_at >= started)
                .where(Session.started_at <= ended)
            )
        ).scalars().all()
        # Peak score across the window.
        peak = (
            await db.execute(
                select(func.coalesce(func.max(Session.threat_score), 0))
                .where(Session.started_at >= started)
                .where(Session.started_at <= ended)
            )
        ).scalar_one()
    return set(techs), int(peak)


@defend_app.command("campaign-score",
                    help="Grade a finished campaign — TTP attribution accuracy.")
def campaign_score_cmd(
    campaign_id: str = typer.Argument(...),
    ttp_only: bool = typer.Option(False, "--ttp-only"),
) -> None:
    async def _go() -> None:
        env = await _envelope(campaign_id)
        if not env:
            error(f"unknown campaign {campaign_id} (expired or never recorded)")
            raise SystemExit(1)
        detected, peak = await _detected_ttps(env)
        expected = set(env.get("expected_ttps") or [])
        matched = expected & detected
        missed = expected - detected
        extra = detected - expected

        if not ttp_only:
            console.rule(f"[bold cyan]Campaign {env['name']} — {campaign_id[:8]}[/bold cyan]")
            info(env.get("description", ""))
            info(f"Steps fired: {', '.join(env.get('steps', []))}")
            info(f"Peak threat score: {peak}/100 ({severity_text(_band(peak))})")
            console.print()

        t = make_table("expected TTP", "matched?", title="coverage")
        for tid in sorted(expected):
            mark = "[green]✓[/green]" if tid in matched else "[red]✗[/red]"
            t.add_row(tid, mark)
        if extra:
            for tid in sorted(extra):
                t.add_row(f"[dim]{tid}[/dim]", "[yellow]extra[/yellow]")
        console.print(t)
        coverage = (len(matched) / len(expected) * 100) if expected else 0.0
        info(f"Coverage: {len(matched)} / {len(expected)} = {coverage:.0f}%")

    try:
        asyncio.run(_go())
    finally:
        asyncio.run(dispose_engine())


def _band(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"
