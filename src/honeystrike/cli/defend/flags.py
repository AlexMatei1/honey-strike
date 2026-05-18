"""`honeystrike defend flags-found` — CTF canary captures.

A canary capture is an attacker REQUESTING a path / typing a command that
the honeypot answers with canary-bearing content. Because we capture
requests (not responses, per docs/08), the check is:

  - HTTP events whose `payload.uri` (or `uri_decoded`) starts with any of
    the canary's `trigger_uris`.
  - SSH events whose `payload.raw` contains any of the `trigger_commands`.

That's exactly what an attacker "found" — they pulled the canary-bearing
endpoint or ran the canary-yielding command.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import typer
from sqlalchemy import select

from honeystrike.cli.attack import canaries
from honeystrike.cli.defend import defend_app
from honeystrike.cli.output import console, info, make_table
from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.models import Event, Session


def _canary_for_event(event_type: str, payload: dict) -> str | None:
    """Return the canary slug an event triggered, or None."""
    if event_type == "HTTP_REQUEST":
        uri = (payload.get("uri_decoded") or payload.get("uri") or "").lower()
        for c in canaries.ALL_CANARIES:
            for trig in c.trigger_uris:
                if uri.startswith(trig.lower()):
                    return c.slug
    elif event_type == "SSH_COMMAND":
        raw = (payload.get("raw") or "").lower()
        for c in canaries.ALL_CANARIES:
            for trig in c.trigger_commands:
                if trig.lower() in raw:
                    return c.slug
    return None


async def _query(*, days: int, slug_filter: str, limit: int) -> list[dict]:
    since = datetime.now(UTC) - timedelta(days=days)
    async with session_scope() as db:
        stmt = (
            select(Event.id, Event.session_id, Event.event_type, Event.ts,
                   Event.payload, Session.service, Session.src_ip)
            .join(Session, Session.id == Event.session_id)
            .where(Event.ts >= since)
            .where(Event.event_type.in_(["HTTP_REQUEST", "SSH_COMMAND"]))
            .order_by(Event.ts.desc())
            .limit(max(limit * 4, 100))
        )
        rows = (await db.execute(stmt)).all()

    out: list[dict] = []
    for r in rows:
        slug = _canary_for_event(r.event_type, r.payload or {})
        if slug is None:
            continue
        if slug_filter != "all" and slug != slug_filter:
            continue
        out.append({
            "ts": r.ts,
            "session_id": str(r.session_id),
            "service": r.service,
            "src_ip": str(r.src_ip),
            "event_type": r.event_type,
            "canary": slug,
        })
        if len(out) >= limit:
            break
    return out


@defend_app.command("flags-found", help="Canary strings the attacker grabbed.")
def flags_cmd(
    limit: int = typer.Option(25, "--limit"),
    days: int = typer.Option(7, "--days"),
    canary: str = typer.Option("all", "--canary",
                                help="aws-key | passwd | admin-token | all"),
) -> None:
    if canary != "all" and canary not in {c.slug for c in canaries.ALL_CANARIES}:
        raise typer.BadParameter(
            f"unknown canary {canary!r}. Try: "
            + ", ".join(c.slug for c in canaries.ALL_CANARIES) + " | all"
        )
    rows = asyncio.run(_run(limit=limit, days=days, slug=canary))
    if not rows:
        info("no canary captures in window")
        return
    t = make_table("time", "src_ip", "service", "canary", "event_type", "session",
                   title=f"canary captures ({days}d)")
    for r in rows:
        t.add_row(
            str(r["ts"])[:19],
            r["src_ip"],
            r["service"],
            r["canary"],
            r["event_type"],
            r["session_id"][:8],
        )
    console.print(t)


async def _run(*, limit: int, days: int, slug: str) -> list[dict]:
    try:
        return await _query(days=days, slug_filter=slug, limit=limit)
    finally:
        await dispose_engine()
