"""`honeystrike defend recent|show|top-attackers|top-ttps|alerts|report|stats`.

Read-only snapshot commands that hit the existing dashboard-api endpoints
defined in [`docs/02_API_Contracts.md`](docs/02_API_Contracts.md). For top-
attackers + alerts we use the same API instead of direct SQL so the CLI
works against a remote operator's API without DB credentials.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Optional

import httpx
import typer

from honeystrike.cli.defend import defend_app
from honeystrike.cli.http_client import api_client, require_token, run_async
from honeystrike.cli.output import (
    console, error, info, kv_table, make_table,
    out, score_text, severity_text, success, warn,
)


def _ymd(value) -> str:
    if value is None:
        return "—"
    return str(value).replace("T", " ").split("+")[0][:19]


# ---------------------------------------------------------------------------
# defend recent
# ---------------------------------------------------------------------------

@defend_app.command("recent", help="Recent closed sessions.")
def recent_cmd(
    limit: int = typer.Option(20, "--limit"),
    service: Optional[str] = typer.Option(None, "--service"),
    min_score: int = typer.Option(0, "--min-score", min=0, max=100),
    from_ts: Optional[str] = typer.Option(None, "--from-ts"),
    to_ts: Optional[str] = typer.Option(None, "--to-ts"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    require_token()
    params: dict[str, str | int] = {"limit": limit, "min_score": min_score}
    if service:
        params["service"] = service
    if from_ts:
        params["from_ts"] = from_ts
    if to_ts:
        params["to_ts"] = to_ts

    async def _go() -> dict:
        async with api_client() as client:
            r = await client.get("/api/sessions", params=params)
            r.raise_for_status()
            return r.json()

    body = run_async(_go())
    if as_json:
        out.print_json(json.dumps(body))
        return

    t = make_table("started", "service", "src_ip", "country", "state",
                   "duration", "ttps", "score", "severity",
                   title=f"recent sessions ({body['total']} match, showing {len(body['items'])})")
    for s in body["items"]:
        dur = f"{s['duration_ms']} ms" if s.get("duration_ms") else "—"
        t.add_row(
            _ymd(s["started_at"]),
            s["service"],
            s["src_ip"],
            s.get("country_iso") or "—",
            s["state"],
            dur,
            str(s["ttp_count"]),
            score_text(s["threat_score"]),
            severity_text(s["severity"]),
        )
    console.print(t)


# ---------------------------------------------------------------------------
# defend show
# ---------------------------------------------------------------------------

def _build_narrative(detail: dict) -> str:
    """Render an incident-response-style paragraph from the JSON detail blob."""
    fp = detail.get("fingerprint") or {}
    src = detail["src_ip"]
    country = fp.get("country_iso") or "??"
    asn = f"AS{fp['asn']}" if fp.get("asn") else "unknown ASN"
    tools = [t["name"] for t in fp.get("tool_signatures", [])]
    ttps = [t["technique_id"] for t in detail.get("ttps", [])]
    score = detail["threat_score"]
    severity = detail["severity"]
    service = detail["service"]

    sentences = [
        f"Attacker {src} ({country}, {asn}) hit {service.upper()} at {_ymd(detail['started_at'])}.",
        f"Session ran for {detail.get('duration_ms', 0)} ms and produced {detail['event_count']} events.",
    ]
    if tools:
        sentences.append("Tool fingerprints: " + ", ".join(tools) + ".")
    if ttps:
        sentences.append("MITRE ATT&CK techniques attributed: " + ", ".join(ttps) + ".")
    sentences.append(f"Final threat score: {score}/100 ({severity}).")
    return " ".join(sentences)


@defend_app.command("show", help="Full session detail + narrative summary.")
def show_cmd(
    session_id: uuid.UUID = typer.Argument(...),
    events: int = typer.Option(20, "--events"),
    as_json: bool = typer.Option(False, "--json"),
    no_narrative: bool = typer.Option(False, "--no-narrative"),
) -> None:
    require_token()

    async def _go() -> dict:
        async with api_client() as client:
            r = await client.get(f"/api/sessions/{session_id}")
            if r.status_code == 404:
                error(f"session not found: {session_id}")
                raise SystemExit(1)
            r.raise_for_status()
            return r.json()

    detail = run_async(_go())
    if as_json:
        out.print_json(json.dumps(detail))
        return

    fp = detail.get("fingerprint") or {}
    console.rule(f"[bold cyan]Session {detail['id']}[/bold cyan]")
    console.print(kv_table([
        ("IP", detail["src_ip"]),
        ("Service", detail["service"]),
        ("State", detail["state"]),
        ("Threat score", f"{detail['threat_score']}/100"),
        ("Severity", str(severity_text(detail["severity"]))),
        ("Started", _ymd(detail["started_at"])),
        ("Ended", _ymd(detail.get("ended_at"))),
        ("Duration (ms)", str(detail.get("duration_ms") or "—")),
        ("Events", str(detail["event_count"])),
        ("Country", fp.get("country_iso") or "—"),
        ("ASN / Org", f"AS{fp['asn']} {fp.get('org','')}" if fp.get("asn") else "—"),
        ("AbuseIPDB", str(fp.get("abuse_score") or "—")),
        ("JA3", fp.get("ja3_hash") or "—"),
    ], title="Source + Session"))

    if fp.get("tool_signatures"):
        t = make_table("Tool", "Confidence", title="Tool signatures")
        for sig in fp["tool_signatures"]:
            t.add_row(sig["name"], f"{sig['confidence']:.2f}")
        console.print(t)

    if detail.get("ttps"):
        t = make_table("Technique", "Name", "Tactic", "Confidence", title="MITRE TTPs")
        for ttp in detail["ttps"]:
            t.add_row(ttp["technique_id"], ttp["technique_name"],
                      ttp["tactic"], f"{ttp['confidence']:.2f}")
        console.print(t)

    preview = (detail.get("events") or {}).get("preview") or []
    if preview:
        t = make_table("time", "type", "payload",
                       title=f"Events ({len(preview)} of {detail['event_count']})")
        for e in preview[:events]:
            t.add_row(
                _ymd(e["timestamp"]),
                e["event_type"],
                json.dumps(e["payload"])[:120],
            )
        console.print(t)

    if detail.get("alerts"):
        t = make_table("channel", "severity", "score", "dispatched_at",
                       title="Alerts dispatched")
        for a in detail["alerts"]:
            t.add_row(a["channel"], a["severity"], str(a["threat_score"]),
                      _ymd(a["dispatched_at"]))
        console.print(t)

    if not no_narrative:
        console.rule("[bold cyan]Narrative[/bold cyan]")
        console.print(_build_narrative(detail))


# ---------------------------------------------------------------------------
# defend top-attackers / top-ttps
# ---------------------------------------------------------------------------

@defend_app.command("top-attackers", help="Top source IPs by max threat score.")
def top_attackers_cmd(
    days: int = typer.Option(7, "--days"),
    limit: int = typer.Option(20, "--limit"),
    min_score: int = typer.Option(0, "--min-score"),
) -> None:
    require_token()

    async def _go() -> list[dict]:
        items: list[dict] = []
        page = 1
        async with api_client() as client:
            while True:
                r = await client.get(
                    "/api/sessions",
                    params={"limit": 200, "page": page, "min_score": min_score},
                )
                r.raise_for_status()
                body = r.json()
                items.extend(body["items"])
                if page * 200 >= body["total"] or not body["items"]:
                    break
                page += 1
                if page > 10:
                    break
        return items

    items = run_async(_go())
    # Aggregate in-CLI.
    agg: dict[str, dict] = {}
    for s in items:
        ip = s["src_ip"]
        bucket = agg.setdefault(
            ip,
            {"sessions": 0, "max_score": 0, "services": set(), "first": None, "last": None},
        )
        bucket["sessions"] += 1
        bucket["max_score"] = max(bucket["max_score"], s["threat_score"])
        bucket["services"].add(s["service"])
        if bucket["first"] is None or s["started_at"] < bucket["first"]:
            bucket["first"] = s["started_at"]
        if bucket["last"] is None or s["started_at"] > bucket["last"]:
            bucket["last"] = s["started_at"]
    ranked = sorted(agg.items(), key=lambda kv: -kv[1]["max_score"])[:limit]

    t = make_table("src_ip", "sessions", "max_score", "services",
                   "first_seen", "last_seen", title=f"top attackers ({days}d)")
    for ip, b in ranked:
        t.add_row(ip, str(b["sessions"]), str(b["max_score"]),
                  ",".join(sorted(b["services"])),
                  _ymd(b["first"]), _ymd(b["last"]))
    console.print(t)


@defend_app.command("top-ttps", help="Top MITRE techniques over a window.")
def top_ttps_cmd(
    days: int = typer.Option(30, "--days"),
    limit: int = typer.Option(20, "--limit"),
) -> None:
    require_token()

    async def _go() -> list[dict]:
        async with api_client() as client:
            r = await client.get("/api/stats/ttps",
                                 params={"days": days, "limit": limit})
            r.raise_for_status()
            return r.json()

    rows = run_async(_go())
    t = make_table("technique", "name", "tactic", "count", "pct",
                   title=f"top TTPs ({days}d)")
    for row in rows:
        t.add_row(row["technique_id"], row["name"], row["tactic"],
                  str(row["count"]), f"{row['pct']:.1f}%")
    console.print(t)


# ---------------------------------------------------------------------------
# defend alerts
# ---------------------------------------------------------------------------

@defend_app.command("alerts", help="Recent alerts dispatched.")
def alerts_cmd(
    severity: Optional[str] = typer.Option(None, "--severity"),
    channel: Optional[str] = typer.Option(None, "--channel"),
    limit: int = typer.Option(25, "--limit"),
    hours: int = typer.Option(24, "--hours"),
) -> None:
    require_token()
    # No /api/alerts endpoint yet — list sessions filtered by min_score then
    # join alerts via /api/sessions/{id}. Simpler: stand on the existing
    # /api/sessions filter for high+critical and show the per-session alerts.
    min_score = {"low": 0, "medium": 20, "high": 50, "critical": 80}.get(severity or "high", 50)

    async def _go() -> list[dict]:
        async with api_client() as client:
            r = await client.get(
                "/api/sessions",
                params={"limit": min(200, max(limit * 3, 25)),
                        "min_score": min_score},
            )
            r.raise_for_status()
            items = r.json()["items"]
            # Fetch detail for each so we get alerts.
            detail_tasks = [
                client.get(f"/api/sessions/{s['id']}")
                for s in items[: limit * 3]
            ]
            details = await asyncio.gather(*detail_tasks)
        out_rows: list[dict] = []
        for d in details:
            if d.status_code != 200:
                continue
            body = d.json()
            for a in body.get("alerts", []):
                if channel and a["channel"] != channel:
                    continue
                if severity and a["severity"] != severity:
                    continue
                out_rows.append({
                    "time": a["dispatched_at"],
                    "channel": a["channel"],
                    "severity": a["severity"],
                    "threat_score": a["threat_score"],
                    "src_ip": body["src_ip"],
                    "session_id": body["id"],
                })
        return sorted(out_rows, key=lambda x: x["time"], reverse=True)[:limit]

    rows = run_async(_go())
    t = make_table("time", "channel", "severity", "score", "src_ip", "session",
                   title="alerts dispatched")
    for r in rows:
        t.add_row(_ymd(r["time"]), r["channel"], r["severity"],
                  str(r["threat_score"]), r["src_ip"], r["session_id"][:8])
    console.print(t)


# ---------------------------------------------------------------------------
# defend stats
# ---------------------------------------------------------------------------

@defend_app.command("stats", help="Overview tile equivalent.")
def stats_cmd(
    days: int = typer.Option(1, "--days"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    require_token()

    async def _go() -> dict:
        async with api_client() as client:
            r = await client.get("/api/stats/overview", params={"days": days})
            r.raise_for_status()
            return r.json()

    body = run_async(_go())
    if as_json:
        out.print_json(json.dumps(body))
        return
    sev = body.get("severity_breakdown") or {}
    console.print(kv_table([
        ("Window", f"{body['period_days']}d"),
        ("Sessions", str(body["total_sessions"])),
        ("Unique IPs", str(body["unique_ips"])),
        ("Avg threat score", str(body["avg_threat_score"])),
        ("Severity low/med/high/crit",
         f"{sev.get('low',0)} / {sev.get('medium',0)} / {sev.get('high',0)} / {sev.get('critical',0)}"),
    ], title="stats"))


# ---------------------------------------------------------------------------
# defend report
# ---------------------------------------------------------------------------

@defend_app.command("report", help="Trigger + download a session report.")
def report_cmd(
    session_id: uuid.UUID = typer.Argument(...),
    fmt: str = typer.Option("pdf", "--format"),
    output: Optional[str] = typer.Option(None, "--output"),
    open_after: bool = typer.Option(False, "--open"),
    wait: int = typer.Option(30, "--wait"),
) -> None:
    require_token()
    if fmt not in {"pdf", "html"}:
        raise typer.BadParameter("--format must be pdf or html")
    out_path = output or f"session-{session_id}.{fmt}"

    async def _go() -> str:
        async with api_client() as client:
            # Trigger.
            r = await client.post(
                f"/api/sessions/{session_id}/report",
                params={"format": fmt},
            )
            if r.status_code not in (200, 202):
                error(f"trigger failed: HTTP {r.status_code} {r.text[:200]}")
                raise SystemExit(1)
            info(f"queued — polling for up to {wait}s")
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                r = await client.get(
                    f"/api/sessions/{session_id}/report",
                    params={"format": fmt},
                )
                if r.status_code == 200:
                    with open(out_path, "wb") as fh:
                        fh.write(r.content)
                    return out_path
                if r.status_code == 410:
                    error("report expired on disk")
                    raise SystemExit(1)
                await asyncio.sleep(1)
        error("timed out waiting for report")
        raise SystemExit(1)

    path = run_async(_go())
    success(f"saved {path}")
    if open_after:
        opener = {"posix": "xdg-open", "nt": "start"}.get(os.name, "open")
        try:
            asyncio.run(asyncio.create_subprocess_exec(opener, path))
        except Exception:                                  # noqa: BLE001
            warn(f"could not auto-open {path}")
