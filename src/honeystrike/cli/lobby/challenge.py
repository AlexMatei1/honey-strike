"""`honeystrike challenge <handle>` — invite a friend to a match.

Flow:
  1. POST /lobby/invite → invite_code
  2. Poll /lobby/match/by-invite/{code} until accepted / declined / timeout
  3. On accept, run the chosen scenario (or campaign) targeted at the defender's
     registered public endpoints.
  4. Notify lobby of completion → lobby posts match summary to Discord.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

import httpx
import typer

from honeystrike.cli import auth
from honeystrike.cli.attack import campaigns, runners
from honeystrike.cli.output import banner, error, info, success, warn


_DEFAULT_INVITE_TIMEOUT = 60


async def _post_invite(
    *, lobby_url: str, token: str, to_handle: str, scenario: str, duration: int,
) -> dict:
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        r = await client.post("/lobby/invite", json={
            "to_handle": to_handle,
            "scenario": scenario,
            "duration_seconds": duration,
        })
        if r.status_code >= 400:
            raise SystemExit(f"invite failed: HTTP {r.status_code} {r.text[:200]}")
        return r.json()


async def _wait_for_accept(
    *, lobby_url: str, token: str, invite_code: str, timeout_seconds: int,
) -> dict | None:
    """Poll lobby every 3s; return the match dict on accept, None on timeout."""
    deadline = time.time() + timeout_seconds
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        while time.time() < deadline:
            r = await client.get(f"/lobby/invite/{invite_code}")
            if r.status_code == 200:
                body = r.json()
                if body["status"] == "accepted":
                    return body["match"]
                if body["status"] == "declined":
                    return None
            await asyncio.sleep(3)
    return None


async def _run_scenario_or_campaign(
    *, scenario: str, defender_endpoints: dict[str, str],
) -> dict:
    """Dispatch to a single runner or a campaign playbook based on the name."""
    if scenario in {"apt28", "fin7", "ransomware-deployer", "script-kiddie"}:
        # Campaign — wraps `_PLAYBOOKS`. We don't reuse the typer command (it
        # records its own envelope to local Redis); the lobby tracks the match
        # ID for us.
        playbook = campaigns._PLAYBOOKS[scenario]                  # noqa: SLF001
        target_host = next(iter(defender_endpoints.values()), "127.0.0.1").split(":")[0]
        campaign = playbook(target_host)
        for step in campaign.steps:
            info(f"▶ {step.name}")
            try:
                await step.runner(**step.kwargs)
            except Exception as exc:                                # noqa: BLE001
                warn(f"step {step.name} failed: {exc}")
            await asyncio.sleep(step.dwell_seconds)
        return {"phases": len(campaign.steps),
                "expected_ttps": list(campaign.expected_ttps)}

    # Single scenario — pick the runner by name.
    target_host = next(iter(defender_endpoints.values()), "127.0.0.1").split(":")[0]
    if scenario == "ssh-hydra":
        await runners.ssh_hydra(
            target=defender_endpoints.get("ssh", f"{target_host}:2222"),
            keep_shell=True, intensity="burst",
        )
    elif scenario == "http-sqlmap":
        await runners.http_sqlmap(
            target=defender_endpoints.get("http", f"{target_host}:18080"),
            path="/wp-admin/index.php?id=1+UNION+SELECT+x",
            user_agent="sqlmap/1.7.8", count=1, intensity="burst",
        )
    elif scenario == "multi-service":
        await runners.multi_service(
            target_host=target_host,
            services=list(defender_endpoints.keys()) or ["ssh", "http"],
            intensity="burst",
        )
    elif scenario == "full-compromise":
        await runners.full_compromise(
            target_host=target_host, dwell_seconds=2.0, with_report=False,
        )
    else:
        warn(f"unknown scenario {scenario!r} — running full-compromise as fallback")
        await runners.full_compromise(
            target_host=target_host, dwell_seconds=2.0, with_report=False,
        )
    return {"phases": 1, "expected_ttps": []}


async def _notify_finish(
    *, lobby_url: str, token: str, match_id: str, summary: dict,
) -> None:
    async with httpx.AsyncClient(
        base_url=lobby_url, timeout=10,
        headers={"Authorization": f"Bearer {token}"},
    ) as client:
        await client.post(f"/lobby/match/{match_id}/finish", json=summary)


def challenge_cmd(
    handle: str = typer.Argument(..., help="Friend's lobby handle to challenge."),
    scenario: str = typer.Option(
        "full-compromise", "--scenario",
        help="Any scenario name or campaign (apt28, fin7, ransomware-deployer, script-kiddie).",
    ),
    duration: int = typer.Option(300, "--duration", help="Match duration (seconds)."),
    invite_timeout: int = typer.Option(
        _DEFAULT_INVITE_TIMEOUT, "--invite-timeout",
        help="How long to wait for the defender to accept.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Send a challenge to a friend; on accept, run the scenario at their endpoints."""
    lob = auth.lobby_section()
    if not lob.get("url") or not lob.get("token") or not lob.get("handle"):
        error("not registered with a lobby — run `honeystrike register` first")
        raise SystemExit(1)

    banner(f"📨 Challenging {handle} → {scenario} ({duration}s)")
    if dry_run:
        info("--dry-run set; would POST /lobby/invite and run scenario")
        return

    async def _go() -> None:
        invite = await _post_invite(
            lobby_url=lob["url"], token=lob["token"],
            to_handle=handle, scenario=scenario, duration=duration,
        )
        info(f"invite_code = {invite['invite_code']}")
        info(f"waiting up to {invite_timeout}s for {handle} to accept …")
        match = await _wait_for_accept(
            lobby_url=lob["url"], token=lob["token"],
            invite_code=invite["invite_code"], timeout_seconds=invite_timeout,
        )
        if match is None:
            error(f"{handle} did not accept (declined or timed out)")
            raise SystemExit(1)
        defender_endpoints = match.get("defender_endpoint") or match.get("defender_endpoints") or {}
        info(f"match {match['match_id']} started; defender endpoints: {defender_endpoints}")
        try:
            summary = await _run_scenario_or_campaign(
                scenario=scenario, defender_endpoints=defender_endpoints,
            )
        except Exception as exc:                                    # noqa: BLE001
            warn(f"scenario errored: {exc}")
            summary = {"phases": 0, "expected_ttps": []}
        await _notify_finish(
            lobby_url=lob["url"], token=lob["token"],
            match_id=match["match_id"], summary=summary,
        )
        success(f"match {match['match_id'][:8]} complete — lobby will post the summary to Discord")

    try:
        asyncio.run(_go())
    except SystemExit:
        raise
