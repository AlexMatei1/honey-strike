"""Campaign playbooks — scripted multi-step intrusions.

A campaign is a list of `CampaignStep` whose `runner` is one of the async
functions in `runners.py`. The CLI logs a campaign envelope to Redis
(`hs:campaign:{uuid}`) when a run starts so the defender's `campaign-score`
command can later reconcile detected TTPs against expected ones.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

import redis.asyncio as aioredis
import typer

from honeystrike.cli.attack import attack_app, runners
from honeystrike.cli.http_client import run_async
from honeystrike.cli.output import banner, info, success
from honeystrike.config import get_settings


@dataclass(slots=True)
class CampaignStep:
    """One step in a playbook."""
    name: str
    runner: Callable[..., Any]
    kwargs: dict[str, Any]
    dwell_seconds: float = 2.0
    expected_ttps: tuple[str, ...] = field(default_factory=tuple)


@dataclass(slots=True)
class Campaign:
    name: str
    description: str
    steps: list[CampaignStep]

    @property
    def expected_ttps(self) -> tuple[str, ...]:
        merged: set[str] = set()
        for s in self.steps:
            merged.update(s.expected_ttps)
        return tuple(sorted(merged))


# ---------------------------------------------------------------------------
# Playbooks. Built so each step's `kwargs` carries a `target` (filled in at
# run time from `target_host`).
# ---------------------------------------------------------------------------

def _apt28(target_host: str) -> Campaign:
    return Campaign(
        name="apt28",
        description="HTTP recon → sqlmap → SSH brute + shell discovery + exfil.",
        steps=[
            CampaignStep(
                "http-recon", runners.http_recon,
                {"target": f"{target_host}:18080", "paths": None,
                 "user_agent": "Nikto/2.5.0"},
                expected_ttps=("T1592", "T1595.001"),
            ),
            CampaignStep(
                "http-sqlmap", runners.http_sqlmap,
                {"target": f"{target_host}:18080",
                 "path": "/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users",
                 "user_agent": "sqlmap/1.7.8#stable", "count": 1, "intensity": "burst"},
                expected_ttps=("T1190",),
            ),
            CampaignStep(
                "ssh-hydra-shell", runners.ssh_hydra,
                {"target": f"{target_host}:2222", "keep_shell": True,
                 "intensity": "burst"},
                expected_ttps=("T1110.001", "T1078", "T1083", "T1592"),
            ),
        ],
    )


def _fin7(target_host: str) -> Campaign:
    return Campaign(
        name="fin7",
        description="sqlmap recon → path traversal → FTP credential reuse.",
        steps=[
            CampaignStep(
                "http-sqlmap", runners.http_sqlmap,
                {"target": f"{target_host}:18080",
                 "path": "/admin?id=1+OR+1=1", "user_agent": "sqlmap/1.7.8",
                 "count": 1, "intensity": "burst"},
                expected_ttps=("T1190",),
            ),
            CampaignStep(
                "http-traversal", runners.http_traversal,
                {"target": f"{target_host}:18080", "depth": 5, "encoding": "url"},
                expected_ttps=("T1083",),
            ),
            CampaignStep(
                "ftp-hydra", runners.ftp_hydra,
                {"target": f"{target_host}:2221",
                 "credentials": "root:toor,admin:admin,oracle:oracle",
                 "intensity": "burst"},
                expected_ttps=("T1110.001",),
            ),
        ],
    )


def _ransomware(target_host: str) -> Campaign:
    return Campaign(
        name="ransomware-deployer",
        description="RDP scan → SSH brute → mass HTTP recon → multi-service.",
        steps=[
            CampaignStep(
                "rdp-scan", runners.rdp_scan,
                {"target": f"{target_host}:33389", "cookie": "mstshash=Ransom",
                 "protocols": 0},
                expected_ttps=("T1595.001",),
            ),
            CampaignStep(
                "ssh-hydra", runners.ssh_hydra,
                {"target": f"{target_host}:2222", "intensity": "burst"},
                expected_ttps=("T1110.001",),
            ),
            CampaignStep(
                "http-recon", runners.http_recon,
                {"target": f"{target_host}:18080", "paths": None,
                 "user_agent": "Mozilla/5.0 (compatible; ZmEu)"},
                expected_ttps=("T1592",),
            ),
            CampaignStep(
                "multi-service", runners.multi_service,
                {"target_host": target_host, "services": ["ssh", "http", "ftp"],
                 "intensity": "burst"},
                expected_ttps=("T1595.001",),
            ),
        ],
    )


def _script_kiddie(target_host: str) -> Campaign:
    return Campaign(
        name="script-kiddie",
        description="Two low-noise probes — a baseline of essentially nothing.",
        steps=[
            CampaignStep(
                "http-recon", runners.http_recon,
                {"target": f"{target_host}:18080",
                 "paths": ["/wp-login.php"], "user_agent": "curl/8.0"},
                expected_ttps=(),
            ),
            CampaignStep(
                "ssh-hydra", runners.ssh_hydra,
                {"target": f"{target_host}:2222", "count": 1,
                 "intensity": "slow"},
                expected_ttps=(),
            ),
        ],
    )


_PLAYBOOKS = {
    "apt28": _apt28,
    "fin7": _fin7,
    "ransomware-deployer": _ransomware,
    "script-kiddie": _script_kiddie,
}


# ---------------------------------------------------------------------------
# Campaign envelope written to Redis so the defender can score it later.
# ---------------------------------------------------------------------------

async def _record_envelope(campaign_id: str, campaign: Campaign) -> None:
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url)
    envelope = {
        "campaign_id": campaign_id,
        "name": campaign.name,
        "description": campaign.description,
        "started_at": time.time(),
        "expected_ttps": list(campaign.expected_ttps),
        "steps": [s.name for s in campaign.steps],
    }
    try:
        await client.set(
            f"hs:campaign:{campaign_id}",
            json.dumps(envelope),
            ex=7 * 24 * 3600,                              # 7-day retention
        )
    finally:
        await client.aclose()


async def _finalise_envelope(campaign_id: str) -> None:
    settings = get_settings()
    client = aioredis.from_url(settings.redis_url)
    try:
        raw = await client.get(f"hs:campaign:{campaign_id}")
        if raw:
            envelope = json.loads(raw)
            envelope["ended_at"] = time.time()
            await client.set(
                f"hs:campaign:{campaign_id}",
                json.dumps(envelope),
                ex=7 * 24 * 3600,
            )
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# `attack campaign <name>`
# ---------------------------------------------------------------------------

@attack_app.command("campaign", help="Run a named adversary-emulation playbook.")
def campaign_cmd(
    name: str = typer.Argument(..., help="apt28 | fin7 | ransomware-deployer | script-kiddie"),
    target_host: str = typer.Option("127.0.0.1", "--target-host"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if name not in _PLAYBOOKS:
        raise typer.BadParameter(f"unknown playbook {name!r}. Try one of: {list(_PLAYBOOKS)}")
    campaign = _PLAYBOOKS[name](target_host)

    banner(f"🎯 Campaign: {campaign.name}")
    info(campaign.description)
    info(f"Steps ({len(campaign.steps)}):")
    for s in campaign.steps:
        info(f"  • {s.name}  (expected TTPs: {', '.join(s.expected_ttps) or '—'})")

    if dry_run:
        info("--dry-run set — nothing fired.")
        return

    campaign_id = str(uuid.uuid4())
    info(f"campaign_id = {campaign_id}")
    run_async(_run_campaign(campaign_id, campaign))
    success(f"campaign complete — run `honeystrike defend campaign-score {campaign_id}` to grade.")


async def _run_campaign(campaign_id: str, campaign: Campaign) -> None:
    await _record_envelope(campaign_id, campaign)
    for step in campaign.steps:
        info(f"▶ step: {step.name}")
        try:
            await step.runner(**step.kwargs)
        except Exception as exc:                            # noqa: BLE001
            info(f"  (step failed: {exc})")
        if step.dwell_seconds:
            await asyncio.sleep(step.dwell_seconds)
    await _finalise_envelope(campaign_id)
