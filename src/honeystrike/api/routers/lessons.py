"""`/api/lessons/*` — typing-driven learning platform.

Lessons are static TOML files under `api/lessons/<family>/<id>.toml`.
The router serves three things:

  - the lesson catalogue (cards on /play/attack and /play/defend hubs)
  - a single lesson's parsed content (the typing engine fetches this)
  - a defender grader: runs the *reference* TTP rule against a fixture and
    returns whether it fired. We never exec user-typed code — the typing
    game gates on character-perfect match against the reference, so the
    only Python that runs is the reference rule already in the repo.
"""

from __future__ import annotations

import json
import tomllib
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from honeystrike.api.auth import current_user
from honeystrike.core.models import User
from honeystrike.workers.intel.signatures import SessionContext
from honeystrike.workers.intel.ttp_rules import (
    _credential_stuffing_rule,
    _exploit_public_app_rule,
    _file_discovery_rule,
    _multi_service_scan_rule,
    _password_guessing_rule,
    _valid_accounts_rule,
    _victim_host_info_rule,
)

router = APIRouter(prefix="/api/lessons", tags=["lessons"])

_LESSONS_DIR = Path(__file__).resolve().parent.parent / "lessons"

# Map defender lesson id -> reference rule callable. The grader uses these.
_DEFENDER_RULES = {
    "detect-password-guess":   _password_guessing_rule,
    "detect-multi-service":    _multi_service_scan_rule,
    "detect-cred-stuffing":    _credential_stuffing_rule,
    "detect-exploit-pubapp":   _exploit_public_app_rule,
    "detect-file-discovery":   _file_discovery_rule,
    "detect-victim-recon":     _victim_host_info_rule,
    "detect-valid-accounts":   _valid_accounts_rule,
}


# ---------------------------------------------------------------------------
# Loaders (cached on first access)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _catalogue() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for family_dir in sorted(_LESSONS_DIR.glob("*")):
        if not family_dir.is_dir() or family_dir.name == "fixtures":
            continue
        for path in sorted(family_dir.glob("*.toml")):
            doc = _load_toml(path)
            out.append({
                "id": doc["id"],
                "family": doc["family"],
                "title": doc["title"],
                "blurb": doc.get("blurb", ""),
                "ttps": doc.get("ttps", []),
                "difficulty": doc.get("difficulty", "medium"),
                "typing_model": doc.get("typing_model", "python"),
            })
    return out


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def _lesson_path(family: str, lesson_id: str) -> Path:
    if "/" in family or "/" in lesson_id or ".." in family or ".." in lesson_id:
        raise HTTPException(status_code=400, detail="bad path")
    p = _LESSONS_DIR / family / f"{lesson_id}.toml"
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"lesson not found: {family}/{lesson_id}")
    return p


def _fixture_path(name: str) -> Path:
    if "/" in name or ".." in name:
        raise HTTPException(status_code=400, detail="bad path")
    p = _LESSONS_DIR / "fixtures" / f"{name}.json"
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"fixture not found: {name}")
    return p


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("")
async def list_lessons(
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    items = _catalogue()
    return {
        "attack": [i for i in items if i["family"] == "attack"],
        "defend": [i for i in items if i["family"] == "defend"],
    }


@router.get("/fixtures/{name}")
async def get_fixture(
    name: str,
    _user: Annotated[User, Depends(current_user)],
) -> Any:
    with _fixture_path(name).open() as f:
        return json.load(f)


@router.get("/{family}/{lesson_id}")
async def get_lesson(
    family: str,
    lesson_id: str,
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    doc = _load_toml(_lesson_path(family, lesson_id))
    return doc


class GradeIn(BaseModel):
    lesson_id: str


class GradeOut(BaseModel):
    fired: bool
    expected: bool
    correct: bool
    technique_id: str | None = None
    technique_name: str | None = None
    confidence: float | None = None
    narrative: str
    reference_source_excerpt: str | None = None


@router.post("/grade-defender", response_model=GradeOut)
async def grade_defender(
    body: GradeIn,
    _user: Annotated[User, Depends(current_user)],
) -> GradeOut:
    """Run the reference rule for `lesson_id` against its fixture. Returns
    whether the rule fired, whether that matches the lesson's expectation,
    and a short human narrative. We do not exec user-typed code."""
    rule = _DEFENDER_RULES.get(body.lesson_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="no reference rule for this lesson")
    # Load the lesson to find its fixture + expected outcome.
    doc = _load_toml(_lesson_path("defend", body.lesson_id))
    fixture_ref = doc.get("fixture", {})
    fixture_name = fixture_ref.get("events_json")
    expected = bool(fixture_ref.get("expected", True))
    if not fixture_name:
        raise HTTPException(status_code=500, detail="lesson missing fixture")
    with _fixture_path(fixture_name).open() as f:
        fx = json.load(f)
    ctx = _ctx_from_fixture(fx)
    match = rule(ctx)
    fired = match is not None
    correct = fired == expected
    narrative = _grade_narrative(body.lesson_id, fired, expected)
    return GradeOut(
        fired=fired,
        expected=expected,
        correct=correct,
        technique_id=match.technique_id if match else None,
        technique_name=match.technique_name if match else None,
        confidence=match.confidence if match else None,
        narrative=narrative,
        reference_source_excerpt=doc.get("reference_source_excerpt"),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx_from_fixture(fx: dict[str, Any]) -> SessionContext:
    """Build a SessionContext the rule functions expect from fixture JSON."""
    started_at = _parse_dt(fx.get("started_at"))
    events = []
    for e in fx.get("events", []):
        events.append({
            "event_type": e["event_type"],
            "payload": e.get("payload", {}),
            "ts": _parse_dt(e.get("ts")) or started_at,
        })
    siblings = []
    for s in fx.get("sibling_sessions", []):
        siblings.append({
            "src_ip": s.get("src_ip"),
            "service": s.get("service"),
            "started_at": _parse_dt(s.get("started_at")) or started_at,
        })
    return SessionContext(
        service=fx.get("service", "ssh"),
        src_ip=fx.get("src_ip", "192.0.2.1"),
        started_at=started_at,
        events=events,
        sibling_sessions=siblings,
    )


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            d = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _grade_narrative(lesson_id: str, fired: bool, expected: bool) -> str:
    if fired and expected:
        return ("✓ Your detector fired on the fixture, as expected. "
                "That's exactly the pattern this rule is designed to catch.")
    if not fired and not expected:
        return ("✓ Your detector held its fire — the fixture doesn't match this "
                "rule's trigger, which is the right call (false-positive avoided).")
    if fired and not expected:
        return ("✗ The detector fired, but this fixture isn't supposed to trip it. "
                "Re-read the trigger conditions — you may be matching too broadly.")
    return ("✗ The detector should have fired on this fixture but didn't. "
            "Re-read the rule body and check which payload fields it inspects.")
