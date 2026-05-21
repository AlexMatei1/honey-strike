"""Unit tests for `honeystrike.api.routers.lessons` — the learning platform.

Verifies:
  - every lesson TOML parses + has the required fields,
  - the catalogue is constructed correctly,
  - the defender grader runs the real reference rules against fixtures and
    returns the expected `correct` flag.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from honeystrike.api.routers import lessons as lessons_mod


_LESSONS_DIR = Path(lessons_mod._LESSONS_DIR)
ATTACK_LESSONS = sorted((_LESSONS_DIR / "attack").glob("*.toml"))
DEFEND_LESSONS = sorted((_LESSONS_DIR / "defend").glob("*.toml"))


@pytest.mark.parametrize("path", ATTACK_LESSONS + DEFEND_LESSONS,
                         ids=lambda p: p.relative_to(_LESSONS_DIR).as_posix())
def test_every_lesson_parses_with_required_fields(path: Path) -> None:
    with path.open("rb") as f:
        doc = tomllib.load(f)
    for key in ("id", "family", "title", "ttps", "blocks"):
        assert key in doc, f"{path.name} missing key {key!r}"
    assert isinstance(doc["blocks"], list) and doc["blocks"], f"{path.name} has no blocks"
    for i, b in enumerate(doc["blocks"]):
        assert b.get("kind") in {"code", "shell", "prose", "choice"}, \
            f"{path.name} block[{i}] bad kind {b.get('kind')!r}"
        if b["kind"] in ("code", "shell"):
            assert b.get("target"), f"{path.name} block[{i}] missing target"
        if b["kind"] == "choice":
            assert isinstance(b.get("options"), list) and len(b["options"]) >= 2
            assert isinstance(b.get("correct"), int)


def test_catalogue_groups_by_family() -> None:
    lessons_mod._catalogue.cache_clear()
    cat = lessons_mod._catalogue()
    by_family: dict[str, list] = {"attack": [], "defend": []}
    for item in cat:
        by_family[item["family"]].append(item["id"])
    assert by_family["attack"], "no attack lessons"
    assert by_family["defend"], "no defender lessons"
    # IDs are unique within a family.
    assert len(set(by_family["attack"])) == len(by_family["attack"])
    assert len(set(by_family["defend"])) == len(by_family["defend"])


def test_every_fixture_backed_defender_lesson_has_matching_reference_rule() -> None:
    # Prediction-style lessons (no [fixture]) are exempt — they have no rule
    # to grade against (e.g. score-threat teaches the scoring formula).
    for path in DEFEND_LESSONS:
        with path.open("rb") as f:
            doc = tomllib.load(f)
        if "fixture" not in doc:
            continue
        assert doc["id"] in lessons_mod._DEFENDER_RULES, \
            f"defender lesson {doc['id']!r} has a fixture but no entry in _DEFENDER_RULES"


def test_every_fixture_backed_defender_lesson_has_a_fixture_file() -> None:
    for path in DEFEND_LESSONS:
        with path.open("rb") as f:
            doc = tomllib.load(f)
        if "fixture" not in doc:
            continue
        fx_name = doc.get("fixture", {}).get("events_json")
        assert fx_name, f"{path.name} has no fixture.events_json"
        fx_path = _LESSONS_DIR / "fixtures" / f"{fx_name}.json"
        assert fx_path.is_file(), f"fixture {fx_path} not found"


def test_grader_for_password_guess_fires_on_fixture() -> None:
    from honeystrike.api.routers.lessons import (
        _ctx_from_fixture, _DEFENDER_RULES, _fixture_path,
    )
    import json
    with _fixture_path("ssh-passwd-guess").open() as f:
        fx = json.load(f)
    ctx = _ctx_from_fixture(fx)
    match = _DEFENDER_RULES["detect-password-guess"](ctx)
    assert match is not None
    assert match.technique_id == "T1110.001"


def test_grader_for_sqli_fires_on_fixture() -> None:
    from honeystrike.api.routers.lessons import (
        _ctx_from_fixture, _DEFENDER_RULES, _fixture_path,
    )
    import json
    with _fixture_path("http-sqli").open() as f:
        fx = json.load(f)
    ctx = _ctx_from_fixture(fx)
    match = _DEFENDER_RULES["detect-exploit-pubapp"](ctx)
    assert match is not None
    assert match.technique_id == "T1190"


def test_attack_lessons_with_live_block_use_known_scenarios() -> None:
    """Drift guard: any attack lesson with a [live] section must name a
    scenario that /api/play/attack actually knows about."""
    from honeystrike.api.routers.play import _SCENARIOS
    known = {s["id"] for s in _SCENARIOS}
    for path in ATTACK_LESSONS:
        with path.open("rb") as f:
            doc = tomllib.load(f)
        live = doc.get("live")
        if live and "scenario" in live:
            assert live["scenario"] in known, \
                f"{path.name}: live.scenario {live['scenario']!r} not in /api/play/scenarios"
