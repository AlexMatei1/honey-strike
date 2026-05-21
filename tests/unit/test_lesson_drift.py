"""Lesson drift guard — every `code` block must be real source.

Wraps scripts/check_lesson_drift.py so CI fails loudly if a runner or rule is
refactored without updating the lesson that teaches it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_SCRIPT = _ROOT / "scripts" / "check_lesson_drift.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_lesson_drift", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_lesson_drift() -> None:
    checker = _load_checker()
    failures = checker.check()
    assert not failures, "lesson code blocks no longer match source:\n" + "\n".join(failures)


def test_every_code_lesson_is_mapped() -> None:
    """Any lesson that has code blocks must have a SOURCE_MAP entry, so a new
    code lesson can't silently skip the drift check."""
    import tomllib
    checker = _load_checker()
    lessons_dir = _ROOT / "src" / "honeystrike" / "api" / "lessons"
    for toml_path in lessons_dir.glob("*/*.toml"):
        with toml_path.open("rb") as f:
            doc = tomllib.load(f)
        has_code = any(b.get("kind") == "code" for b in doc.get("blocks", []))
        if has_code:
            assert doc["id"] in checker.SOURCE_MAP, (
                f"{doc['id']} has code blocks but no SOURCE_MAP entry in "
                "scripts/check_lesson_drift.py"
            )
