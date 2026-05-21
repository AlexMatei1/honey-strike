#!/usr/bin/env python3
"""Lesson drift checker.

Every `kind = "code"` block in a lesson is supposed to be a *real* line from
the codebase — the whole premise of the learning platform is "type the actual
runner / detector". If a runner or rule is refactored and the lesson isn't
updated, the learner ends up typing code that no longer exists. This script
catches that drift.

For each lesson it maps the lesson id to its source file, then verifies every
`code` block's `target` appears (whitespace-normalised) in that source. CLI
`shell` blocks, `prose`, and `choice` blocks are not checked.

Usage:
    python scripts/check_lesson_drift.py          # exit 1 on any drift
    python scripts/check_lesson_drift.py --quiet   # only print failures

Run in CI and as tests/unit/test_lesson_drift.py.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_LESSONS = _ROOT / "src" / "honeystrike" / "api" / "lessons"
_SRC = _ROOT / "src" / "honeystrike"

# Map each lesson id to the source file its code blocks are lifted from.
# Lessons that are all prose/choice/shell (no python code blocks) need no entry.
SOURCE_MAP: dict[str, Path] = {
    # attack — python runners
    "ssh-hydra":      _SRC / "cli" / "attack" / "runners.py",
    "ftp-hydra":      _SRC / "cli" / "attack" / "runners.py",
    "multi-service":  _SRC / "cli" / "attack" / "runners.py",
    # defender — TTP rules
    "detect-password-guess":  _SRC / "workers" / "intel" / "ttp_rules.py",
    "detect-exploit-pubapp":  _SRC / "workers" / "intel" / "ttp_rules.py",
    "detect-cred-stuffing":   _SRC / "workers" / "intel" / "ttp_rules.py",
    "detect-multi-service":   _SRC / "workers" / "intel" / "ttp_rules.py",
    "detect-file-discovery":  _SRC / "workers" / "intel" / "ttp_rules.py",
    "detect-victim-recon":    _SRC / "workers" / "intel" / "ttp_rules.py",
    "detect-valid-accounts":  _SRC / "workers" / "intel" / "ttp_rules.py",
    "score-threat":           _SRC / "workers" / "intel" / "threat_scoring.py",
}


def _norm(s: str) -> str:
    """Collapse all runs of whitespace to a single space and strip."""
    return re.sub(r"\s+", " ", s).strip()


def check() -> list[str]:
    failures: list[str] = []
    source_cache: dict[Path, str] = {}

    for toml_path in sorted(_LESSONS.glob("*/*.toml")):
        with toml_path.open("rb") as f:
            doc = tomllib.load(f)
        lesson_id = doc["id"]
        code_blocks = [b for b in doc.get("blocks", []) if b.get("kind") == "code"]
        if not code_blocks:
            continue
        src_path = SOURCE_MAP.get(lesson_id)
        if src_path is None:
            failures.append(
                f"{lesson_id}: has {len(code_blocks)} code block(s) but no SOURCE_MAP entry"
            )
            continue
        if src_path not in source_cache:
            source_cache[src_path] = _norm(src_path.read_text(encoding="utf-8"))
        haystack = source_cache[src_path]
        for i, b in enumerate(code_blocks):
            needle = _norm(b["target"])
            if needle not in haystack:
                failures.append(
                    f"{lesson_id} block[{i}] not found in {src_path.name}:\n"
                    f"    {b['target']}"
                )
    return failures


def main() -> int:
    quiet = "--quiet" in sys.argv
    failures = check()
    if failures:
        print(f"✗ lesson drift: {len(failures)} block(s) no longer match source\n")
        for f in failures:
            print(f"  - {f}")
        return 1
    if not quiet:
        print("✓ all lesson code blocks match their source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
