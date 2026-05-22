"""Server-authoritative gamification rules: XP, ranks, and badges.

Moved out of the browser so progress is tied to the account (not the
browser) and admins can see member progress. The frontend POSTs *actions*
(e.g. "lesson_complete") and this module decides the XP/streak/badge effects
— the client never sets XP directly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable

# Action → XP delta. Negative deltas are floored at 0 total XP.
XP_DELTAS: dict[str, int] = {
    "lesson_complete": 15,
    "correct_label": 10,
    "wrong_label": -2,
    "canary_found": 5,
    "block": 3,
    "duel_played": 10,
    "duel_win": 25,
}

# (min_xp, name) ascending. rank_for() returns current + next.
RANKS: list[tuple[int, str]] = [
    (0, "Apprentice"),
    (25, "Sentry"),
    (75, "Defender"),
    (150, "Hunter"),
    (300, "Veteran"),
    (600, "Threat-OG"),
    (1000, "HoneyMaster"),
]

_ACTIVITY_MAX = 50


def rank_for(xp: int) -> dict[str, Any]:
    cur = RANKS[0]
    nxt: tuple[int, str] | None = None
    for i, r in enumerate(RANKS):
        if xp >= r[0]:
            cur = r
        else:
            nxt = r
            break
    if nxt is None:
        return {"name": cur[1], "min": cur[0], "next": None, "next_at": None, "pct": 100}
    span = nxt[0] - cur[0]
    pct = max(0, min(100, round((xp - cur[0]) / span * 100))) if span else 100
    return {"name": cur[1], "min": cur[0], "next": nxt[1], "next_at": nxt[0], "pct": pct}


# ---- badges --------------------------------------------------------------
# Each check receives a context dict: {xp, best_streak, counts, stats, lessons}
#   counts  = per-action tallies (blocks, correctLabels, canariesCaught, …)
#   stats   = platform stats (critical_sessions, unique_countries)
#   lessons = {"attack": set(done_ids), "defend": set(done_ids),
#              "_all_attack": set(all_ids), "_all_defend": set(all_ids)}

def _all_done(ctx: dict, family: str) -> bool:
    allset = ctx["lessons"].get("_all_" + family) or set()
    done = ctx["lessons"].get(family) or set()
    return bool(allset) and allset <= done


BADGES: list[dict[str, Any]] = [
    {"id": "newcomer", "icon": "🐣", "name": "Newcomer",
     "desc": "Welcome to HoneyStrike.", "check": lambda c: True},
    {"id": "first-xp", "icon": "⭐", "name": "First XP",
     "desc": "Earned your first XP.", "check": lambda c: c["xp"] > 0},
    {"id": "apprentice", "icon": "📚", "name": "Apprentice",
     "desc": "Reach 50 XP.", "check": lambda c: c["xp"] >= 50},
    {"id": "veteran", "icon": "⚔️", "name": "Veteran",
     "desc": "Reach 250 XP.", "check": lambda c: c["xp"] >= 250},
    {"id": "honeymaster", "icon": "👑", "name": "HoneyMaster",
     "desc": "Reach 1000 XP.", "check": lambda c: c["xp"] >= 1000},
    {"id": "on-streak", "icon": "🔥", "name": "On a Streak",
     "desc": "Three correct labels in a row.", "check": lambda c: c["best_streak"] >= 3},
    {"id": "sharpshooter", "icon": "🎯", "name": "Sharpshooter",
     "desc": "Ten correct labels in a row.", "check": lambda c: c["best_streak"] >= 10},
    {"id": "first-block", "icon": "🚫", "name": "First Block",
     "desc": "Blocked your first attacker IP.", "check": lambda c: c["counts"].get("blocks", 0) >= 1},
    {"id": "wall-builder", "icon": "🧱", "name": "Wall Builder",
     "desc": "Blocked 10 attacker IPs.", "check": lambda c: c["counts"].get("blocks", 0) >= 10},
    {"id": "student", "icon": "🎓", "name": "Student",
     "desc": "Complete your first lesson.", "check": lambda c: c["counts"].get("lessonsDone", 0) >= 1},
    {"id": "scholar", "icon": "📖", "name": "Scholar",
     "desc": "Complete every attack lesson.", "check": lambda c: _all_done(c, "attack")},
    {"id": "detective", "icon": "🕵️", "name": "Detective",
     "desc": "Complete every defender lesson.", "check": lambda c: _all_done(c, "defend")},
    {"id": "critical-catcher", "icon": "💯", "name": "Critical Catcher",
     "desc": "Your honeypot recorded a critical session.",
     "check": lambda c: c["stats"].get("critical_sessions", 0) > 0},
    {"id": "globalist", "icon": "🌍", "name": "Globalist",
     "desc": "Attacks from 5+ countries.",
     "check": lambda c: c["stats"].get("unique_countries", 0) >= 5},
    {"id": "flag-hunter", "icon": "🚩", "name": "Flag Hunter",
     "desc": "Caught a canary in an attacker session.",
     "check": lambda c: c["counts"].get("canariesCaught", 0) >= 1},
    {"id": "duelist", "icon": "⚔️", "name": "Duelist",
     "desc": "Played your first member-vs-member duel.",
     "check": lambda c: c["counts"].get("duelsPlayed", 0) >= 1},
    {"id": "champion", "icon": "🏆", "name": "Champion",
     "desc": "Win 5 duels.",
     "check": lambda c: c["counts"].get("duelsWon", 0) >= 5},
]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def apply_event(progress: dict[str, Any], action: str, meta: dict[str, Any] | None) -> dict[str, Any]:
    """Mutate `progress` (xp/streak/best_streak/counts/activity) for one action.
    Returns the same dict. Unknown actions are a no-op."""
    if action not in XP_DELTAS:
        return progress
    meta = meta or {}
    counts: dict[str, Any] = progress.setdefault("counts", {})
    progress["xp"] = max(0, int(progress.get("xp", 0)) + XP_DELTAS[action])

    icon, text = "•", action
    if action == "lesson_complete":
        fam, lid = meta.get("family"), meta.get("id")
        done = set(counts.get("lessonsDoneIds", []))
        if fam and lid:
            done.add(f"{fam}:{lid}")
        counts["lessonsDoneIds"] = sorted(done)
        counts["lessonsDone"] = len(done)
        icon, text = "🎓", f"Completed {fam or 'a'} lesson {lid or ''}".strip()
    elif action == "correct_label":
        progress["streak"] = int(progress.get("streak", 0)) + 1
        progress["best_streak"] = max(int(progress.get("best_streak", 0)), progress["streak"])
        counts["correctLabels"] = counts.get("correctLabels", 0) + 1
        icon, text = "✓", "Correctly labelled / graded a TTP."
    elif action == "wrong_label":
        progress["streak"] = 0
        counts["wrongLabels"] = counts.get("wrongLabels", 0) + 1
        icon, text = "✗", "Wrong label — streak reset."
    elif action == "canary_found":
        counts["canariesCaught"] = counts.get("canariesCaught", 0) + 1
        icon, text = "🚩", "Caught a canary in an attacker session."
    elif action == "block":
        counts["blocks"] = counts.get("blocks", 0) + 1
        icon, text = "🚫", "Blocked an attacker IP."
    elif action == "duel_played":
        counts["duelsPlayed"] = counts.get("duelsPlayed", 0) + 1
        won = bool(meta.get("won"))
        opp = meta.get("opponent") or "an opponent"
        icon = "🏆" if won else "🤝"
        text = f"{'Won' if won else 'Played'} a duel vs {opp}."
    elif action == "duel_win":
        counts["duelsWon"] = counts.get("duelsWon", 0) + 1
        icon, text = "🏆", f"Won a duel vs {meta.get('opponent') or 'an opponent'}."

    activity: list = progress.setdefault("activity", [])
    activity.insert(0, {"t": _now_iso(), "icon": icon, "text": text})
    del activity[_ACTIVITY_MAX:]
    return progress


def evaluate_badges(
    progress: dict[str, Any],
    *,
    stats: dict[str, Any],
    lessons: dict[str, Any],
) -> list[str]:
    """Mark any newly-satisfied badges as earned (with a timestamp) in
    progress['badges']. Returns the list of newly-earned badge ids."""
    earned: dict[str, str] = progress.setdefault("badges", {})
    ctx = {
        "xp": int(progress.get("xp", 0)),
        "best_streak": int(progress.get("best_streak", 0)),
        "counts": progress.get("counts", {}),
        "stats": stats,
        "lessons": lessons,
    }
    newly: list[str] = []
    for b in BADGES:
        if b["id"] not in earned and b["check"](ctx):
            earned[b["id"]] = _now_iso()
            newly.append(b["id"])
    return newly


def serialize_badges(progress: dict[str, Any]) -> list[dict[str, Any]]:
    """All badges with earned state + metadata, for the profile grid."""
    earned: dict[str, str] = progress.get("badges", {})
    out = []
    for b in BADGES:
        out.append({
            "id": b["id"], "icon": b["icon"], "name": b["name"], "desc": b["desc"],
            "earned": b["id"] in earned, "earned_at": earned.get(b["id"]),
        })
    return out
