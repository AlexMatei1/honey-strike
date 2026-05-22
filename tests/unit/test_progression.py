"""Unit tests for core.progression — the server-side XP/rank/badge rules."""

from __future__ import annotations

from honeystrike.core import progression as P


def _fresh() -> dict:
    return {"xp": 0, "streak": 0, "best_streak": 0, "counts": {}, "activity": [], "badges": {}}


# ---- XP + actions --------------------------------------------------------

def test_lesson_complete_awards_xp_and_records_done():
    p = _fresh()
    P.apply_event(p, "lesson_complete", {"family": "attack", "id": "ssh-hydra"})
    assert p["xp"] == 15
    assert p["counts"]["lessonsDone"] == 1
    assert "attack:ssh-hydra" in p["counts"]["lessonsDoneIds"]
    assert p["activity"][0]["icon"] == "🎓"


def test_lesson_complete_dedupes_same_lesson():
    p = _fresh()
    P.apply_event(p, "lesson_complete", {"family": "attack", "id": "ssh-hydra"})
    P.apply_event(p, "lesson_complete", {"family": "attack", "id": "ssh-hydra"})
    assert p["counts"]["lessonsDone"] == 1     # still one distinct lesson
    assert p["xp"] == 30                        # but xp awarded twice


def test_correct_label_builds_streak():
    p = _fresh()
    P.apply_event(p, "correct_label", None)
    P.apply_event(p, "correct_label", None)
    assert p["xp"] == 20
    assert p["streak"] == 2
    assert p["best_streak"] == 2


def test_wrong_label_resets_streak_and_floors_xp():
    p = _fresh()
    P.apply_event(p, "correct_label", None)   # xp 10, streak 1
    P.apply_event(p, "wrong_label", None)     # xp 8, streak 0
    assert p["streak"] == 0
    assert p["best_streak"] == 1
    assert p["xp"] == 8


def test_xp_never_negative():
    p = _fresh()
    for _ in range(5):
        P.apply_event(p, "wrong_label", None)
    assert p["xp"] == 0


def test_block_and_canary_counts():
    p = _fresh()
    P.apply_event(p, "block", None)
    P.apply_event(p, "canary_found", None)
    assert p["counts"]["blocks"] == 1
    assert p["counts"]["canariesCaught"] == 1
    assert p["xp"] == 8


def test_unknown_action_is_noop():
    p = _fresh()
    P.apply_event(p, "nonsense", None)
    assert p["xp"] == 0


def test_activity_capped():
    p = _fresh()
    for _ in range(80):
        P.apply_event(p, "correct_label", None)
    assert len(p["activity"]) == 50


# ---- ranks ---------------------------------------------------------------

def test_rank_progression():
    assert P.rank_for(0)["name"] == "Apprentice"
    assert P.rank_for(25)["name"] == "Sentry"
    assert P.rank_for(1000)["name"] == "HoneyMaster"
    assert P.rank_for(1000)["next"] is None


def test_rank_pct_within_band():
    r = P.rank_for(50)        # between Sentry(25) and Defender(75)
    assert r["name"] == "Sentry"
    assert r["next"] == "Defender"
    assert 0 <= r["pct"] <= 100


# ---- badges --------------------------------------------------------------

def _ctx_lessons(attack_done=None, defend_done=None, all_attack=None, all_defend=None):
    return {
        "attack": set(attack_done or []),
        "defend": set(defend_done or []),
        "_all_attack": set(all_attack or []),
        "_all_defend": set(all_defend or []),
    }


def test_newcomer_and_first_xp_badges():
    p = _fresh()
    P.apply_event(p, "lesson_complete", {"family": "attack", "id": "x"})
    newly = P.evaluate_badges(p, stats={}, lessons=_ctx_lessons())
    assert "newcomer" in newly
    assert "first-xp" in newly
    assert "student" in newly


def test_scholar_requires_all_attack_lessons():
    p = _fresh()
    p["counts"]["lessonsDoneIds"] = ["attack:a", "attack:b"]
    lessons = _ctx_lessons(attack_done=["a", "b"], all_attack=["a", "b"])
    newly = P.evaluate_badges(p, stats={}, lessons=lessons)
    assert "scholar" in newly


def test_scholar_not_earned_when_lessons_remain():
    p = _fresh()
    lessons = _ctx_lessons(attack_done=["a"], all_attack=["a", "b"])
    newly = P.evaluate_badges(p, stats={}, lessons=lessons)
    assert "scholar" not in newly


def test_stat_badges_critical_and_globalist():
    p = _fresh()
    newly = P.evaluate_badges(
        p, stats={"critical_sessions": 3, "unique_countries": 6}, lessons=_ctx_lessons()
    )
    assert "critical-catcher" in newly
    assert "globalist" in newly


def test_badges_not_re_awarded():
    p = _fresh()
    P.evaluate_badges(p, stats={}, lessons=_ctx_lessons())     # earns newcomer
    again = P.evaluate_badges(p, stats={}, lessons=_ctx_lessons())
    assert "newcomer" not in again      # already earned, not in newly list


def test_serialize_badges_marks_earned():
    p = _fresh()
    P.evaluate_badges(p, stats={}, lessons=_ctx_lessons())
    serialized = P.serialize_badges(p)
    by_id = {b["id"]: b for b in serialized}
    assert by_id["newcomer"]["earned"] is True
    assert by_id["honeymaster"]["earned"] is False
    assert len(serialized) == len(P.BADGES)
