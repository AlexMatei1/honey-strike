"""Tests for the composite threat-score helper."""

from __future__ import annotations

from honeystrike.workers.intel.signatures import ToolMatch
from honeystrike.workers.intel.threat_scoring import score_session
from honeystrike.workers.intel.ttp_rules import TTPMatch


def _ttp(tid: str, conf: float, name: str = "demo", tactic: str = "Demo") -> TTPMatch:
    return TTPMatch(
        technique_id=tid,
        technique_name=name,
        tactic=tactic,
        confidence=conf,
        trigger_event_id=None,
    )


def test_no_signal_returns_zero_low() -> None:
    s = score_session(abuse_score=None, tool_matches=[], ttp_matches=[])
    assert s.score == 0
    assert s.severity == "low"
    assert s.components == {"abuse": 0, "tool": 0, "ttp": 0, "privilege": 0}


def test_abuse_only_caps_at_40() -> None:
    s = score_session(abuse_score=100, tool_matches=[], ttp_matches=[])
    assert s.components["abuse"] == 40
    assert s.score == 40
    assert s.severity == "medium"


def test_low_confidence_tools_do_not_count() -> None:
    s = score_session(
        abuse_score=None,
        tool_matches=[ToolMatch("curl", 0.3), ToolMatch("python-requests", 0.4)],
        ttp_matches=[],
    )
    assert s.components["tool"] == 0


def test_tool_component_capped_at_30() -> None:
    s = score_session(
        abuse_score=None,
        tool_matches=[
            ToolMatch("sqlmap", 0.99),
            ToolMatch("Hydra", 0.95),
            ToolMatch("Masscan", 0.90),
            ToolMatch("Nikto", 0.95),
        ],
        ttp_matches=[],
    )
    assert s.components["tool"] == 30


def test_ttp_mean_confidence_drives_score() -> None:
    s = score_session(
        abuse_score=None,
        tool_matches=[],
        ttp_matches=[_ttp("T1190", 0.85), _ttp("T1083", 0.75)],
    )
    # Mean 0.80 → 40 points; not enough on its own for high.
    assert s.components["ttp"] == 40
    assert s.severity == "medium"


def test_privilege_bonus_fires_on_T1078() -> None:
    s = score_session(
        abuse_score=None,
        tool_matches=[],
        ttp_matches=[_ttp("T1078", 0.90)],
    )
    # ttp_component = round(50 * 0.90) = 45, plus 25 privilege bonus = 70 → high.
    assert s.components["privilege"] == 25
    assert s.score == 70
    assert s.severity == "high"


def test_combined_signals_can_reach_critical() -> None:
    s = score_session(
        abuse_score=90,                                  # 36
        tool_matches=[ToolMatch("sqlmap", 0.99),
                      ToolMatch("Hydra", 0.95)],          # 30
        ttp_matches=[_ttp("T1078", 0.90),
                     _ttp("T1190", 0.85)],                # mean 0.875 → 44, +25 priv
    )
    assert s.score == 100
    assert s.severity == "critical"


def test_score_is_clamped_to_100() -> None:
    s = score_session(
        abuse_score=100,
        tool_matches=[ToolMatch("sqlmap", 0.99)] * 10,
        ttp_matches=[_ttp("T1078", 1.0), _ttp("T1190", 1.0)],
    )
    assert s.score == 100
    assert s.severity == "critical"
