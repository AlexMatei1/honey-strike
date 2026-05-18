"""Composite threat-score for a fingerprinted session.

Takes the artefacts the FingerprintWorker has already produced
(abuse record, tool signatures, TTP matches) and folds them into a single
0..100 integer plus a severity bucket. The formula is intentionally
transparent so an operator reviewing a flagged session can reproduce the
score from the row contents.

  abuse_component     = round(abuse_score * 0.40)                # 0..40
  tool_component      = clamp(0, 30, 15 * num_tools_>=0.7_conf)   # 0..30
  ttp_component       = clamp(0, 50, round(50 * mean_confidence)) # 0..50
  privilege_bonus     = 25 if T1078 (Valid Accounts) else 0       # 0..25

  score = clamp(0, 100, sum_of_components)
  severity = low <20, medium <50, high <80, critical otherwise.

All weights are heuristics chosen by reading docs/01 §M3 + §Severity scale.
The tests in test_threat_scoring lock the boundary behaviour in.
"""

from __future__ import annotations

from dataclasses import dataclass

from honeystrike.workers.intel.signatures import ToolMatch
from honeystrike.workers.intel.ttp_rules import TTPMatch


@dataclass(slots=True, frozen=True)
class ThreatScore:
    score: int
    severity: str            # low | medium | high | critical
    components: dict[str, int]


# Cap-tunable. Kept module-level so callers can monkey-patch in tests.
_TOOL_CONFIDENCE_FLOOR = 0.70
_TOOL_WEIGHT = 15
_TOOL_CAP = 30
_TTP_CAP = 50
_ABUSE_WEIGHT = 0.40
_PRIVILEGE_BONUS = 25
_PRIVILEGE_TID = "T1078"


def _bucket(score: int) -> str:
    if score < 20:
        return "low"
    if score < 50:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def score_session(
    *,
    abuse_score: int | None,
    tool_matches: list[ToolMatch],
    ttp_matches: list[TTPMatch],
) -> ThreatScore:
    """Compute a session-level threat score from the worker's enrichment output."""
    abuse_component = round((abuse_score or 0) * _ABUSE_WEIGHT)
    abuse_component = max(0, min(40, abuse_component))

    high_conf_tools = sum(1 for t in tool_matches if t.confidence >= _TOOL_CONFIDENCE_FLOOR)
    tool_component = min(_TOOL_CAP, _TOOL_WEIGHT * high_conf_tools)

    if ttp_matches:
        mean_ttp_conf = sum(m.confidence for m in ttp_matches) / len(ttp_matches)
        ttp_component = min(_TTP_CAP, round(_TTP_CAP * mean_ttp_conf))
    else:
        ttp_component = 0

    privilege_bonus = (
        _PRIVILEGE_BONUS
        if any(m.technique_id == _PRIVILEGE_TID for m in ttp_matches)
        else 0
    )

    total = abuse_component + tool_component + ttp_component + privilege_bonus
    score = max(0, min(100, total))
    return ThreatScore(
        score=score,
        severity=_bucket(score),
        components={
            "abuse": abuse_component,
            "tool": tool_component,
            "ttp": ttp_component,
            "privilege": privilege_bonus,
        },
    )
