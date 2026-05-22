"""Unit tests for the duel scoring helpers (pure pieces, no DB)."""

from __future__ import annotations

from types import SimpleNamespace

from honeystrike.api.routers import duels


def _duel(waves):
    return SimpleNamespace(waves=waves, attacker_score=0, defender_score=0)


def test_tally_counts_blocked_and_through():
    d = _duel([
        {"id": "1", "correct": True},
        {"id": "2", "correct": False},
        {"id": "3", "correct": True},
    ])
    duels._tally(d)
    assert d.defender_score == 20      # 2 blocked × 10
    assert d.attacker_score == 10      # 1 through × 10


def test_tally_empty_duel_is_zero():
    d = _duel([])
    duels._tally(d)
    assert d.attacker_score == 0
    assert d.defender_score == 0


def test_tally_all_blocked():
    d = _duel([{"id": "1", "correct": True}, {"id": "2", "correct": True}])
    duels._tally(d)
    assert d.defender_score == 20
    assert d.attacker_score == 0


def test_duel_scenarios_all_have_expected_ttps():
    # Only scenarios with a labellable technique are duel-able.
    for s in duels._DUEL_SCENARIOS:
        assert s.get("expected_ttps"), f"{s['id']} has no expected_ttps"


def test_duel_scenarios_indexed_by_id():
    for s in duels._DUEL_SCENARIOS:
        assert duels._BY_ID[s["id"]] is s


def test_wave_points_constant():
    assert duels.WAVE_POINTS == 10
