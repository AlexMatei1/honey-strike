"""Unit tests for the open PvP arena state machine (in-memory helpers)."""

from __future__ import annotations

import time

import pytest

from honeystrike.api.routers import arena


@pytest.fixture(autouse=True)
def _reset_arena():
    arena._arena.update({"open": False, "ends_at": None, "opened_by": None, "waves": [], "scores": {}})
    yield
    arena._arena.update({"open": False, "ends_at": None, "opened_by": None, "waves": [], "scores": {}})


def _wave(wid, firer, resolved=False, blocked_by=None):
    return {
        "id": wid, "scenario": "http-recon", "label": "HTTP recon",
        "expected_ttps": ["T1592"], "fired_by": firer, "fired_at": time.time(),
        "resolved": resolved, "blocked_by": blocked_by,
    }


def test_is_open_false_when_closed():
    assert arena._is_open() is False


def test_is_open_expires_past_ends_at():
    arena._arena.update({"open": True, "ends_at": time.time() - 1})
    assert arena._is_open() is False
    assert arena._arena["open"] is False        # auto-closed


def test_is_open_true_within_window():
    arena._arena.update({"open": True, "ends_at": time.time() + 100})
    assert arena._is_open() is True


def test_close_awards_firer_for_unblocked_waves():
    arena._arena.update({
        "open": True, "ends_at": time.time() + 100,
        "waves": [_wave("1", "alice"), _wave("2", "bob", resolved=True, blocked_by="cara")],
        "scores": {"cara": 10},
    })
    arena._close()
    # alice's wave timed out → +10 to alice; bob's was already blocked (no change).
    assert arena._arena["scores"]["alice"] == 10
    assert arena._arena["scores"]["cara"] == 10
    assert arena._arena["open"] is False


def test_scoreboard_sorted_desc():
    arena._arena["scores"] = {"alice": 10, "bob": 30, "cara": 20}
    rows = arena._scoreboard()
    assert [r["username"] for r in rows] == ["bob", "cara", "alice"]


def test_only_labellable_scenarios_offered():
    for s in arena._DUEL_SCENARIOS:
        assert s.get("expected_ttps")
