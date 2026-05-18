"""Tests for the events-partition maintenance helper."""

from __future__ import annotations

from datetime import date

from honeystrike.workers.maintenance.partition_events import _months_ahead


def test_months_ahead_returns_first_of_each_month() -> None:
    months = _months_ahead(date(2026, 5, 17), 4)
    assert months == [
        date(2026, 5, 1),
        date(2026, 6, 1),
        date(2026, 7, 1),
        date(2026, 8, 1),
    ]


def test_months_ahead_wraps_year_boundary() -> None:
    months = _months_ahead(date(2026, 11, 20), 3)
    assert months == [
        date(2026, 11, 1),
        date(2026, 12, 1),
        date(2027, 1, 1),
    ]


def test_months_ahead_count_zero_returns_empty() -> None:
    assert _months_ahead(date(2026, 5, 17), 0) == []
