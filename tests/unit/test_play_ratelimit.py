"""Unit tests for the /api/play rate limiter.

The play endpoints fire real attack traffic, so launches are capped by
concurrency and by a rolling per-minute window. We test the pure guard
`_enforce_rate_limit` directly against the in-process registries.
"""

from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from honeystrike.api.routers import play


@pytest.fixture(autouse=True)
def _clean_registries():
    play._TASKS.clear()
    play._launch_times.clear()
    yield
    play._TASKS.clear()
    play._launch_times.clear()


def _running_task(tid: str) -> play.PlayTask:
    return play.PlayTask(task_id=tid, scenario="ssh-hydra", target="x", status="running")


def test_allows_launch_under_limits():
    # No tasks, no recent launches → fine.
    play._enforce_rate_limit()
    assert len(play._launch_times) == 1


def test_blocks_when_max_concurrent_running():
    for i in range(play.MAX_CONCURRENT):
        play._TASKS[str(i)] = _running_task(str(i))
    with pytest.raises(HTTPException) as exc:
        play._enforce_rate_limit()
    assert exc.value.status_code == 429
    assert "concurrent" in exc.value.detail


def test_finished_tasks_do_not_count_toward_concurrency():
    for i in range(play.MAX_CONCURRENT):
        t = _running_task(str(i))
        t.status = "done"
        t.finished_at = time.time()
        play._TASKS[str(i)] = t
    # All finished → should not block.
    play._enforce_rate_limit()


def test_blocks_when_window_rate_exceeded():
    now = time.time()
    play._launch_times.extend([now] * play.MAX_PER_WINDOW)
    with pytest.raises(HTTPException) as exc:
        play._enforce_rate_limit()
    assert exc.value.status_code == 429
    assert "rate" in exc.value.detail.lower()
    assert "Retry-After" in exc.value.headers


def test_window_slides_so_old_launches_expire():
    old = time.time() - play.WINDOW_SECONDS - 5
    play._launch_times.extend([old] * play.MAX_PER_WINDOW)
    # All are older than the window → they get pruned and the launch is allowed.
    play._enforce_rate_limit()
    assert len(play._launch_times) == 1
