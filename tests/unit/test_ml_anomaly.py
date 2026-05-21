"""Tests for the Isolation-Forest anomaly detector (Phase 5 stretch).

The persistence and DB-collection paths are exercised by integration. Here
we focus on the pure pieces:
  - `_months_ahead` (used by partition_events maintenance) is in its own test
  - `model_version` is stable for a fixed feature set
  - `score_batch` returns the expected shape and clamps the score range
"""

from __future__ import annotations

import uuid

import pytest

from honeystrike.workers.intel.ml_anomaly import (
    FEATURE_NAMES,
    SessionFeatures,
    model_version,
    score_batch,
)


def _feat(values: list[float]) -> SessionFeatures:
    return SessionFeatures(session_id=uuid.uuid4(), features=values, raw={})


def test_feature_names_are_stable() -> None:
    assert FEATURE_NAMES == (
        "threat_score",
        "abuse_score",
        "tool_count",
        "ttp_count",
        "attempt_rate_rpm",
        "event_count",
        "duration_ms",
        "is_high_severity",
    )


def test_model_version_changes_when_features_change(monkeypatch) -> None:
    base = model_version()
    monkeypatch.setattr(
        "honeystrike.workers.intel.ml_anomaly.FEATURE_NAMES",
        (*FEATURE_NAMES, "extra_feature"),
    )
    mutated = model_version()
    assert base != mutated


def test_score_batch_skips_when_too_few_samples() -> None:
    # MIN_SAMPLES_FOR_FIT = 30
    rows = [_feat([float(i)] * len(FEATURE_NAMES)) for i in range(10)]
    assert score_batch(rows) == []


def test_score_batch_returns_one_result_per_input() -> None:
    pytest.importorskip("sklearn", reason="scikit-learn not installed in this env")
    # 35 mostly-benign + 5 outliers.
    benign = [_feat([10.0, 0.0, 0.0, 0.0, 1.0, 5.0, 100.0, 0.0]) for _ in range(35)]
    spikes = [_feat([95.0, 90.0, 4.0, 4.0, 9999.0, 500.0, 1.0, 1.0]) for _ in range(5)]
    rows = benign + spikes
    out = score_batch(rows)
    assert len(out) == len(rows)
    # Output shape: (feat, score in [0,1], is_anomaly bool)
    for feat, score, is_anom in out:
        assert 0.0 <= score <= 1.0
        assert isinstance(is_anom, bool)
    # The outliers should land higher on the anomaly axis than the mean.
    bench_scores = [s for _, s, _ in out[:35]]
    spike_scores = [s for _, s, _ in out[35:]]
    assert max(spike_scores) > max(bench_scores)


def test_score_batch_marks_some_outliers_as_anomaly() -> None:
    pytest.importorskip("sklearn", reason="scikit-learn not installed in this env")
    benign = [_feat([10.0, 0.0, 0.0, 0.0, 1.0, 5.0, 100.0, 0.0]) for _ in range(40)]
    spikes = [_feat([99.0, 95.0, 4.0, 4.0, 99999.0, 9999.0, 1.0, 1.0]) for _ in range(3)]
    out = score_batch(benign + spikes, contamination=0.07)
    flagged = [is_anom for _, _, is_anom in out]
    # At least one row in the batch must be flagged.
    assert any(flagged)
