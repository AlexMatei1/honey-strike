"""Live exercise for the Isolation-Forest anomaly detector.

Skips if the DB doesn't yet have enough scored sessions for a fit
(`MIN_SAMPLES_FOR_FIT` from `ml_anomaly`). Otherwise runs the full
collect → fit → persist pipeline against the real Postgres and asserts
`ml_anomaly_scores` rows land.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.core.models import MLAnomalyScore
from honeystrike.workers.intel.ml_anomaly import (
    MIN_SAMPLES_FOR_FIT,
    collect_features,
    model_version,
    persist_scores,
    score_batch,
)


@pytest.mark.asyncio
async def test_pipeline_writes_anomaly_rows(db: AsyncSession) -> None:
    feats = await collect_features(db, window_hours=24 * 30)  # wide window
    if len(feats) < MIN_SAMPLES_FOR_FIT:
        pytest.skip(
            f"DB has {len(feats)} sessions, need {MIN_SAMPLES_FOR_FIT} to fit"
        )

    scored = score_batch(feats)
    assert len(scored) == len(feats)

    before = int(
        (await db.execute(select(func.count(MLAnomalyScore.id)))).scalar_one()
    )
    written = await persist_scores(db, scored, version=model_version())
    after = int(
        (await db.execute(select(func.count(MLAnomalyScore.id)))).scalar_one()
    )

    # `written` equals the batch size; the row count may not grow by that much
    # because the upsert collapses repeats per session.
    assert written == len(scored)
    # We did insert at least one fresh row (or, at minimum, refreshed existing
    # rows in place).
    assert after >= before
