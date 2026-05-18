"""Isolation-Forest anomaly detector — Phase 5 Week 17 stretch.

What it does:
  - Each invocation pulls recent scored sessions (`fingerprints` join `sessions`),
    extracts a small numeric feature vector per session, fits an
    `IsolationForest`, and writes `ml_anomaly_scores` rows for the sessions
    that landed in the same window.

  - We deliberately fit + score on the SAME window. With a steady stream of
    benign-scanner sessions plus the occasional sophisticated attack, the
    Isolation Forest treats the outliers as anomalies. This is exactly the
    "compare today's traffic to today's baseline" use case the algorithm is
    good at — and it avoids the headache of model persistence + drift.

  - `model_version` is `if-<features-hash>-<contamination>` so an operator
    can tell at a glance which feature set + hyperparameters produced a row.

Run modes:
  - One-shot: `python -m honeystrike.workers.intel.ml_anomaly`
  - Cron from the operator side (recommended hourly).

The detector deliberately does not run inside the FingerprintWorker — it's
better suited to a periodic batch than to per-session evaluation.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.config import get_settings
from honeystrike.core.db import dispose_engine, get_sessionmaker
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.models import Fingerprint, MLAnomalyScore, Session

log = get_logger(__name__)

# Order matters — also used as the hash input for model_version.
FEATURE_NAMES = (
    "threat_score",
    "abuse_score",
    "tool_count",
    "ttp_count",
    "attempt_rate_rpm",
    "event_count",
    "duration_ms",
    "is_high_severity",
)
DEFAULT_CONTAMINATION = 0.05
DEFAULT_WINDOW_HOURS = 24
MIN_SAMPLES_FOR_FIT = 30


@dataclass(slots=True, frozen=True)
class SessionFeatures:
    session_id: uuid.UUID
    features: list[float]
    raw: dict[str, Any]


def _features_hash() -> str:
    return hashlib.sha256("|".join(FEATURE_NAMES).encode()).hexdigest()[:8]


def model_version(contamination: float = DEFAULT_CONTAMINATION) -> str:
    return f"if-{_features_hash()}-{contamination}"


async def collect_features(
    db: AsyncSession,
    *,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> list[SessionFeatures]:
    since = datetime.now(UTC) - timedelta(hours=window_hours)
    rows = (
        await db.execute(
            select(
                Session.id,
                Session.threat_score,
                Session.event_count,
                Session.duration_ms,
                Session.severity,
                Fingerprint.abuse_score,
                Fingerprint.attempt_rate_rpm,
                Fingerprint.tool_signatures,
            )
            .join(Fingerprint, Fingerprint.session_id == Session.id)
            .where(Session.started_at >= since)
        )
    ).all()

    ttp_counts: dict[Any, int] = {}
    if rows:
        ttp_rows = (
            await db.execute(
                text(
                    "SELECT session_id, count(*) AS c FROM ttp_matches "
                    "WHERE session_id = ANY(:ids) GROUP BY session_id"
                ).bindparams(ids=[str(r.id) for r in rows])
            )
        ).all()
        ttp_counts = {sid: int(c) for sid, c in ttp_rows}

    out: list[SessionFeatures] = []
    for r in rows:
        tools = len(r.tool_signatures or [])
        ttps = int(ttp_counts.get(r.id, 0))
        out.append(
            SessionFeatures(
                session_id=r.id,
                features=[
                    float(r.threat_score or 0),
                    float(r.abuse_score or 0),
                    float(tools),
                    float(ttps),
                    float(r.attempt_rate_rpm or 0),
                    float(r.event_count or 0),
                    float(r.duration_ms or 0),
                    1.0 if r.severity in ("high", "critical") else 0.0,
                ],
                raw={
                    "threat_score": r.threat_score,
                    "abuse_score": r.abuse_score,
                    "tool_count": tools,
                    "ttp_count": ttps,
                    "attempt_rate_rpm": float(r.attempt_rate_rpm) if r.attempt_rate_rpm is not None else None,
                    "event_count": r.event_count,
                    "duration_ms": r.duration_ms,
                    "severity": r.severity,
                },
            )
        )
    return out


def score_batch(
    features: list[SessionFeatures],
    *,
    contamination: float = DEFAULT_CONTAMINATION,
    random_state: int = 42,
) -> list[tuple[SessionFeatures, float, bool]]:
    """Fit Isolation Forest on `features` and return per-row (anomaly_score, is_anomaly).

    `anomaly_score` is normalised so 0=very normal, 1=very anomalous — operator-
    friendly orientation, opposite to sklearn's `score_samples` (where higher
    is more normal). The conversion is monotonic so an operator-readable
    threshold like `> 0.7` still picks the most-anomalous rows first.
    """
    if len(features) < MIN_SAMPLES_FOR_FIT:
        return []
    # Lazy-import sklearn so module import stays cheap and unit tests can run
    # without sklearn installed (the test patches `score_batch`).
    import numpy as np
    from sklearn.ensemble import IsolationForest

    X = np.array([f.features for f in features], dtype=float)
    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100,
    )
    model.fit(X)
    raw_scores = model.score_samples(X)        # higher = more normal
    is_anomaly = model.predict(X) == -1
    # Convert to [0, 1] where 1 is the most anomalous row in this batch.
    lo, hi = float(raw_scores.min()), float(raw_scores.max())
    span = max(hi - lo, 1e-9)
    out: list[tuple[SessionFeatures, float, bool]] = []
    for feat, raw, anom in zip(features, raw_scores, is_anomaly):
        normalised = 1.0 - ((float(raw) - lo) / span)
        out.append((feat, max(0.0, min(1.0, normalised)), bool(anom)))
    return out


async def persist_scores(
    db: AsyncSession,
    rows: list[tuple[SessionFeatures, float, bool]],
    *,
    version: str,
) -> int:
    if not rows:
        return 0
    payloads = [
        {
            "session_id": feat.session_id,
            "anomaly_score": round(score, 4),
            "is_anomaly": is_anom,
            "model_version": version,
            "features": feat.raw,
        }
        for feat, score, is_anom in rows
    ]
    stmt = pg_insert(MLAnomalyScore).values(payloads).on_conflict_do_update(
        index_elements=["session_id"],
        set_={
            "anomaly_score": pg_insert(MLAnomalyScore).excluded.anomaly_score,
            "is_anomaly": pg_insert(MLAnomalyScore).excluded.is_anomaly,
            "model_version": pg_insert(MLAnomalyScore).excluded.model_version,
            "features": pg_insert(MLAnomalyScore).excluded.features,
            "scored_at": datetime.now(UTC),
        },
    )
    await db.execute(stmt)
    await db.commit()
    return len(payloads)


async def run_once(*, window_hours: int = DEFAULT_WINDOW_HOURS) -> int:    # pragma: no cover
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as db:
        feats = await collect_features(db, window_hours=window_hours)
    log.info("ml_anomaly.collected", count=len(feats), window_hours=window_hours)
    if len(feats) < MIN_SAMPLES_FOR_FIT:
        log.info("ml_anomaly.skip_insufficient_samples", count=len(feats))
        return 0
    scored = score_batch(feats)
    version = model_version()
    async with sessionmaker() as db:
        written = await persist_scores(db, scored, version=version)
    log.info("ml_anomaly.persisted", count=written, model_version=version)
    return written


async def _main() -> int:                                  # pragma: no cover
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")
    try:
        await run_once()
        return 0
    finally:
        await dispose_engine()


if __name__ == "__main__":                                 # pragma: no cover
    sys.exit(asyncio.run(_main()))
