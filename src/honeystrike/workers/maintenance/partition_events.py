"""Create future monthly partitions for the `events` table.

Idempotent — safe to invoke daily from cron. Skips months whose partition
already exists. Logs `partition_events.created` per new partition.

Pre-condition: the operator has already run `infra/migrations/003_events_partitioning.sql`,
which converts `events` to a RANGE-partitioned table. Invoking this script
against an un-partitioned `events` table is a no-op (the IS NOT NULL guard
fails the look-up and we log a warning).

Invocation:

    docker compose run --rm app \
        python -m honeystrike.workers.maintenance.partition_events

    # Or schedule via cron, daily:
    # 0 3 * * * /usr/local/bin/python -m honeystrike.workers.maintenance.partition_events
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import text

from honeystrike.config import get_settings
from honeystrike.core.db import dispose_engine, get_sessionmaker
from honeystrike.core.logging import configure_logging, get_logger

log = get_logger(__name__)


def _months_ahead(start: date, count: int) -> list[date]:
    """Return the first day of each of the next `count` months from `start`."""
    months = []
    cur = date(start.year, start.month, 1)
    for _ in range(count):
        months.append(cur)
        # Manual month rollover so we don't drag in dateutil for one helper.
        if cur.month == 12:
            cur = date(cur.year + 1, 1, 1)
        else:
            cur = date(cur.year, cur.month + 1, 1)
    return months


async def _is_partitioned(db) -> bool:                     # pragma: no cover
    row = (
        await db.execute(
            text(
                "SELECT relkind FROM pg_class "
                "WHERE relname = 'events' AND relnamespace = 'public'::regnamespace"
            )
        )
    ).first()
    # 'p' = partitioned table, 'r' = regular table.
    return row is not None and row[0] == "p"


async def ensure_future_partitions(*, lookahead_months: int = 3) -> int:    # pragma: no cover
    """Create partitions for the current month + `lookahead_months` future months."""
    sessionmaker = get_sessionmaker()
    created = 0
    async with sessionmaker() as db:
        if not await _is_partitioned(db):
            log.warning("partition_events.events_not_partitioned")
            return 0
        months = _months_ahead(datetime.now(UTC).date(), lookahead_months + 1)
        for m in months:
            p_name = f"events_{m.year:04d}_{m.month:02d}"
            next_month = (
                date(m.year + 1, 1, 1) if m.month == 12 else date(m.year, m.month + 1, 1)
            )
            # CREATE TABLE IF NOT EXISTS … PARTITION OF … makes this idempotent.
            stmt = text(
                f"CREATE TABLE IF NOT EXISTS {p_name} "
                f"PARTITION OF events FOR VALUES FROM ('{m.isoformat()}') TO ('{next_month.isoformat()}')"
            )
            try:
                await db.execute(stmt)
                log.info(
                    "partition_events.created",
                    partition=p_name,
                    range_start=m.isoformat(),
                    range_end=next_month.isoformat(),
                )
                created += 1
            except Exception as exc:    # noqa: BLE001
                # `IF NOT EXISTS` covers the duplicate case; anything else is
                # operator-visible. Don't crash the loop — keep trying the
                # remaining months.
                log.warning(
                    "partition_events.create_failed",
                    partition=p_name,
                    error=str(exc),
                )
        await db.commit()
    return created


async def _main() -> int:                                  # pragma: no cover
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")
    try:
        created = await ensure_future_partitions()
        log.info("partition_events.done", created=created)
        return 0
    finally:
        await dispose_engine()


if __name__ == "__main__":                                 # pragma: no cover
    sys.exit(asyncio.run(_main()))
