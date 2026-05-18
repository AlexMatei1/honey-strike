"""Allow 'log' as an alerts.channel value.

Phase 3 Week 10 adds a `log` channel that always succeeds — used in dev/CI
where no real transport is configured. Persisting one row per dispatched
channel keeps the alerts table self-describing, so the check constraint
needs to know about it.

Revision ID: 002
Revises: 001
Create Date: 2026-05-17
"""

from __future__ import annotations

from alembic import op

revision = "002"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_channel_check")
    op.execute(
        "ALTER TABLE alerts ADD CONSTRAINT alerts_channel_check "
        "CHECK (channel IN ('telegram','email','slack','log'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_channel_check")
    op.execute(
        "ALTER TABLE alerts ADD CONSTRAINT alerts_channel_check "
        "CHECK (channel IN ('telegram','email','slack'))"
    )
