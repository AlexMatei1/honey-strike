"""Allow 'discord' as an alerts.channel value (Phase 6 multiplayer).

Revision ID: 004
Revises: 003
Create Date: 2026-05-18
"""

from __future__ import annotations

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_channel_check")
    op.execute(
        "ALTER TABLE alerts ADD CONSTRAINT alerts_channel_check "
        "CHECK (channel IN ('telegram','email','slack','log','discord'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_channel_check")
    op.execute(
        "ALTER TABLE alerts ADD CONSTRAINT alerts_channel_check "
        "CHECK (channel IN ('telegram','email','slack','log'))"
    )
