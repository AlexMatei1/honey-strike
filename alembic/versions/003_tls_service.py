"""Allow 'tls' as a sessions.service value.

Phase 5 ships a TLS-fingerprint sniffer that captures JA3 hashes on its own
high port. Sessions opened by that listener carry `service='tls'`; the
check-constraint needs to know about it. Same change is mirrored in the
`events` table to keep the per-event service column in sync.

Revision ID: 003
Revises: 002
Create Date: 2026-05-17
"""

from __future__ import annotations

from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Postgres auto-generated the original 'service IN (…)' constraint under
    # the name `sessions_service_check` when the column was declared inline.
    # Drop both possible names so this migration works against both the
    # 001-bootstrapped schema and a fresh ORM-created one.
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_service_check")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS ck_service")
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT ck_service "
        "CHECK (service IN ('ssh','http','ftp','rdp','tls'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS ck_service")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_service_check")
    op.execute(
        "ALTER TABLE sessions ADD CONSTRAINT ck_service "
        "CHECK (service IN ('ssh','http','ftp','rdp'))"
    )
