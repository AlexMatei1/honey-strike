"""Allow 'telnet', 'smtp', 'redis' as sessions.service values.

Phase 8 adds three more honeypot listeners for the most-scanned ports the
v1 stack didn't cover: Telnet (:23), SMTP (:25), and Redis (:6379). Their
sessions carry the new service strings, so the check-constraint has to know
about them. The `events` table has no service CHECK (it's a plain String),
so only `sessions` needs the migration.

Revision ID: 005
Revises: 004
Create Date: 2026-05-19
"""

from __future__ import annotations

from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None

_ALL = "('ssh','http','ftp','rdp','tls','telnet','smtp','redis')"
_PREV = "('ssh','http','ftp','rdp','tls')"


def upgrade() -> None:
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_service_check")
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS ck_service")
    op.execute(f"ALTER TABLE sessions ADD CONSTRAINT ck_service CHECK (service IN {_ALL})")


def downgrade() -> None:
    op.execute("ALTER TABLE sessions DROP CONSTRAINT IF EXISTS ck_service")
    op.execute(f"ALTER TABLE sessions ADD CONSTRAINT ck_service CHECK (service IN {_PREV})")
