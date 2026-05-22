"""Add optional email + verification flag to users.

Enables email verification and self-service password reset. Email is optional
(nullable) so existing accounts and email-less signups keep working.

asyncpg note: one statement per op.execute().

Revision ID: 008
Revises: 007
Create Date: 2026-05-19
"""

from __future__ import annotations

from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE")
    # Case-insensitive uniqueness for emails that are set (NULLs allowed/ignored).
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_lower "
        "ON users (lower(email)) WHERE email IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_users_email_lower")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS email_verified")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS email")
