"""Add user roles (admin/member) + a server-side per-user progress table.

Phase 9 introduces role-based access (SOC Lead = admin, Analyst = member) and
moves the gamification state (XP, streak, badges, activity) out of the
browser's localStorage into the database so it follows the account across
devices and admins can see member progress.

asyncpg note: one statement per op.execute().

Revision ID: 006
Revises: 005
Create Date: 2026-05-19
"""

from __future__ import annotations

from alembic import op

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ---- roles --------------------------------------------------------------
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(16) NOT NULL DEFAULT 'member'")
    op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_user_role")
    op.execute("ALTER TABLE users ADD CONSTRAINT ck_user_role CHECK (role IN ('admin','member'))")
    # Best-effort promote the conventional seed admin; bootstrap also enforces
    # this on boot for whatever ADMIN_USERNAME is configured.
    op.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")

    # ---- per-user progress --------------------------------------------------
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS user_progress (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id     UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            xp          INTEGER NOT NULL DEFAULT 0,
            streak      INTEGER NOT NULL DEFAULT 0,
            best_streak INTEGER NOT NULL DEFAULT 0,
            badges      JSONB NOT NULL DEFAULT '{}'::jsonb,
            counts      JSONB NOT NULL DEFAULT '{}'::jsonb,
            activity    JSONB NOT NULL DEFAULT '[]'::jsonb,
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_progress")
    op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_user_role")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS role")
