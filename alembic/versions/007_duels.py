"""Member-vs-member duels (in-instance consensual PvP).

A duel pairs an attacker member with a defender member for a timed match.
The attacker fires scenario "waves" at the shared honeypot; the defender
labels each wave's TTP in time to "block" it. Scores + winner are computed
at finish and awarded as XP.

Wave state lives in a JSONB column (low concurrency, one writer per side).

asyncpg note: one statement per op.execute().

Revision ID: 007
Revises: 006
Create Date: 2026-05-19
"""

from __future__ import annotations

from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS duels (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            attacker_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            defender_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status        VARCHAR(16) NOT NULL DEFAULT 'pending',
            duration_seconds INTEGER NOT NULL DEFAULT 300,
            attacker_score INTEGER NOT NULL DEFAULT 0,
            defender_score INTEGER NOT NULL DEFAULT 0,
            waves         JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            started_at    TIMESTAMPTZ,
            ends_at       TIMESTAMPTZ,
            finished_at   TIMESTAMPTZ
        )
        """
    )
    op.execute(
        "ALTER TABLE duels ADD CONSTRAINT ck_duel_status "
        "CHECK (status IN ('pending','active','declined','finished','expired'))"
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_duels_defender ON duels (defender_id, status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_duels_attacker ON duels (attacker_id, status)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS duels")
