"""Bootstrap the dashboard's first admin user.

Invocation (one-shot, idempotent):

    docker compose run --rm app python -m honeystrike.api.bootstrap

Reads `ADMIN_USERNAME` and `ADMIN_PASSWORD` from the environment; falls
back to the values baked into `Settings`. Creates the user if it doesn't
exist; otherwise refreshes the password hash so an operator can rotate
credentials without manual SQL.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from honeystrike.api.auth import hash_password
from honeystrike.config import get_settings
from honeystrike.core.db import dispose_engine, get_sessionmaker
from honeystrike.core.logging import configure_logging, get_logger
from honeystrike.core.models import User

log = get_logger(__name__)


async def _run() -> int:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    username = settings.admin_username
    password = settings.admin_password
    if not username or not password:
        log.error("bootstrap.missing_credentials")
        return 2

    sessionmaker = get_sessionmaker()
    hashed = hash_password(password)
    async with sessionmaker() as db:
        existing = (
            (await db.execute(select(User).where(User.username == username)))
            .scalars()
            .first()
        )
        if existing is None:
            await db.execute(
                pg_insert(User).values(
                    username=username,
                    password_hash=hashed,
                    role="admin",
                    is_active=True,
                )
            )
            log.info("bootstrap.admin_created", username=username)
        else:
            await db.execute(
                pg_insert(User)
                .values(
                    id=existing.id,
                    username=username,
                    password_hash=hashed,
                    role="admin",
                    is_active=True,
                )
                .on_conflict_do_update(
                    index_elements=["id"],
                    # Always (re)assert admin role + active for the seed account.
                    set_={"password_hash": hashed, "role": "admin", "is_active": True},
                )
            )
            log.info("bootstrap.admin_rotated", username=username)
        await db.commit()

    await dispose_engine()
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
