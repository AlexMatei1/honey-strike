"""`/api/defender/*` — multiplayer game endpoints.

Auth: same Bearer JWT as the rest of the dashboard API. Only the operator
of THIS HoneyStrike instance can label and block; an attacker's CLI never
hits these endpoints (they're scoped to the local defender's instance).
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.config import get_settings
from honeystrike.core import blocklist
from honeystrike.core.models import Session, TTPMatch, User
from honeystrike.workers.intel.fingerprint import _sanitise_ip

router = APIRouter(prefix="/api/defender", tags=["defender"])


class LabelIn(BaseModel):
    session_id: uuid.UUID
    technique_id: str = Field(..., min_length=2, max_length=16)
    match_id: str | None = None
    block: bool = True
    ttl_seconds: int = Field(300, ge=10, le=3600)


class LabelOut(BaseModel):
    correct: bool
    actual_ttps: list[str]
    blocked_ip: str | None = None
    ttl_seconds: int | None = None
    match_id: str | None = None


class BlockIn(BaseModel):
    ip: str
    ttl_seconds: int = Field(300, ge=10, le=3600)
    reason: str | None = None


class BlockOut(BaseModel):
    ok: bool
    ip: str
    ttl_seconds: int


def _redis_client() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url)


@router.post("/label", response_model=LabelOut)
async def label_session(
    body: LabelIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
) -> LabelOut:
    """Label the TTP an attacker exhibited. If the label matches a real
    `ttp_matches.technique_id` on that session, optionally block the
    source IP for `ttl_seconds`."""
    sess = (
        (await db.execute(select(Session).where(Session.id == body.session_id)))
        .scalars().first()
    )
    if sess is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")

    actual = (
        (await db.execute(
            select(TTPMatch.technique_id).where(TTPMatch.session_id == sess.id)
        )).scalars().all()
    )
    actual_ids = [str(t) for t in actual]
    guess = body.technique_id.strip().upper()
    correct = guess in {a.upper() for a in actual_ids}

    blocked_ip: str | None = None
    ttl_used: int | None = None
    if correct and body.block:
        # Sessions.src_ip is Postgres inet ("1.2.3.4/32"); listeners see the
        # bare host string, so normalise before writing the blocklist key.
        ip_to_block = _sanitise_ip(str(sess.src_ip))
        client = _redis_client()
        try:
            await blocklist.add(
                client, ip_to_block,
                ttl_seconds=body.ttl_seconds,
                reason=f"correct-label {guess} (match={body.match_id})",
            )
            blocked_ip = ip_to_block
            ttl_used = body.ttl_seconds
        finally:
            await client.aclose()

    return LabelOut(
        correct=correct,
        actual_ttps=actual_ids,
        blocked_ip=blocked_ip,
        ttl_seconds=ttl_used,
        match_id=body.match_id,
    )


@router.post("/block", response_model=BlockOut)
async def block_ip(
    body: BlockIn,
    _user: Annotated[User, Depends(current_user)],
) -> BlockOut:
    """Manually add an IP to the block list. Used by `defend label --block` and
    can also be invoked by the operator for ad-hoc blocking."""
    ip_to_block = _sanitise_ip(body.ip)
    # Reject anything that isn't a real IP so a malformed value can't be
    # written as a stray Redis blocklist key.
    try:
        ipaddress.ip_address(ip_to_block)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"not a valid IP address: {body.ip!r}",
        ) from exc
    client = _redis_client()
    try:
        await blocklist.add(client, ip_to_block,
                            ttl_seconds=body.ttl_seconds, reason=body.reason)
    finally:
        await client.aclose()
    return BlockOut(ok=True, ip=ip_to_block, ttl_seconds=body.ttl_seconds)


@router.delete("/block/{ip}")
async def unblock_ip(
    ip: str,
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    client = _redis_client()
    try:
        await blocklist.remove(client, ip)
    finally:
        await client.aclose()
    return {"ok": True, "ip": ip}


@router.get("/block/{ip}")
async def block_status(
    ip: str,
    _user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    client = _redis_client()
    try:
        blocked = await blocklist.is_blocked(client, ip)
        ttl = await blocklist.ttl(client, ip) if blocked else None
    finally:
        await client.aclose()
    return {"ip": ip, "blocked": blocked, "ttl_seconds": ttl}
