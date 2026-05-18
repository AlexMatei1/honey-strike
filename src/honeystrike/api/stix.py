"""STIX 2.1 bundle export — Phase 5 Week 17 stretch.

Translates HoneyStrike's per-session intel into a STIX 2.1 `Bundle`:

  - one `Identity` per HoneyStrike instance (the producer)
  - one `Indicator` per high-severity attacker IP (pattern: `[ipv4-addr:value = '…']`)
  - one `ObservedData` per session with `network-traffic` + `ipv4-addr` SCOs
  - one `Sighting` linking the indicator to the observed-data

Bundles are typically consumed by SIEMs / threat-intel platforms that
ingest STIX directly. The same bundle is what the TAXII collection serves
under `objects/`.

Endpoint: `GET /api/stix/bundle?days=7&min_score=60` — auth required.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import stix2
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.core.models import Fingerprint, Session, TTPMatch, User

router = APIRouter(prefix="/api/stix", tags=["stix"])

# Deterministic identity UUID so consumers can recognise the same source
# across bundle pulls. Namespace UUID is "HoneyStrike v1.0".
HONEYSTRIKE_IDENTITY_ID = "identity--c1c1c1c1-c1c1-4c1c-8c1c-c1c1c1c1c1c1"


def _identity() -> stix2.Identity:
    return stix2.Identity(
        id=HONEYSTRIKE_IDENTITY_ID,
        name="HoneyStrike",
        identity_class="system",
        description="HoneyStrike active honeypot platform producer identity.",
    )


async def build_bundle(
    db: AsyncSession,
    *,
    days: int,
    min_score: int,
    limit: int,
) -> stix2.Bundle:
    """Build a STIX 2.1 bundle of sessions matching the filter."""
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        await db.execute(
            select(
                Session.id,
                Session.src_ip,
                Session.service,
                Session.threat_score,
                Session.severity,
                Session.started_at,
                Session.ended_at,
                Fingerprint.country_iso,
                Fingerprint.asn,
                Fingerprint.org,
                Fingerprint.tool_signatures,
            )
            .join(Fingerprint, Fingerprint.session_id == Session.id)
            .where(Session.started_at >= since)
            .where(Session.threat_score >= min_score)
            .order_by(Session.started_at.desc())
            .limit(limit)
        )
    ).all()

    sids = [r.id for r in rows]
    technique_map: dict[Any, list[str]] = {sid: [] for sid in sids}
    if sids:
        ttp_rows = (
            await db.execute(
                select(TTPMatch.session_id, TTPMatch.technique_id)
                .where(TTPMatch.session_id.in_(sids))
            )
        ).all()
        for sid, tid in ttp_rows:
            technique_map.setdefault(sid, []).append(tid)

    identity = _identity()
    objects: list[Any] = [identity]
    indicators_by_ip: dict[str, stix2.Indicator] = {}

    for r in rows:
        ip = str(r.src_ip)

        if ip not in indicators_by_ip:
            indicator = stix2.Indicator(
                created_by_ref=identity.id,
                name=f"Hostile honeypot interactor {ip}",
                description=(
                    f"Source IP observed attacking a HoneyStrike honeypot. "
                    f"ASN AS{r.asn} ({r.org})." if r.asn else
                    f"Source IP observed attacking a HoneyStrike honeypot."
                ),
                pattern_type="stix",
                pattern=f"[ipv4-addr:value = '{ip}']",
                valid_from=r.started_at,
                indicator_types=["malicious-activity"],
                labels=[r.severity],
            )
            indicators_by_ip[ip] = indicator
            objects.append(indicator)

        addr = stix2.IPv4Address(value=ip)
        net = stix2.NetworkTraffic(
            src_ref=addr.id,
            protocols=["tcp", r.service],
            extensions={},
        )
        observed = stix2.ObservedData(
            created_by_ref=identity.id,
            first_observed=r.started_at,
            last_observed=r.ended_at or r.started_at,
            number_observed=1,
            object_refs=[addr.id, net.id],
        )
        sighting = stix2.Sighting(
            created_by_ref=identity.id,
            sighting_of_ref=indicators_by_ip[ip].id,
            observed_data_refs=[observed.id],
            first_seen=r.started_at,
            last_seen=r.ended_at or r.started_at,
            count=1,
        )

        objects.extend([addr, net, observed, sighting])

    bundle = stix2.Bundle(objects=objects, allow_custom=False)
    return bundle


@router.get("/bundle")
async def get_bundle(                                      # pragma: no cover
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(7, ge=1, le=90),
    min_score: int = Query(60, ge=0, le=100),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    bundle = await build_bundle(db, days=days, min_score=min_score, limit=limit)
    # stix2 objects serialise via .serialize() which returns a JSON string.
    # Return parsed JSON so FastAPI applies the standard Content-Type and the
    # OpenAPI schema stays accurate.
    import json
    return json.loads(bundle.serialize())


@router.get("/identity")
async def get_identity(                                    # pragma: no cover
    _user: Annotated[User, Depends(current_user)],
) -> dict:
    """Return the HoneyStrike STIX `identity` SDO. Useful for TAXII discovery."""
    import json
    return json.loads(_identity().serialize())


@router.get("/stats")
async def stix_stats(                                      # pragma: no cover
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(7, ge=1, le=90),
    min_score: int = Query(60, ge=0, le=100),
) -> dict:
    """Cheap pre-flight: how big would the bundle be for these filters?"""
    since = datetime.now(UTC) - timedelta(days=days)
    count = int(
        (
            await db.execute(
                select(func.count(Session.id))
                .join(Fingerprint, Fingerprint.session_id == Session.id)
                .where(Session.started_at >= since)
                .where(Session.threat_score >= min_score)
            )
        ).scalar_one()
    )
    return {
        "days": days,
        "min_score": min_score,
        "matching_sessions": count,
        "estimated_objects": 1 + count * 5,        # identity + (indicator+addr+net+observed+sighting)
    }
