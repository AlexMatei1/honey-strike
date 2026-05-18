"""Minimal TAXII 2.1 read-only server — Phase 5 Week 17 stretch.

Exposes the same STIX bundle the `/api/stix/bundle` endpoint serves, but
through the TAXII 2.1 discovery + collection layout that ingestion
platforms (MISP, OpenCTI) expect.

Spec compliance is intentionally narrow:
  - `GET  /taxii2/`                                   — server discovery
  - `GET  /taxii2/{api-root}/`                        — API root metadata
  - `GET  /taxii2/{api-root}/collections/`            — collection list
  - `GET  /taxii2/{api-root}/collections/{id}/`       — collection metadata
  - `GET  /taxii2/{api-root}/collections/{id}/objects/` — STIX bundle

Auth uses the same Bearer JWT as the rest of the dashboard API. The default
collection `honeystrike-high-severity` serves sessions scoring >= 60 from
the last 7 days. The defaults can be tightened/loosened via query params.

Content-Types follow the TAXII spec:
  - `application/taxii+json;version=2.1` on discovery/collection metadata
  - `application/stix+json;version=2.1`  on the `objects/` payload
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from honeystrike.api.auth import current_user, get_db
from honeystrike.api.stix import build_bundle
from honeystrike.core.models import User

router = APIRouter(prefix="/taxii2", tags=["taxii"])

API_ROOT = "v1"
COLLECTION_ID = "honeystrike-high-severity"
TAXII_CONTENT = "application/taxii+json;version=2.1"
STIX_CONTENT = "application/stix+json;version=2.1"


def _server_discovery() -> dict:
    return {
        "title": "HoneyStrike TAXII server",
        "description": "Read-only TAXII 2.1 endpoint serving HoneyStrike threat intel.",
        "contact": "operator@example.invalid",
        "default": f"/taxii2/{API_ROOT}/",
        "api_roots": [f"/taxii2/{API_ROOT}/"],
    }


def _api_root_metadata() -> dict:
    return {
        "title": "HoneyStrike v1",
        "description": "Default API root.",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10_485_760,
    }


def _collection_metadata() -> dict:
    return {
        "id": COLLECTION_ID,
        "title": "High-severity sessions",
        "description": (
            "Sessions scoring >= 60 in the last 7 days. Override via "
            "`days` and `min_score` query params on /objects/."
        ),
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_CONTENT],
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
async def discovery(                                       # pragma: no cover
    _user: Annotated[User, Depends(current_user)],
) -> Response:
    import json
    return Response(content=json.dumps(_server_discovery()), media_type=TAXII_CONTENT)


@router.get("/{api_root}/")
async def api_root(                                        # pragma: no cover
    api_root: str,
    _user: Annotated[User, Depends(current_user)],
) -> Response:
    if api_root != API_ROOT:
        raise HTTPException(status_code=404, detail="unknown api-root")
    import json
    return Response(content=json.dumps(_api_root_metadata()), media_type=TAXII_CONTENT)


@router.get("/{api_root}/collections/")
async def collections(                                     # pragma: no cover
    api_root: str,
    _user: Annotated[User, Depends(current_user)],
) -> Response:
    if api_root != API_ROOT:
        raise HTTPException(status_code=404, detail="unknown api-root")
    import json
    body = {"collections": [_collection_metadata()]}
    return Response(content=json.dumps(body), media_type=TAXII_CONTENT)


@router.get("/{api_root}/collections/{collection_id}/")
async def collection_meta(                                 # pragma: no cover
    api_root: str,
    collection_id: str,
    _user: Annotated[User, Depends(current_user)],
) -> Response:
    if api_root != API_ROOT or collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")
    import json
    return Response(content=json.dumps(_collection_metadata()), media_type=TAXII_CONTENT)


@router.get("/{api_root}/collections/{collection_id}/objects/")
async def collection_objects(                              # pragma: no cover
    api_root: str,
    collection_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(current_user)],
    days: int = Query(7, ge=1, le=90),
    min_score: int = Query(60, ge=0, le=100),
    limit: int = Query(500, ge=1, le=5000),
) -> Response:
    if api_root != API_ROOT or collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")
    bundle = await build_bundle(db, days=days, min_score=min_score, limit=limit)
    return Response(content=bundle.serialize(), media_type=STIX_CONTENT)
