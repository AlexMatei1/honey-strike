"""Unit tests for the WebSocket helpers — auth + cursor pagination shape."""

from __future__ import annotations

import pytest

from honeystrike.api.auth import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    issue_token,
)
from honeystrike.api.ws import _authenticate


@pytest.mark.asyncio
async def test_authenticate_returns_subject_for_valid_access_token() -> None:
    tok = issue_token(subject="admin", token_type=ACCESS_TOKEN_TYPE, ttl_seconds=60)
    assert await _authenticate(tok) == "admin"


@pytest.mark.asyncio
async def test_authenticate_rejects_refresh_token() -> None:
    tok = issue_token(subject="admin", token_type=REFRESH_TOKEN_TYPE, ttl_seconds=60)
    # A refresh token must not authenticate the WS — that path is for /api/auth/refresh.
    assert await _authenticate(tok) is None


@pytest.mark.asyncio
async def test_authenticate_rejects_missing_token() -> None:
    assert await _authenticate(None) is None
    assert await _authenticate("") is None


@pytest.mark.asyncio
async def test_authenticate_rejects_expired_token() -> None:
    tok = issue_token(subject="admin", token_type=ACCESS_TOKEN_TYPE, ttl_seconds=-5)
    assert await _authenticate(tok) is None


@pytest.mark.asyncio
async def test_authenticate_rejects_tampered_token() -> None:
    tok = issue_token(subject="admin", token_type=ACCESS_TOKEN_TYPE, ttl_seconds=60)
    # Flip a character in the *middle* of the signature. The very last base64
    # char only encodes 4 useful bits — flipping the other 2 "don't-care" bits
    # decodes to the same bytestring and the HMAC still verifies.
    sig_start = tok.rindex(".") + 1
    mid = sig_start + (len(tok) - sig_start) // 2
    tampered = tok[:mid] + ("A" if tok[mid] != "A" else "B") + tok[mid + 1:]
    assert await _authenticate(tampered) is None
