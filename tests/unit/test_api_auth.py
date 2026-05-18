"""Tests for the JWT + password helpers in the dashboard API.

The full request-cycle (login route, dependency injection) is exercised in
tests/integration. Here we keep things hermetic and just verify the algebra.
"""

from __future__ import annotations

import time

import jwt
import pytest
from fastapi import HTTPException

from honeystrike.api.auth import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    decode_token,
    hash_password,
    issue_token,
    verify_password,
)
from honeystrike.config import get_settings


def test_password_roundtrip_verifies_match() -> None:
    h = hash_password("hunter2")
    assert verify_password("hunter2", h) is True


def test_password_verify_rejects_wrong_password() -> None:
    h = hash_password("hunter2")
    assert verify_password("hunter3", h) is False


def test_password_hashes_differ_each_time() -> None:
    a = hash_password("same")
    b = hash_password("same")
    # argon2 generates a random salt per hash.
    assert a != b


def test_issue_then_decode_roundtrips_subject_and_type() -> None:
    tok = issue_token(subject="admin", token_type=ACCESS_TOKEN_TYPE, ttl_seconds=60)
    payload = decode_token(tok, expected_type=ACCESS_TOKEN_TYPE)
    assert payload["sub"] == "admin"
    assert payload["type"] == ACCESS_TOKEN_TYPE


def test_decode_rejects_wrong_token_type() -> None:
    tok = issue_token(subject="admin", token_type=REFRESH_TOKEN_TYPE, ttl_seconds=60)
    with pytest.raises(HTTPException) as exc_info:
        decode_token(tok, expected_type=ACCESS_TOKEN_TYPE)
    assert exc_info.value.status_code == 401
    assert "token type" in exc_info.value.detail


def test_decode_rejects_tampered_signature() -> None:
    tok = issue_token(subject="admin", token_type=ACCESS_TOKEN_TYPE, ttl_seconds=60)
    # Flip a character in the *middle* of the signature. The trailing base64
    # char only encodes a few useful bits — flipping the "don't-care" bits can
    # decode to the same bytestring and leave the HMAC valid.
    sig_start = tok.rindex(".") + 1
    mid = sig_start + (len(tok) - sig_start) // 2
    tampered = tok[:mid] + ("A" if tok[mid] != "A" else "B") + tok[mid + 1:]
    with pytest.raises(HTTPException) as exc_info:
        decode_token(tampered)
    assert exc_info.value.status_code == 401


def test_decode_rejects_token_signed_with_different_secret() -> None:
    settings = get_settings()
    bad = jwt.encode(
        {"sub": "evil", "type": ACCESS_TOKEN_TYPE, "exp": int(time.time()) + 60},
        f"not-{settings.secret_key}",
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc_info:
        decode_token(bad)
    assert exc_info.value.status_code == 401


def test_decode_rejects_expired_token() -> None:
    tok = issue_token(subject="admin", token_type=ACCESS_TOKEN_TYPE, ttl_seconds=-5)
    with pytest.raises(HTTPException) as exc_info:
        decode_token(tok)
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail
