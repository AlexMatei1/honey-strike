"""Unit tests for the password-reset token (pure token logic, no DB)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from honeystrike.api import auth


def test_reset_token_roundtrips_as_reset_type():
    tok = auth.issue_reset_token("alice")
    claims = auth.decode_token(tok, expected_type=auth.RESET_TOKEN_TYPE)
    assert claims["sub"] == "alice"
    assert claims["type"] == auth.RESET_TOKEN_TYPE


def test_reset_token_is_not_an_access_token():
    # A reset token must not be usable to authenticate API calls.
    tok = auth.issue_reset_token("alice")
    with pytest.raises(HTTPException) as exc:
        auth.decode_token(tok, expected_type=auth.ACCESS_TOKEN_TYPE)
    assert exc.value.status_code == 401


def test_access_token_is_not_a_reset_token():
    tok = auth.issue_token(subject="alice", token_type=auth.ACCESS_TOKEN_TYPE, ttl_seconds=60)
    with pytest.raises(HTTPException):
        auth.decode_token(tok, expected_type=auth.RESET_TOKEN_TYPE)
