"""Unit tests for the registration validation + rate limiter (pure pieces).

The full HTTP register→login flow is covered by the live integration test;
here we lock the username/password rules and the in-process sign-up limiter.
"""

from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from honeystrike.api import auth


@pytest.fixture(autouse=True)
def _reset_limiter():
    auth._register_times.clear()
    yield
    auth._register_times.clear()


# ---- validation ----------------------------------------------------------

@pytest.mark.parametrize("username", ["ab", "", "1", "x" * 33, "-bad", ".bad", "has space", "bad/slash"])
def test_rejects_bad_usernames(username):
    assert auth.validate_registration(username, "longenough1") is not None


@pytest.mark.parametrize("username", ["abc", "Alice", "user_1", "a.b-c", "root", "x" * 32, "0day"])
def test_accepts_good_usernames(username):
    assert auth.validate_registration(username, "longenough1") is None


@pytest.mark.parametrize("password", ["", "short", "1234567"])
def test_rejects_short_passwords(password):
    assert auth.validate_registration("validuser", password) is not None


def test_rejects_overlong_password():
    assert auth.validate_registration("validuser", "x" * 129) is not None


def test_accepts_min_length_password():
    assert auth.validate_registration("validuser", "x" * 8) is None


# ---- rate limiter --------------------------------------------------------

def test_rate_limit_allows_up_to_max():
    for _ in range(auth._REGISTER_MAX_PER_WINDOW):
        auth._registration_rate_limit()      # must not raise
    assert len(auth._register_times) == auth._REGISTER_MAX_PER_WINDOW


def test_rate_limit_blocks_over_max():
    for _ in range(auth._REGISTER_MAX_PER_WINDOW):
        auth._registration_rate_limit()
    with pytest.raises(HTTPException) as exc:
        auth._registration_rate_limit()
    assert exc.value.status_code == 429
    assert "Retry-After" in exc.value.headers


def test_rate_limit_window_slides():
    old = time.time() - auth._REGISTER_WINDOW_SECONDS - 5
    auth._register_times.extend([old] * auth._REGISTER_MAX_PER_WINDOW)
    # All stale → pruned → the next sign-up is allowed.
    auth._registration_rate_limit()
    assert len(auth._register_times) == 1
