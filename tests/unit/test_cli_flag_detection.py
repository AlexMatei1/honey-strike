"""Tests for the event → canary detector used by `defend flags-found`."""

from __future__ import annotations

from honeystrike.cli.defend.flags import _canary_for_event


def test_http_request_to_env_matches_aws_key() -> None:
    slug = _canary_for_event(
        "HTTP_REQUEST",
        {"uri": "/.env", "uri_decoded": "/.env"},
    )
    assert slug == "aws-key"


def test_http_request_to_admin_matches_admin_token() -> None:
    slug = _canary_for_event(
        "HTTP_REQUEST",
        {"uri": "/admin", "uri_decoded": "/admin"},
    )
    assert slug == "admin-token"


def test_http_request_to_login_matches_admin_token() -> None:
    slug = _canary_for_event(
        "HTTP_REQUEST",
        {"uri_decoded": "/login?next=/home"},
    )
    assert slug == "admin-token"


def test_ssh_cat_etc_passwd_matches_passwd() -> None:
    slug = _canary_for_event(
        "SSH_COMMAND", {"raw": "cat /etc/passwd"},
    )
    assert slug == "passwd"


def test_ssh_cat_aws_creds_matches_aws_key() -> None:
    slug = _canary_for_event(
        "SSH_COMMAND", {"raw": "cat ~/.aws/credentials"},
    )
    assert slug == "aws-key"


def test_unrelated_event_returns_none() -> None:
    assert _canary_for_event("SSH_AUTH_ATTEMPT", {"username": "root"}) is None
    assert _canary_for_event("HTTP_REQUEST", {"uri_decoded": "/"}) is None
