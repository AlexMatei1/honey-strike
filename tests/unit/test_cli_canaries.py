"""Tests for the CTF canary library + detection."""

from __future__ import annotations

from honeystrike.cli.attack import canaries


def test_all_canaries_have_unique_slugs() -> None:
    slugs = [c.slug for c in canaries.ALL_CANARIES]
    assert len(slugs) == len(set(slugs))


def test_all_canaries_have_distinctive_needles() -> None:
    # Each needle must be unique + at least 10 characters so it's not a
    # plausible substring of real benign traffic.
    needles = [c.needle for c in canaries.ALL_CANARIES]
    assert len(needles) == len(set(needles))
    for n in needles:
        assert len(n) >= 10, f"needle too short: {n}"


def test_contains_canary_finds_each_needle() -> None:
    for c in canaries.ALL_CANARIES:
        text = f"prefix {c.needle} suffix"
        assert canaries.contains_canary(text) == c.slug


def test_contains_canary_handles_bytes() -> None:
    needle = canaries.FAKE_AWS_KEY.needle.encode()
    assert canaries.contains_canary(needle) == "aws-key"


def test_contains_canary_returns_none_for_benign_text() -> None:
    assert canaries.contains_canary("hello world, nothing here") is None


def test_aws_canary_has_trigger_uris_and_commands() -> None:
    assert "/.env" in canaries.FAKE_AWS_KEY.trigger_uris
    assert any("aws/credentials" in t for t in canaries.FAKE_AWS_KEY.trigger_commands)


def test_admin_canary_has_admin_uris() -> None:
    assert "/admin" in canaries.FAKE_ADMIN_TOKEN.trigger_uris


def test_passwd_canary_only_has_command_trigger() -> None:
    assert canaries.FAKE_PASSWD_LINE.trigger_uris == ()
    assert "cat /etc/passwd" in canaries.FAKE_PASSWD_LINE.trigger_commands
