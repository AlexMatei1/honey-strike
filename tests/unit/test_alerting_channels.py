"""Tests for the alerting channels — formatter + factory + per-channel send."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from honeystrike.workers.alerting.channels import (
    AlertMessage,
    EmailChannel,
    LogChannel,
    SMTPConfig,
    SlackChannel,
    TelegramChannel,
    build_channels_from_settings,
    format_alert,
)


def _sample_msg(**overrides) -> AlertMessage:
    defaults = dict(
        session_id="ssn",
        src_ip="1.2.3.4",
        service="ssh",
        severity="critical",
        threat_score=88,
        country_iso="RU",
        tool_signatures=["Hydra"],
        ttp_techniques=["T1110.001"],
    )
    defaults.update(overrides)
    return format_alert(**defaults)


# ---------------------------------------------------------------------------
# format_alert
# ---------------------------------------------------------------------------

def test_format_alert_includes_score_and_severity_in_subject() -> None:
    msg = _sample_msg()
    assert "CRITICAL" in msg.subject
    assert "1.2.3.4" in msg.subject
    assert "88" in msg.subject


def test_format_alert_body_includes_tools_and_ttps() -> None:
    msg = _sample_msg(tool_signatures=["Hydra", "Masscan"], ttp_techniques=["T1078"])
    assert "Hydra" in msg.body
    assert "Masscan" in msg.body
    assert "T1078" in msg.body


def test_format_alert_handles_no_country() -> None:
    msg = _sample_msg(country_iso=None)
    assert "(??" in msg.subject
    assert "unknown" in msg.body


# ---------------------------------------------------------------------------
# LogChannel — always succeeds, no transport.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_log_channel_send_does_not_raise() -> None:
    await LogChannel().send(_sample_msg())


# ---------------------------------------------------------------------------
# TelegramChannel
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_telegram_channel_posts_expected_payload() -> None:
    client = MagicMock(spec=httpx.AsyncClient)
    response = MagicMock()
    response.raise_for_status = MagicMock(return_value=None)
    client.post = AsyncMock(return_value=response)

    chan = TelegramChannel(token="abc", chat_id="123", client=client)
    msg = _sample_msg()
    await chan.send(msg)

    args, kwargs = client.post.call_args
    assert args[0] == "https://api.telegram.org/botabc/sendMessage"
    body = kwargs["json"]
    assert body["chat_id"] == "123"
    assert msg.subject in body["text"]
    assert "Hydra" in body["text"]


# ---------------------------------------------------------------------------
# SlackChannel
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_slack_channel_posts_expected_payload() -> None:
    client = MagicMock(spec=httpx.AsyncClient)
    response = MagicMock()
    response.raise_for_status = MagicMock(return_value=None)
    client.post = AsyncMock(return_value=response)

    chan = SlackChannel(webhook_url="https://hooks.example/abc", client=client)
    msg = _sample_msg()
    await chan.send(msg)

    args, kwargs = client.post.call_args
    assert args[0] == "https://hooks.example/abc"
    assert msg.subject in kwargs["json"]["text"]


# ---------------------------------------------------------------------------
# EmailChannel — patch smtplib so the test doesn't actually open a connection.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_email_channel_uses_smtplib_with_starttls(monkeypatch) -> None:
    captured = {}

    class _FakeSMTP:
        def __init__(self, host, port, timeout=None) -> None:
            captured["host"] = host
            captured["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self) -> None:
            captured["starttls"] = True

        def login(self, u, p) -> None:
            captured["login"] = (u, p)

        def send_message(self, msg) -> None:
            captured["msg"] = msg

    import honeystrike.workers.alerting.channels as channels_module
    monkeypatch.setattr(channels_module.smtplib, "SMTP", _FakeSMTP)

    chan = EmailChannel(
        SMTPConfig(
            host="smtp.example", port=587,
            username="u", password="p",
            from_addr="from@example", to_addr="to@example",
        )
    )
    await chan.send(_sample_msg())

    assert captured["host"] == "smtp.example"
    assert captured["port"] == 587
    assert captured["starttls"] is True
    assert captured["login"] == ("u", "p")
    assert captured["msg"]["To"] == "to@example"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class _StubSettings:
    telegram_token = ""
    telegram_chat_id = ""
    smtp_host = ""
    smtp_to = ""
    smtp_port = 587
    smtp_username = ""
    smtp_password = ""
    smtp_from = "honeystrike@example.com"
    slack_webhook_url = ""


def test_factory_always_returns_log_channel() -> None:
    channels = build_channels_from_settings(_StubSettings())
    names = [c.name for c in channels]
    assert names == ["log"]


def test_factory_adds_only_configured_channels() -> None:
    s = _StubSettings()
    s.telegram_token = "tok"
    s.telegram_chat_id = "cid"
    s.slack_webhook_url = "https://example/wh"
    s.smtp_host = "smtp.example"
    s.smtp_to = "ops@example"
    channels = build_channels_from_settings(s)
    assert {c.name for c in channels} == {"log", "telegram", "slack", "email"}
