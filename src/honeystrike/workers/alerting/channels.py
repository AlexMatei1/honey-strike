"""Alert dispatch channels.

Each channel implements the `Channel` protocol — a small async `send()` that
takes a pre-formatted `AlertMessage` and pushes it through a transport. The
worker calls every enabled channel and persists one `alerts` row per channel
that succeeded.

Failure mode is fail-open: a misconfigured or unreachable transport is logged
but never crashes the worker, and other channels still get a chance to fire.
"""

from __future__ import annotations

import asyncio
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol

import httpx

from honeystrike.core.logging import get_logger

log = get_logger(__name__)


@dataclass(slots=True, frozen=True)
class AlertMessage:
    """Pre-formatted alert payload. Channels render this as they see fit."""

    session_id: str
    src_ip: str
    service: str
    severity: str
    threat_score: int
    country_iso: str | None
    tool_signatures: list[str]
    ttp_techniques: list[str]
    subject: str
    body: str


class Channel(Protocol):
    """Async transport contract. `name` must match an alerts.channel value."""

    name: str

    async def send(self, msg: AlertMessage) -> None: ...


# ---------------------------------------------------------------------------
# Log channel — always available, useful in dev/CI where no real transport
# is configured. The worker still writes the `alerts` row, so e2e tests can
# assert dispatch happened without standing up an SMTP server.
# ---------------------------------------------------------------------------

class LogChannel:
    name = "log"

    async def send(self, msg: AlertMessage) -> None:
        log.info(
            "alert.dispatched",
            channel=self.name,
            session_id=msg.session_id,
            src_ip=msg.src_ip,
            severity=msg.severity,
            threat_score=msg.threat_score,
            subject=msg.subject,
        )


# ---------------------------------------------------------------------------
# Telegram channel
# ---------------------------------------------------------------------------

class TelegramChannel:
    name = "telegram"

    def __init__(self, *, token: str, chat_id: str, client: httpx.AsyncClient | None = None) -> None:
        self._token = token
        self._chat_id = chat_id
        self._client = client or httpx.AsyncClient(timeout=10)
        self._owns_client = client is None

    async def send(self, msg: AlertMessage) -> None:
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": f"*{msg.subject}*\n\n{msg.body}",
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        r = await self._client.post(url, json=payload)
        r.raise_for_status()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


# ---------------------------------------------------------------------------
# Slack channel — incoming webhook URL.
# ---------------------------------------------------------------------------

class SlackChannel:
    name = "slack"

    def __init__(self, *, webhook_url: str, client: httpx.AsyncClient | None = None) -> None:
        self._webhook = webhook_url
        self._client = client or httpx.AsyncClient(timeout=10)
        self._owns_client = client is None

    async def send(self, msg: AlertMessage) -> None:
        text = f"*{msg.subject}*\n```\n{msg.body}\n```"
        r = await self._client.post(self._webhook, json={"text": text})
        r.raise_for_status()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


# ---------------------------------------------------------------------------
# Discord channel — incoming webhook URL. Phase 6.
# ---------------------------------------------------------------------------

class DiscordChannel:
    name = "discord"

    _SEVERITY_COLOR = {
        "low":      0x5fb878,
        "medium":   0xd29922,
        "high":     0xf0883e,
        "critical": 0xf85149,
    }

    def __init__(self, *, webhook_url: str, client: httpx.AsyncClient | None = None) -> None:
        self._webhook = webhook_url
        self._client = client or httpx.AsyncClient(timeout=10)
        self._owns_client = client is None

    async def send(self, msg: AlertMessage) -> None:
        # Discord webhooks accept rich `embeds`. Use a colour-graded embed
        # so the alert reads at a glance.
        embed = {
            "title": msg.subject,
            "description": "```\n" + msg.body + "\n```",
            "color": self._SEVERITY_COLOR.get(msg.severity, 0x8b949e),
            "fields": [
                {"name": "service", "value": msg.service, "inline": True},
                {"name": "src_ip", "value": msg.src_ip, "inline": True},
                {"name": "score", "value": f"{msg.threat_score}/100", "inline": True},
            ],
        }
        r = await self._client.post(self._webhook, json={"embeds": [embed]})
        r.raise_for_status()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


# ---------------------------------------------------------------------------
# Email (SMTP) channel — runs the blocking smtplib call on a worker thread
# so the asyncio loop is never blocked.
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class SMTPConfig:
    host: str
    port: int
    username: str
    password: str
    from_addr: str
    to_addr: str


class EmailChannel:
    name = "email"

    def __init__(self, cfg: SMTPConfig) -> None:
        self._cfg = cfg

    def _send_sync(self, msg: AlertMessage) -> None:
        em = EmailMessage()
        em["Subject"] = msg.subject
        em["From"] = self._cfg.from_addr
        em["To"] = self._cfg.to_addr
        em.set_content(msg.body)
        with smtplib.SMTP(self._cfg.host, self._cfg.port, timeout=15) as smtp:
            smtp.starttls()
            if self._cfg.username:
                smtp.login(self._cfg.username, self._cfg.password)
            smtp.send_message(em)

    async def send(self, msg: AlertMessage) -> None:
        await asyncio.to_thread(self._send_sync, msg)


# ---------------------------------------------------------------------------
# Factory — build the channel list from the runtime config. Channels with
# missing creds are silently skipped; the LogChannel is always wired so
# something records the alert even when nothing else is configured.
# ---------------------------------------------------------------------------

def build_channels_from_settings(settings) -> list[Channel]:  # type: ignore[no-untyped-def]
    """Construct the channel list. Always returns at least LogChannel."""
    channels: list[Channel] = [LogChannel()]

    if settings.telegram_token and settings.telegram_chat_id:
        channels.append(
            TelegramChannel(
                token=settings.telegram_token,
                chat_id=settings.telegram_chat_id,
            )
        )

    if settings.slack_webhook_url:
        channels.append(SlackChannel(webhook_url=settings.slack_webhook_url))

    if getattr(settings, "discord_webhook_url", None):
        channels.append(DiscordChannel(webhook_url=settings.discord_webhook_url))

    if settings.smtp_host and settings.smtp_to:
        channels.append(
            EmailChannel(
                SMTPConfig(
                    host=settings.smtp_host,
                    port=settings.smtp_port,
                    username=settings.smtp_username,
                    password=settings.smtp_password,
                    from_addr=settings.smtp_from,
                    to_addr=settings.smtp_to,
                )
            )
        )

    return channels


def format_alert(
    *,
    session_id: str,
    src_ip: str,
    service: str,
    severity: str,
    threat_score: int,
    country_iso: str | None,
    tool_signatures: list[str],
    ttp_techniques: list[str],
) -> AlertMessage:
    """Build the shared subject + body used by every channel."""
    flag = country_iso or "??"
    subject = f"[HoneyStrike] {severity.upper()} {service} attack from {src_ip} ({flag}) — score {threat_score}"
    body_lines = [
        f"Session:        {session_id}",
        f"Source IP:      {src_ip}",
        f"Country:        {country_iso or 'unknown'}",
        f"Service:        {service}",
        f"Severity:       {severity}",
        f"Threat score:   {threat_score}/100",
    ]
    if tool_signatures:
        body_lines.append(f"Tools:          {', '.join(tool_signatures)}")
    if ttp_techniques:
        body_lines.append(f"MITRE TTPs:     {', '.join(ttp_techniques)}")
    return AlertMessage(
        session_id=session_id,
        src_ip=src_ip,
        service=service,
        severity=severity,
        threat_score=threat_score,
        country_iso=country_iso,
        tool_signatures=tool_signatures,
        ttp_techniques=ttp_techniques,
        subject=subject,
        body="\n".join(body_lines),
    )
