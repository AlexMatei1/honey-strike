"""Tiny outbound-email helper with a graceful no-SMTP fallback.

If SMTP is configured (settings.smtp_host set), `send_email` delivers via
that server. If not — e.g. the public demo — it *logs* the message instead of
failing, so flows that "send an email" (password reset, verification) still
work end-to-end; an operator can read the link from the logs.

`smtp_configured()` lets callers branch their UX (e.g. "we emailed you" vs
"ask a SOC Lead").
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from honeystrike.config import get_settings
from honeystrike.core.logging import get_logger

log = get_logger("honeystrike.mailer")


def smtp_configured() -> bool:
    return bool(get_settings().smtp_host)


def _send_sync(host: str, port: int, user: str, pw: str, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=10) as s:
        s.ehlo()
        try:
            s.starttls()
            s.ehlo()
        except smtplib.SMTPException:
            pass            # server without STARTTLS — proceed plaintext
        if user:
            s.login(user, pw)
        s.send_message(msg)


async def send_email(*, to: str, subject: str, body: str) -> bool:
    """Send (or log) an email. Returns True if actually delivered via SMTP,
    False if it was logged because SMTP isn't configured. Never raises into
    the caller — a mail hiccup must not break the auth flow."""
    import asyncio

    settings = get_settings()
    if not settings.smtp_host:
        # No mail server — log the would-be email so the operator can act.
        log.info("mailer.no_smtp_logged", to=to, subject=subject, body=body)
        return False

    em = EmailMessage()
    em["From"] = settings.smtp_from
    em["To"] = to
    em["Subject"] = subject
    em.set_content(body)
    try:
        await asyncio.to_thread(
            _send_sync, settings.smtp_host, settings.smtp_port,
            settings.smtp_username, settings.smtp_password, em,
        )
        log.info("mailer.sent", to=to, subject=subject)
        return True
    except Exception as exc:        # noqa: BLE001 — best-effort
        log.warning("mailer.send_failed", to=to, subject=subject, error=str(exc))
        return False
