"""Render a per-session threat-intel report as HTML and PDF.

Two outputs share the same Jinja template:
  - `render_html(ctx)` → self-contained HTML page (collapsible sections, the
    same dark theme as the dashboard for a familiar look).
  - `render_pdf(ctx)` → bytes from WeasyPrint, using a print-friendly stylesheet.

The renderer is intentionally pure: callers fetch the session, fingerprint,
TTPs, events, and alerts; we just stamp the template. Keeps the unit tests
trivial and lets the API return previews without writing to disk.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
# Both templates render HTML (the PDF stage renders HTML first, then WeasyPrint
# turns it into PDF). The filenames end in `.j2`, which would defeat Jinja's
# default `select_autoescape(["html", "xml"])`. Force autoescape ON — every
# field the templates render contains attacker-controlled data.
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


@dataclass(slots=True)
class ReportContext:
    """All the data the template needs to render one report.

    Built by the ReportWorker from the session row, fingerprint row, TTP rows,
    a bounded event preview, and the alerts row list. None of these field
    types are SQLAlchemy ORM objects — we pass dicts so the renderer can be
    unit-tested without a DB.
    """

    session: dict[str, Any]
    fingerprint: dict[str, Any] | None
    ttps: list[dict[str, Any]]
    events: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    generated_at: datetime


def _common_kwargs(ctx: ReportContext) -> dict[str, Any]:
    return {
        "session": ctx.session,
        "fingerprint": ctx.fingerprint,
        "ttps": ctx.ttps,
        "events": ctx.events,
        "alerts": ctx.alerts,
        "generated_at": ctx.generated_at,
    }


def render_html(ctx: ReportContext) -> str:
    """Return a self-contained HTML report."""
    template = _env.get_template("report.html.j2")
    return template.render(_common_kwargs(ctx))


def render_pdf(ctx: ReportContext) -> bytes:
    """Return PDF bytes produced by WeasyPrint."""
    # Import inside the function so test environments without the system
    # libs can still load this module (e.g. importlib-time validation).
    from weasyprint import HTML

    template = _env.get_template("report.pdf.html.j2")
    html_str = template.render(_common_kwargs(ctx))
    return HTML(string=html_str).write_pdf()


def safe_filename(session_id: str | uuid.UUID, fmt: str) -> str:
    """Predictable on-disk name so retention sweeps + API downloads agree."""
    return f"session-{session_id}.{fmt}"
