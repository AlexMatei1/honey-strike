"""Unit tests for the report renderer — focuses on the Jinja layer and the
PDF roundtrip. WeasyPrint's heavy lifting is exercised here so the integration
suite can stay focused on the worker/API plumbing.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from honeystrike.workers.reports.renderer import (
    ReportContext,
    render_html,
    render_pdf,
    safe_filename,
)


def _weasyprint_available() -> bool:
    """WeasyPrint raises OSError (not ImportError) when its native libs
    (libpango / libcairo / libgdk-pixbuf) are missing, so pytest.importorskip
    can't catch it. The reports container ships these libs; a bare dev env
    may not — skip the PDF roundtrip there rather than hard-fail."""
    try:
        import weasyprint  # noqa: F401
    except Exception:
        return False
    return True


_WEASYPRINT = _weasyprint_available()


def _ctx(**overrides) -> ReportContext:
    base = ReportContext(
        session={
            "id": "11111111-1111-1111-1111-111111111111",
            "src_ip": "203.0.113.7",
            "service": "ssh",
            "state": "CLOSED",
            "threat_score": 82,
            "severity": "critical",
            "started_at": "2026-05-17T10:00:00+00:00",
            "ended_at": "2026-05-17T10:00:45+00:00",
            "duration_ms": 45_000,
            "event_count": 14,
        },
        fingerprint={
            "country_iso": "RU",
            "country_name": "Russia",
            "city": "Moscow",
            "asn": 12345,
            "org": "ScannerNet Ltd",
            "abuse_score": 88,
            "abuse_reports": 24,
            "tool_signatures": [
                {"name": "Hydra", "confidence": 0.92},
                {"name": "Masscan / port-scan", "confidence": 0.95},
            ],
            "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
            "timing_pattern": "burst",
            "attempt_rate_rpm": 312.4,
        },
        ttps=[
            {
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "tactic": "Credential Access",
                "confidence": 0.90,
            },
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Defense Evasion",
                "confidence": 0.90,
            },
        ],
        events=[
            {
                "timestamp": "2026-05-17T10:00:01+00:00",
                "event_type": "SSH_AUTH_ATTEMPT",
                "payload_repr": '{"username": "root", "password": "123456"}',
            }
        ],
        alerts=[
            {
                "channel": "log",
                "severity": "critical",
                "dispatched_at": "2026-05-17T10:00:46+00:00",
            }
        ],
        generated_at=datetime(2026, 5, 17, 10, 1, 0, tzinfo=UTC).isoformat(timespec="seconds"),
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def test_render_html_contains_core_session_fields() -> None:
    html = render_html(_ctx())
    assert "203.0.113.7" in html
    assert "Moscow" in html
    assert "Hydra" in html
    assert "T1110.001" in html
    assert "T1078" in html
    assert "82/100" in html
    assert "CRITICAL" in html


def test_render_html_handles_missing_fingerprint() -> None:
    html = render_html(_ctx(fingerprint=None))
    assert "203.0.113.7" in html
    # Tool-signatures section explicitly says "No tool signatures matched".
    assert "No tool signatures matched." in html


def test_render_html_escapes_attacker_payloads() -> None:
    payload = '<script>alert("xss")</script>'
    ctx = _ctx(
        events=[
            {
                "timestamp": "2026-05-17T10:00:01+00:00",
                "event_type": "HTTP_REQUEST",
                "payload_repr": payload,
            }
        ]
    )
    html = render_html(ctx)
    # The autoescape pass should convert the < and " characters.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _WEASYPRINT, reason="WeasyPrint native libs unavailable in this env")
def test_render_pdf_returns_valid_pdf_header() -> None:
    pdf_bytes = render_pdf(_ctx())
    # Every valid PDF file starts with `%PDF-` and ends with `%%EOF`.
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes[-1024:]
    # Modest sanity check on size — even a one-page report should be ≥1KB.
    assert len(pdf_bytes) >= 1024


# ---------------------------------------------------------------------------
# Filename helper
# ---------------------------------------------------------------------------

def test_safe_filename_is_predictable() -> None:
    assert safe_filename("11111111-1111-1111-1111-111111111111", "pdf") == \
        "session-11111111-1111-1111-1111-111111111111.pdf"
    assert safe_filename("abc", "html") == "session-abc.html"
