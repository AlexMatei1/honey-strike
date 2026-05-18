"""FastAPI honeypot — fake admin panels with full request capture.

Routing strategy:

  - `/wp-login.php`, `/wp-admin/...`     → WordPress login page
  - `/phpmyadmin/...`, `/pma/...`        → phpMyAdmin login page
  - `/admin`, `/administrator`           → generic admin panel
  - any other path                        → realistic 404 (nginx-styled)

Every request — including the 404s and POST bodies up to 64 KB — is captured
by middleware before any handler runs. The middleware:

  1. Creates a `sessions` row on first contact (one per TCP connection's
     worth of activity isn't viable under keep-alive; we instead create one
     session row per HTTP request, which matches the doc 02 contract where
     `session.id` identifies a request not a TCP connection).
  2. Persists an HTTP_REQUEST event to PG + Redis.
  3. Closes the session immediately after (response sent).

We never echo attacker input back into the HTML — Jinja autoescaping is
not enough on its own; we just don't reflect input at all in v1.0.
"""

from __future__ import annotations

import time
from urllib.parse import unquote_plus

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from honeystrike.core import blocklist
from honeystrike.core.db import session_scope
from honeystrike.core.event_bus import EventBus
from honeystrike.core.events import EventType, Service
from honeystrike.core.logging import get_logger
from honeystrike.core.session_manager import SessionManager
from honeystrike.services.http import templates
from honeystrike.services.http.detectors import (
    cve_signature,
    path_traversal_found,
    scanner_signature,
    sqli_pattern_found,
    xss_pattern_found,
)

log = get_logger("honeystrike.services.http")

# Caps mirror docs/08 §3 — HTTP body 64 KB, headers always small enough not to cap.
_BODY_CAP_BYTES = 64 * 1024
_HEADER_VALUE_CAP = 4 * 1024


def _truncate_headers(items: list[tuple[str, str]]) -> dict[str, str]:
    """Flatten a header iterable to a dict, truncating oversized values."""
    out: dict[str, str] = {}
    for k, v in items:
        out[k] = v[:_HEADER_VALUE_CAP] if v else v
    return out


class CaptureMiddleware(BaseHTTPMiddleware):
    """Capture every request → PG + Redis. Always runs before the route handler."""

    def __init__(self, app: ASGIApp, *, bus: EventBus, local_port: int) -> None:
        super().__init__(app)
        self._bus = bus
        self._local_port = local_port

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        start = time.monotonic()
        client = request.client
        src_ip = client.host if client else "0.0.0.0"  # noqa: S104 — fallback only
        src_port = client.port if client else 0

        # Phase 6 blocking — refuse if the defender labelled this attacker's
        # IP correctly within the active match window.
        if await blocklist.is_blocked(self._bus.client, src_ip):
            return Response(status_code=403, content="forbidden",
                            media_type="text/plain")

        # Drain the body *once* and stash it so the route handler still sees it.
        raw_body = await request.body()
        body_bytes = len(raw_body)
        body_truncated = raw_body[:_BODY_CAP_BYTES]
        body_text = body_truncated.decode("utf-8", errors="replace")

        headers = _truncate_headers(list(request.headers.items()))
        # URL-decode for detector matching (raw `?x=a+OR+1%3D1` → `a OR 1=1`),
        # but preserve the encoded form on the event payload for forensics.
        raw_path = str(request.url.path)
        raw_query = str(request.url.query)
        full_target = raw_path + (f"?{raw_query}" if raw_query else "")
        decoded_target = unquote_plus(full_target)
        decoded_body = unquote_plus(body_text)
        scanner = scanner_signature(headers)
        cve = cve_signature(decoded_target, decoded_body)

        payload = {
            "method": request.method,
            "uri": full_target,                                    # raw on the wire
            "uri_decoded": decoded_target,                          # decoded for analytics
            "http_version": request.scope.get("http_version", "1.1"),
            "headers": headers,
            "body_truncated": body_text,
            "body_bytes": body_bytes,
            "body_was_truncated": body_bytes > _BODY_CAP_BYTES,
            "scanner_detected": scanner.name if scanner else None,
            "scanner_confidence": scanner.confidence if scanner else None,
            "sqli_pattern": sqli_pattern_found(
                decoded_target + " " + decoded_body
            ),
            "path_traversal": path_traversal_found(decoded_target),
            "xss_pattern": xss_pattern_found(decoded_body),
            "cve_signature": cve,
        }

        # ---- persist + emit -------------------------------------------------
        async with session_scope() as db:
            mgr = SessionManager(db, self._bus)
            session_id = await mgr.open(
                service=Service.HTTP,
                src_ip=src_ip,
                src_port=src_port,
                local_port=self._local_port,
            )
            await mgr.record_event(
                session_id=session_id,
                event_type=EventType.HTTP_REQUEST,
                service=Service.HTTP,
                src_ip=src_ip,
                src_port=src_port,
                payload=payload,
            )

        # Hand the request to the route handler; Starlette already consumed
        # the body when we awaited request.body(), so re-attach it for any
        # handler that wants to read it (we don't, but be correct).
        request._body = raw_body  # noqa: SLF001 — required to replay the body
        response = await call_next(request)

        # Close the session row with a synthetic duration based on this request.
        async with session_scope() as db:
            mgr = SessionManager(db, self._bus)
            await mgr.close(
                session_id=session_id,
                service=Service.HTTP,
                src_ip=src_ip,
                src_port=src_port,
                event_count=1,
                duration_ms=int((time.monotonic() - start) * 1000),
                close_reason="response_sent",
            )

        log.info(
            "http.request.captured",
            src_ip=src_ip,
            method=request.method,
            uri=payload["uri"],
            scanner=payload["scanner_detected"],
            cve=payload["cve_signature"],
        )
        return response


# ---------------------------------------------------------------------------
# Route handlers — pure HTML, no attacker echo.
# ---------------------------------------------------------------------------

def create_app(*, bus: EventBus, local_port: int) -> FastAPI:
    app = FastAPI(
        title="honeystrike-http-honeypot",
        docs_url=None,                # hide /docs
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(CaptureMiddleware, bus=bus, local_port=local_port)

    # ---- WordPress decoy -------------------------------------------------
    @app.get("/wp-login.php", response_class=HTMLResponse)
    @app.get("/wp-admin/", response_class=HTMLResponse)
    @app.get("/wp-admin/{rest:path}", response_class=HTMLResponse)
    async def wp_login_get(rest: str = "") -> HTMLResponse:  # noqa: ARG001
        return HTMLResponse(templates.WP_LOGIN)

    @app.post("/wp-login.php", response_class=HTMLResponse)
    async def wp_login_post() -> HTMLResponse:
        # Real WP returns the same login page with no error on a bad cred.
        return HTMLResponse(templates.WP_LOGIN)

    @app.get("/xmlrpc.php")
    async def xmlrpc_get() -> Response:
        return Response(
            "XML-RPC server accepts POST requests only.",
            status_code=405,
            headers={"Allow": "POST"},
        )

    # ---- phpMyAdmin decoy -----------------------------------------------
    @app.get("/phpmyadmin/", response_class=HTMLResponse)
    @app.get("/phpmyadmin/{rest:path}", response_class=HTMLResponse)
    @app.get("/pma/", response_class=HTMLResponse)
    @app.get("/pma/{rest:path}", response_class=HTMLResponse)
    @app.get("/phpMyAdmin/", response_class=HTMLResponse)
    async def phpmyadmin(rest: str = "") -> HTMLResponse:  # noqa: ARG001
        return HTMLResponse(templates.PHPMYADMIN)

    @app.post("/phpmyadmin/index.php", response_class=HTMLResponse)
    async def phpmyadmin_post() -> HTMLResponse:
        return HTMLResponse(templates.PHPMYADMIN)

    # ---- generic admin --------------------------------------------------
    @app.get("/admin", response_class=HTMLResponse)
    @app.get("/administrator", response_class=HTMLResponse)
    @app.get("/login", response_class=HTMLResponse)
    async def generic_admin() -> HTMLResponse:
        # Phase 6: serve the canary-bearing variant so `defend flags-found`
        # picks up attackers who grab the admin login page source.
        return HTMLResponse(templates.GENERIC_ADMIN_WITH_CANARY)

    @app.post("/admin", response_class=HTMLResponse)
    @app.post("/login", response_class=HTMLResponse)
    async def generic_admin_post() -> HTMLResponse:
        return HTMLResponse(templates.GENERIC_ADMIN_WITH_CANARY)

    # ---- Phase 6 canary fixtures ---------------------------------------
    @app.get("/.env", response_class=HTMLResponse)
    async def fake_env() -> Response:
        return Response(content=templates.FAKE_ENV_FILE, media_type="text/plain")

    @app.get("/.git/HEAD", response_class=HTMLResponse)
    async def fake_git_head() -> Response:
        return Response(content=templates.FAKE_GIT_HEAD, media_type="text/plain")

    # ---- catch-all 404 --------------------------------------------------
    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        response_class=HTMLResponse,
    )
    async def fallback(full_path: str) -> HTMLResponse:  # noqa: ARG001
        return HTMLResponse(templates.GENERIC_404, status_code=404)

    # Always present a server header that matches an old nginx — adds realism.
    @app.middleware("http")
    async def add_server_header(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["Server"] = "nginx/1.18.0 (Ubuntu)"
        return response

    return app
