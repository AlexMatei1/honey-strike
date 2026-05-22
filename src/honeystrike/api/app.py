"""FastAPI app factory — wires up routers, CORS, and structlog access logs."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from honeystrike.api import auth, stix, taxii, ws
from honeystrike.api.routers import (
    admin, defender, duels, health, lessons, play, profile, progress, replay,
    sessions, stats,
)
from honeystrike.config import get_settings
from honeystrike.core.logging import configure_logging, get_logger

log = get_logger("honeystrike.api")

_ROOT = Path(__file__).resolve().parent
_STATIC_DIR = _ROOT / "static"
_TEMPLATE_DIR = _ROOT / "templates"


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.app_env == "production")

    app = FastAPI(
        title="HoneyStrike API",
        version="0.1.0",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )

    # In dev we let the dashboard host poke the API from anywhere; in prod the
    # operator sits a reverse proxy in front so same-origin is the norm. The
    # explicit empty list disables CORS in production unless the operator
    # supplies a domain.
    allowed_origins = ["*"] if settings.app_env != "production" else []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def _access_log(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        log.info(
            "api.request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=elapsed_ms,
            client=request.client.host if request.client else None,
        )
        return response

    app.include_router(auth.router)
    app.include_router(sessions.router)
    app.include_router(stats.router)
    app.include_router(health.router)
    app.include_router(ws.router)
    app.include_router(stix.router)
    app.include_router(taxii.router)
    app.include_router(defender.router)
    app.include_router(play.router)
    app.include_router(replay.router)
    app.include_router(lessons.router)
    app.include_router(profile.router)
    app.include_router(progress.router)
    app.include_router(admin.router)
    app.include_router(duels.router)

    # ---- Dashboard UI -----------------------------------------------------
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=_TEMPLATE_DIR) if _TEMPLATE_DIR.is_dir() else None

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_root(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1><p>UI templates not packaged.</p>")
        return templates.TemplateResponse(request, "dashboard.html", {})

    @app.get("/sessions/{session_id}", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_session(request: Request, session_id: str) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1><p>UI templates not packaged.</p>")
        return templates.TemplateResponse(
            request, "session_detail.html", {"session_id": session_id}
        )

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_login(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1><p>UI templates not packaged.</p>")
        return templates.TemplateResponse(request, "login.html", {})

    @app.get("/reset", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_reset(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "reset.html", {})

    @app.get("/verify", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_verify(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "verify.html", {})

    @app.get("/sessions", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_sessions(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1><p>UI templates not packaged.</p>")
        return templates.TemplateResponse(request, "sessions.html", {})

    @app.get("/analytics", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_analytics(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1><p>UI templates not packaged.</p>")
        return templates.TemplateResponse(request, "analytics.html", {})

    # Phase 6 — `/play` game pages + replay theater + war room.
    @app.get("/play", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "play_landing.html", {})

    @app.get("/play/attack", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play_attack(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "play_attack.html", {})

    @app.get("/play/defend", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play_defend(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "play_defend.html", {})

    @app.get("/play/defend/arena", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play_defend_arena(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "play_defend_arena.html", {})

    @app.get("/play/duel", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play_duel(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "duel.html", {})

    @app.get("/play/attack/{lesson_id}", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play_attack_lesson(request: Request, lesson_id: str) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(
            request, "lesson.html",
            {"family": "attack", "lesson_id": lesson_id},
        )

    @app.get("/play/defend/{lesson_id}", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_play_defend_lesson(request: Request, lesson_id: str) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        # Reserve /play/defend/arena (handled above) — anything else is a lesson id.
        if lesson_id == "arena":
            return templates.TemplateResponse(request, "play_defend_arena.html", {})
        return templates.TemplateResponse(
            request, "lesson.html",
            {"family": "defend", "lesson_id": lesson_id},
        )

    @app.get("/sessions/{session_id}/replay",
             response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_replay(request: Request, session_id: str) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(
            request, "replay.html", {"session_id": session_id},
        )

    @app.get("/profile", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_profile(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "profile.html", {})

    @app.get("/admin/users", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_admin_users(request: Request) -> HTMLResponse:
        # The page is rendered for everyone, but admin.js + the API enforce
        # admin-only access (members see an access-denied notice).
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "admin_users.html", {})

    @app.get("/warroom", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_warroom(request: Request) -> HTMLResponse:
        if templates is None:
            return HTMLResponse("<h1>HoneyStrike</h1>")
        return templates.TemplateResponse(request, "warroom.html", {})

    return app
