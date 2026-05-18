"""`honeystrike login` — interactive login against the dashboard API."""

from __future__ import annotations

import os

import httpx
import typer

from honeystrike.cli import auth
from honeystrike.cli.http_client import run_async
from honeystrike.cli.output import error, info, success


async def _login(username: str, password: str, api_base: str) -> str:
    async with httpx.AsyncClient(base_url=api_base, timeout=30) as client:
        r = await client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
    if r.status_code != 200:
        raise SystemExit(f"login failed: HTTP {r.status_code} {r.text[:200]}")
    body = r.json()
    return body["access_token"]


def login_cmd(
    username: str | None = typer.Option(
        None, "--username", "-u",
        help="Account name. Falls back to $HONEYSTRIKE_USERNAME then prompts.",
    ),
    password: str | None = typer.Option(
        None, "--password", "-p",
        help="Password. Falls back to $HONEYSTRIKE_PASSWORD then prompts.",
        hide_input=True,
    ),
    api_base: str | None = typer.Option(
        None, "--api-base",
        help="Dashboard API base URL. Default http://127.0.0.1:8001.",
    ),
) -> None:
    """Authenticate against the dashboard API and cache the access token.

    Resolution order: --username/--password flags → env (HONEYSTRIKE_USERNAME /
    HONEYSTRIKE_PASSWORD) → interactive prompt.
    """
    user = username or os.environ.get("HONEYSTRIKE_USERNAME") or typer.prompt("Username")
    pw = password or os.environ.get("HONEYSTRIKE_PASSWORD") or typer.prompt(
        "Password", hide_input=True
    )
    base = api_base or auth.resolve_api_base()
    info(f"→ POST {base}/api/auth/login as {user!r}")
    try:
        token = run_async(_login(user, pw, base))
    except SystemExit as exc:
        error(str(exc))
        raise
    auth.save_token(token, api_base=base)
    success(f"Token cached at {auth.config_path()}.")
