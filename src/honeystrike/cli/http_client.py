"""Auth-aware httpx wrapper used by every defender/lobby command.

Centralises:
  - reading the token from auth.py
  - sending Bearer auth + the documented base URL
  - one-shot transparent re-login on 401 (env-creds only; never prompts mid-
    flight to keep automated runs deterministic)
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx

from honeystrike.cli import auth
from honeystrike.cli.output import error, warn


class CLIAuthError(RuntimeError):
    pass


async def _refresh_via_env(client: httpx.AsyncClient) -> str | None:
    """Re-login using HONEYSTRIKE_USERNAME / _PASSWORD env vars if present."""
    user = os.environ.get("HONEYSTRIKE_USERNAME")
    password = os.environ.get("HONEYSTRIKE_PASSWORD")
    if not (user and password):
        return None
    try:
        r = await client.post(
            "/api/auth/login",
            json={"username": user, "password": password},
        )
        if r.status_code == 200:
            tok = r.json()["access_token"]
            auth.save_token(tok)
            return tok
    except httpx.HTTPError:
        pass
    return None


@asynccontextmanager
async def api_client(
    *,
    token: str | None = None,
    api_base: str | None = None,
    timeout: float = 30.0,
) -> AsyncIterator[httpx.AsyncClient]:
    """Async context manager yielding an httpx client primed with auth."""
    base = auth.resolve_api_base(api_base)
    tok = auth.resolve_token(token)
    headers = {}
    if tok:
        headers["Authorization"] = f"Bearer {tok}"

    async with httpx.AsyncClient(
        base_url=base, headers=headers, timeout=timeout
    ) as client:
        yield client


async def api_get(path: str, **kwargs) -> httpx.Response:
    """GET with one transparent re-login attempt on 401."""
    async with api_client() as client:
        r = await client.get(path, **kwargs)
        if r.status_code == 401:
            fresh = await _refresh_via_env(client)
            if fresh:
                client.headers["Authorization"] = f"Bearer {fresh}"
                r = await client.get(path, **kwargs)
        return r


async def api_post(path: str, **kwargs) -> httpx.Response:
    async with api_client() as client:
        r = await client.post(path, **kwargs)
        if r.status_code == 401:
            fresh = await _refresh_via_env(client)
            if fresh:
                client.headers["Authorization"] = f"Bearer {fresh}"
                r = await client.post(path, **kwargs)
        return r


def require_token() -> str:
    """For commands that simply cannot run without auth — exits 1 with a hint."""
    tok = auth.resolve_token()
    if not tok:
        error("Not authenticated. Run `honeystrike login` first.")
        raise SystemExit(1)
    return tok


def run_async(coro):
    """Tiny shim used by typer commands to bridge into the asyncio runners.

    Centralised so unit tests can monkey-patch the executor.
    """
    return asyncio.run(coro)
