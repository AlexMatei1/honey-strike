"""Token + config cache for the CLI.

`~/.honeystrike/config.toml` holds:

  [auth]
  token = "<jwt>"
  api_base = "http://127.0.0.1:8001"
  saved_at = "2026-05-18T10:00:00Z"

  [lobby]
  url = "https://lobby.example"
  handle = "alice"
  token = "<lobby-token>"
  current_match_id = null

  [public_endpoints]
  ssh = "alice.example:2222"
  http = "alice.example:18080"
  ...

  [discord]
  webhook = "https://discord.com/api/webhooks/..."

Resolution priority for the API access token:
  1. `--token` CLI flag (passed via context).
  2. `$HONEYSTRIKE_TOKEN` env var.
  3. Cached `auth.token` in config.toml.
  4. Interactive `honeystrike login` (or env `HONEYSTRIKE_USERNAME`/`PASSWORD`).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import tomli_w

try:                                                       # Python 3.11+
    import tomllib
except ImportError:                                        # pragma: no cover
    import tomli as tomllib                                 # type: ignore[no-redef]


_DEFAULT_API_BASE = "http://127.0.0.1:8001"


def config_dir() -> Path:
    """Where the CLI persists its state. Override with `HONEYSTRIKE_CONFIG_DIR`
    for testing or unusual home directories."""
    override = os.environ.get("HONEYSTRIKE_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".honeystrike"


def config_path() -> Path:
    return config_dir() / "config.toml"


def _ensure_dir() -> None:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    # Best-effort: tighten perms on POSIX. No-op on Windows.
    try:                                                   # pragma: no cover
        os.chmod(d, 0o700)
    except OSError:
        pass


def load_config() -> dict[str, Any]:
    p = config_path()
    if not p.is_file():
        return {}
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except Exception:                                      # noqa: BLE001
        return {}


def save_config(data: dict[str, Any]) -> None:
    _ensure_dir()
    p = config_path()
    with p.open("wb") as fh:
        tomli_w.dump(data, fh)
    try:                                                   # pragma: no cover
        os.chmod(p, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def cached_token() -> str | None:
    return load_config().get("auth", {}).get("token")


def cached_api_base() -> str:
    return load_config().get("auth", {}).get("api_base", _DEFAULT_API_BASE)


def save_token(token: str, api_base: str | None = None) -> None:
    cfg = load_config()
    cfg.setdefault("auth", {})
    cfg["auth"]["token"] = token
    cfg["auth"]["api_base"] = api_base or cfg["auth"].get("api_base", _DEFAULT_API_BASE)
    cfg["auth"]["saved_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    save_config(cfg)


def clear_token() -> None:
    cfg = load_config()
    if "auth" in cfg:
        cfg["auth"].pop("token", None)
    save_config(cfg)


def resolve_token(explicit: str | None = None) -> str | None:
    """Token in priority order. Returns None only if nothing is configured."""
    if explicit:
        return explicit
    env = os.environ.get("HONEYSTRIKE_TOKEN")
    if env:
        return env
    return cached_token()


def resolve_api_base(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("HONEYSTRIKE_API_BASE")
    if env:
        return env
    return cached_api_base()


# ---------------------------------------------------------------------------
# Lobby helpers — used by `honeystrike register` / `players` / `challenge`.
# Stored separately under [lobby] so re-running `register` doesn't trash the
# API auth token.
# ---------------------------------------------------------------------------

def lobby_section() -> dict[str, Any]:
    return load_config().get("lobby", {})


def save_lobby(*, url: str, handle: str, token: str) -> None:
    cfg = load_config()
    cfg.setdefault("lobby", {})
    cfg["lobby"].update({
        "url": url,
        "handle": handle,
        "token": token,
        "saved_at": datetime.now(UTC).isoformat(timespec="seconds"),
    })
    save_config(cfg)


def save_public_endpoints(endpoints: dict[str, str]) -> None:
    cfg = load_config()
    cfg["public_endpoints"] = {k: v for k, v in endpoints.items() if v}
    save_config(cfg)


def public_endpoints() -> dict[str, str]:
    return load_config().get("public_endpoints", {})


def save_discord_webhook(url: str | None) -> None:
    cfg = load_config()
    if url:
        cfg.setdefault("discord", {})["webhook"] = url
    else:
        cfg.pop("discord", None)
    save_config(cfg)


def discord_webhook() -> str | None:
    return load_config().get("discord", {}).get("webhook")


def set_current_match(match_id: str | None) -> None:
    cfg = load_config()
    cfg.setdefault("lobby", {})
    cfg["lobby"]["current_match_id"] = match_id
    save_config(cfg)


def current_match() -> str | None:
    return load_config().get("lobby", {}).get("current_match_id")
