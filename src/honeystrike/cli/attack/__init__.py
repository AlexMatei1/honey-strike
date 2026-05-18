"""`honeystrike attack ...` — scripted attack scenarios + campaigns."""

from __future__ import annotations

import typer

attack_app = typer.Typer(
    name="attack",
    help="Run scripted attacks against a HoneyStrike honeypot.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Wire commands. Imports must come AFTER attack_app is created so the decorators
# in `scenarios` / `campaigns` can attach.
from honeystrike.cli.attack import scenarios as _scenarios   # noqa: E402,F401
from honeystrike.cli.attack import campaigns as _campaigns   # noqa: E402,F401

__all__ = ["attack_app"]
