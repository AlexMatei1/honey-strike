"""`honeystrike register|players|challenge` — multiplayer top-level commands.

Lives outside the `attack` / `defend` subapps because they're lobby-scoped
rather than per-role. `lobby_commands.attach(app)` wires them onto the root.
"""

from __future__ import annotations

import typer

# Each command is implemented as a top-level function; we group them here so
# the root CLI can install them with a single call.
from honeystrike.cli.lobby import register as _register
from honeystrike.cli.lobby import players as _players
from honeystrike.cli.lobby import challenge as _challenge


def attach(app: typer.Typer) -> None:
    """Install the multiplayer commands directly onto the root typer app."""
    from honeystrike.cli import login as _login

    app.command("login", help="Authenticate against the dashboard API.")(_login.login_cmd)
    app.command("register", help="Register with the lobby (multiplayer).")(_register.register_cmd)
    app.command("players", help="List online lobby players.")(_players.players_cmd)
    app.command("challenge", help="Challenge a friend to a match.")(_challenge.challenge_cmd)


__all__ = ["attach"]
