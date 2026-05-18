"""HoneyStrike unified CLI (`honeystrike` entry point).

Exposes a single Typer app that dispatches to the `attack`, `defend`, and
multiplayer (`register`, `players`, `challenge`) sub-applications. The
package layout deliberately keeps Typer bindings thin — every command
delegates to a pure async runner so the same code paths can be unit-tested
without typer in the loop.
"""

from __future__ import annotations

import typer

from honeystrike.cli.attack import attack_app
from honeystrike.cli.defend import defend_app
from honeystrike.cli import lobby as _lobby_pkg

app = typer.Typer(
    name="honeystrike",
    help=(
        "HoneyStrike — drive attacks, watch the defense, play matches.\n\n"
        "`honeystrike attack ...`  fire scripted attacks at a honeypot.\n"
        "`honeystrike defend ...`  read logs, narrate live, label TTPs, block.\n"
        "`honeystrike challenge`   challenge a friend to a multiplayer match."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)

app.add_typer(attack_app, name="attack", help="Run scripted attacks at a honeypot.")
app.add_typer(defend_app, name="defend", help="Investigate captured sessions, label, block.")

# Top-level multiplayer commands hang directly off `app` so they look like
# `honeystrike register` / `honeystrike challenge bob` (no extra subgroup).
_lobby_pkg.attach(app)


# Re-export for `python -m honeystrike.cli`.
__all__ = ["app"]
