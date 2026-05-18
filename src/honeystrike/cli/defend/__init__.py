"""`honeystrike defend ...` — investigate, narrate, label, block."""

from __future__ import annotations

import typer

defend_app = typer.Typer(
    name="defend",
    help="Investigate captured sessions, narrate live attacks, label TTPs.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

from honeystrike.cli.defend import snapshot as _snapshot     # noqa: E402,F401
from honeystrike.cli.defend import tail as _tail             # noqa: E402,F401
from honeystrike.cli.defend import narrate as _narrate       # noqa: E402,F401
from honeystrike.cli.defend import flags as _flags           # noqa: E402,F401
from honeystrike.cli.defend import campaign_score as _cs     # noqa: E402,F401
from honeystrike.cli.defend import label as _label           # noqa: E402,F401
from honeystrike.cli.defend import listen as _listen         # noqa: E402,F401

__all__ = ["defend_app"]
