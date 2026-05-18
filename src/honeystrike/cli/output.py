"""Shared rich output helpers — colours, tables, severity styling.

Every command imports `console` (a Rich console pointed at stderr so JSON
output on stdout stays pipeable) and the small set of style helpers below.
"""

from __future__ import annotations

import os
from typing import Iterable, Mapping

from rich.console import Console
from rich.table import Table
from rich.text import Text


_NO_COLOR = bool(os.environ.get("NO_COLOR")) or bool(os.environ.get("HONEYSTRIKE_NO_COLOR"))

console = Console(stderr=True, no_color=_NO_COLOR, highlight=False)
out = Console(stderr=False, no_color=_NO_COLOR, highlight=False)  # stdout — JSON / data


SEVERITY_STYLE = {
    "low": "bold green",
    "medium": "bold yellow",
    "high": "bold orange3",
    "critical": "bold red",
}

SCORE_GRADIENT = [
    (0, "dim"),
    (20, "green"),
    (50, "yellow"),
    (80, "red"),
]


def severity_text(severity: str | None) -> Text:
    if not severity:
        return Text("—", style="dim")
    return Text(severity.upper(), style=SEVERITY_STYLE.get(severity.lower(), ""))


def score_text(score: int | None) -> Text:
    if score is None:
        return Text("—", style="dim")
    style = "dim"
    for threshold, color in SCORE_GRADIENT:
        if score >= threshold:
            style = color
    return Text(str(score), style=style)


def make_table(*headers: str, title: str | None = None) -> Table:
    t = Table(title=title, expand=True, header_style="bold cyan")
    for h in headers:
        t.add_column(h, overflow="fold")
    return t


def kv_table(rows: Iterable[tuple[str, str]], *, title: str | None = None) -> Table:
    t = Table(title=title, show_header=False, expand=False, box=None, pad_edge=False)
    t.add_column(style="dim")
    t.add_column()
    for k, v in rows:
        t.add_row(k, v)
    return t


def banner(text: str, *, style: str = "bold cyan") -> None:
    """Prominent in-CLI banner for match start / scenario announcements."""
    console.rule(Text(text, style=style))


def warn(text: str) -> None:
    console.print(f"[yellow]![/yellow] {text}")


def error(text: str) -> None:
    console.print(f"[red]✗[/red] {text}")


def success(text: str) -> None:
    console.print(f"[green]✓[/green] {text}")


def info(text: str) -> None:
    console.print(f"[cyan]i[/cyan] {text}")


def render_kv(mapping: Mapping[str, str | None], *, title: str | None = None) -> None:
    rows = [(k, str(v) if v is not None else "—") for k, v in mapping.items()]
    console.print(kv_table(rows, title=title))
