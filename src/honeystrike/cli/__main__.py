"""Entry point so `python -m honeystrike.cli` works the same as the
`honeystrike` console-script defined under `[tool.poetry.scripts]`.
"""

from __future__ import annotations

from honeystrike.cli import app


def main() -> None:                                        # pragma: no cover
    app()


if __name__ == "__main__":                                 # pragma: no cover
    main()
