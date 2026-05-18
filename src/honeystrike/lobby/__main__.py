"""uvicorn entrypoint: `python -m honeystrike.lobby`."""

from __future__ import annotations

import os

import uvicorn

from honeystrike.lobby.app import app
from honeystrike.lobby import store


def main() -> None:                                        # pragma: no cover
    store.init_schema()
    host = os.getenv("LOBBY_LISTEN_HOST", "0.0.0.0")       # noqa: S104 — game lobby
    port = int(os.getenv("LOBBY_LISTEN_PORT", "8002"))
    uvicorn.run(
        "honeystrike.lobby.app:app",
        host=host, port=port,
        log_config=None, access_log=True, reload=False,
    )


if __name__ == "__main__":                                 # pragma: no cover
    main()
