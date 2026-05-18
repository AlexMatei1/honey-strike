"""uvicorn entrypoint: `python -m honeystrike.api`."""

from __future__ import annotations

import os

import uvicorn

from honeystrike.api.app import create_app

app = create_app()


def main() -> None:
    host = os.getenv("API_LISTEN_HOST", "0.0.0.0")
    port = int(os.getenv("API_LISTEN_PORT", "8000"))
    uvicorn.run(
        "honeystrike.api.__main__:app",
        host=host,
        port=port,
        log_config=None,
        access_log=False,            # our middleware emits structured access logs
        reload=False,
    )


if __name__ == "__main__":
    main()
