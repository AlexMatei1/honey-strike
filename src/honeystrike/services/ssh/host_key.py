"""Persistent SSH host key — generated on first boot, kept across restarts.

Stable host key matters because attacker tooling sometimes correlates by
host key fingerprint. Storing it on a docker volume (`ssh_host_keys`) means
the same fingerprint persists across container rebuilds.
"""

from __future__ import annotations

from pathlib import Path

import paramiko

from honeystrike.core.logging import get_logger

log = get_logger(__name__)

_KEY_FILE = "ssh_host_rsa_key"


def load_or_create_host_key(key_dir: str) -> paramiko.PKey:
    directory = Path(key_dir)
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / _KEY_FILE

    if key_path.exists():
        log.debug("ssh.host_key.loaded", path=str(key_path))
        return paramiko.RSAKey(filename=str(key_path))

    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    log.info(
        "ssh.host_key.generated",
        path=str(key_path),
        fingerprint=key.get_fingerprint().hex(),
    )
    return key
