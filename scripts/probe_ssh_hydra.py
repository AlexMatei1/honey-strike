"""One-shot Hydra-style SSH probe used for Phase 3 Week 8 validation.

Submits 7 wordlist creds in a single TCP transport. With
SSH_ALLOW_AFTER_N_ATTEMPTS bumped high enough that none of them are granted,
the resulting session ends up with 7 SSH_AUTH_ATTEMPT events — enough to fire
both ssh-cred-wordlist and ssh-attempt-burst signatures.
"""

from __future__ import annotations

import socket
import sys
import time

import paramiko

HYDRA_CREDS = [
    ("root", "root"),
    ("root", "toor"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "hunter2"),
    ("root", "letmein"),
    ("root", "qwerty"),
]


def main(host: str = "127.0.0.1", port: int = 2222) -> int:
    sock = socket.create_connection((host, port), timeout=10)
    t = paramiko.Transport(sock)
    t.start_client(timeout=10)
    print(f"connected, banner={t.remote_version}")
    granted = 0
    for u, p in HYDRA_CREDS:
        try:
            t.auth_password(u, p)
            print(f"  GRANTED {u}:{p}")
            granted += 1
            break
        except paramiko.AuthenticationException:
            print(f"  failed {u}:{p}")
        except paramiko.SSHException as exc:
            print(f"  ssh-err  {u}:{p} -> {exc!s}")
            break
        time.sleep(0.05)
    t.close()
    print(f"done; granted={granted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
