"""Post-auth fake interactive shell.

Once Paramiko grants a shell, this module drives the channel:

  - sends a realistic prompt
  - reads bytes from the attacker
  - splits on newline → one SSH_COMMAND per command line
  - returns plausible canned output (no real shell — never exec attacker data)
  - terminates on `exit` / `logout` / max-duration / channel close

All commands run as inert strings. Nothing is ever passed to subprocess/exec.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from dataclasses import dataclass

import paramiko

from honeystrike.core.logging import get_logger

log = get_logger(__name__)


_MAX_COMMAND_BYTES = 4096           # docs/08 §3 — SSH command size cap
_PROMPT = "root@srv-01:~# "
_EXIT_COMMANDS = frozenset({"exit", "logout", "quit"})


# ---- canned outputs -------------------------------------------------------

def _output_for(command: str) -> str:
    """Return plausible output for common reconnaissance commands.

    Kept intentionally small — anything not matched returns an empty string,
    which is realistic shell behaviour for unknown commands (most return
    a "not found" line or nothing).
    """
    cmd = command.strip()
    if not cmd:
        return ""
    head = cmd.split()[0]

    if head == "whoami":
        return "root\r\n"
    if head in {"id", "uid"}:
        return "uid=0(root) gid=0(root) groups=0(root)\r\n"
    if head == "uname":
        if "-a" in cmd:
            return "Linux srv-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
        return "Linux\r\n"
    if head == "hostname":
        return "srv-01\r\n"
    if head == "pwd":
        return "/root\r\n"
    if head == "ls":
        return ".aws  .bashrc  .profile  .ssh  backup.tar.gz\r\n"
    if head == "cat" and "/etc/passwd" in cmd:
        # Phase 6 canary line so `defend flags-found` catches /etc/passwd reads.
        from honeystrike.cli.attack.canaries import FAKE_PASSWD_LINE
        return (
            "root:x:0:0:root:/root:/bin/bash\r\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
            f"{FAKE_PASSWD_LINE.needle}\r\n"
        )
    if head == "cat" and ".aws/credentials" in cmd:
        # Phase 6 canary: fake AWS creds attackers love to grab on a popped box.
        from honeystrike.cli.attack.canaries import FAKE_AWS_KEY
        return (
            "[default]\r\n"
            f"aws_access_key_id = {FAKE_AWS_KEY.needle}\r\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"
            "region = us-east-1\r\n"
        )
    if head == "ps":
        return (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:01 systemd\r\n"
            "  421 ?        00:00:00 sshd\r\n"
            " 1024 pts/0    00:00:00 bash\r\n"
        )
    if head in {"clear", "history", "echo"}:
        return ""
    # Most unknown commands on a real shell return an error line:
    return f"-bash: {head}: command not found\r\n"


@dataclass
class CommandEvent:
    """Emitted by the shell loop for each command line entered."""

    raw: str
    tokens: list[str]


class FakeShell:
    """Reads bytes from a Paramiko channel and yields CommandEvents."""

    def __init__(
        self,
        channel: paramiko.Channel,
        *,
        max_duration_seconds: int = 300,
    ) -> None:
        self._channel = channel
        self._max_duration = max_duration_seconds
        self._buffer = bytearray()
        self._start = time.monotonic()

    def _send(self, text: str) -> None:
        try:
            self._channel.send(text.encode("utf-8"))
        except (OSError, EOFError, socket.error):
            pass

    def run(self) -> Iterator[CommandEvent]:
        """Drive the interactive loop. Yields each captured command line.

        The caller (listener) persists each yielded CommandEvent and decides
        when to close the session.
        """
        # Welcome banner — looks like a real Ubuntu login.
        self._send(
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            "\r\n"
            "Last login: " + time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime())
            + " from 10.0.0.1\r\n"
        )
        self._send(_PROMPT)

        while True:
            if (time.monotonic() - self._start) > self._max_duration:
                log.info("ssh.shell.timeout")
                self._send("\r\nConnection closed by timeout\r\n")
                return

            try:
                self._channel.settimeout(1.0)
                chunk = self._channel.recv(1024)
            except socket.timeout:
                continue
            except (OSError, EOFError):
                return

            if not chunk:
                return

            self._buffer.extend(chunk)
            # Cap buffer to avoid memory pressure on a malicious peer that
            # never sends a newline. Anything past the cap is dropped.
            if len(self._buffer) > _MAX_COMMAND_BYTES * 4:
                del self._buffer[: _MAX_COMMAND_BYTES * 2]

            while b"\n" in self._buffer or b"\r" in self._buffer:
                line, self._buffer = self._split_one_line(self._buffer)
                if line is None:
                    break

                # echo the line back so the client sees their input.
                self._send("\r\n")

                cmd_raw = line.decode("utf-8", errors="replace")[
                    :_MAX_COMMAND_BYTES
                ].strip()

                if cmd_raw:
                    yield CommandEvent(raw=cmd_raw, tokens=cmd_raw.split())
                    if cmd_raw.split()[0] in _EXIT_COMMANDS:
                        self._send("logout\r\n")
                        return
                    self._send(_output_for(cmd_raw))

                self._send(_PROMPT)

    @staticmethod
    def _split_one_line(buf: bytearray) -> tuple[bytes | None, bytearray]:
        """Return (line, remainder). Treats CR, LF, CRLF as line endings."""
        for i, b in enumerate(buf):
            if b in (0x0A, 0x0D):  # LF or CR
                line = bytes(buf[:i])
                rest = buf[i + 1 :]
                # Eat a following LF if this was CR (CRLF case).
                if b == 0x0D and rest and rest[0] == 0x0A:
                    rest = rest[1:]
                return line, bytearray(rest)
        return None, buf
