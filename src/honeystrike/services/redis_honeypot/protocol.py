"""Minimal RESP (REdis Serialization Protocol) parser + canned replies.

Pure logic, no sockets. We parse client requests (RESP arrays of bulk
strings, or inline commands) and produce believable replies for the handful
of commands attackers run against an exposed Redis:

  PING, AUTH, INFO, CONFIG GET/SET, SET, GET, SAVE, COMMAND, SELECT, ...

The interesting attack is unauthenticated RCE: CONFIG SET dir /root/.ssh +
SET payload + CONFIG SET dbfilename authorized_keys + SAVE. We don't execute
any of it — we just answer plausibly and record every command.
"""

from __future__ import annotations

CRLF = b"\r\n"


def parse_command(buf: bytes) -> tuple[list[str] | None, bytes]:
    """Parse one command from `buf`.

    Returns (args, remaining_bytes). If the buffer doesn't yet hold a full
    command, returns (None, buf) so the caller can read more. Supports both
    RESP arrays (`*N$len...`) and inline commands (`PING\\r\\n`).
    """
    if not buf:
        return None, buf
    if buf[:1] == b"*":
        return _parse_resp_array(buf)
    # Inline command — read up to CRLF.
    idx = buf.find(CRLF)
    if idx == -1:
        return None, buf
    line = buf[:idx].decode("utf-8", errors="replace")
    rest = buf[idx + 2:]
    parts = [p for p in line.split() if p]
    return (parts or [""]), rest


def _parse_resp_array(buf: bytes) -> tuple[list[str] | None, bytes]:
    idx = buf.find(CRLF)
    if idx == -1:
        return None, buf
    try:
        count = int(buf[1:idx])
    except ValueError:
        # Malformed header — consume the line and treat as empty command.
        return [""], buf[idx + 2:]
    pos = idx + 2
    args: list[str] = []
    for _ in range(count):
        if pos >= len(buf) or buf[pos:pos + 1] != b"$":
            return None, buf            # incomplete
        nl = buf.find(CRLF, pos)
        if nl == -1:
            return None, buf
        try:
            blen = int(buf[pos + 1:nl])
        except ValueError:
            return [""], buf[nl + 2:]
        start = nl + 2
        end = start + blen
        if end + 2 > len(buf):
            return None, buf            # bulk body not fully arrived
        args.append(buf[start:end].decode("utf-8", errors="replace"))
        pos = end + 2
    return args, buf[pos:]


# ---- replies --------------------------------------------------------------

_FAKE_INFO = (
    "# Server\r\n"
    "redis_version:7.0.11\r\n"
    "os:Linux 5.15.0-86-generic x86_64\r\n"
    "process_id:1\r\n"
    "tcp_port:6379\r\n"
    "# Clients\r\nconnected_clients:1\r\n"
    "# Memory\r\nused_memory_human:1.10M\r\n"
    "# Keyspace\r\ndb0:keys=3,expires=0,avg_ttl=0\r\n"
)


def _simple(s: str) -> bytes:
    return f"+{s}\r\n".encode()


def _error(s: str) -> bytes:
    return f"-{s}\r\n".encode()


def _bulk(s: str) -> bytes:
    return f"${len(s)}\r\n{s}\r\n".encode()


def reply_for(args: list[str]) -> tuple[bytes, bool, bool]:
    """Return (reply_bytes, should_close, is_rce_attempt) for a command.

    `is_rce_attempt` flags the CONFIG SET dir/dbfilename pattern used to drop
    SSH keys or cron jobs via an unauth Redis.
    """
    if not args or not args[0]:
        return _error("ERR unknown command"), False, False
    cmd = args[0].upper()
    if cmd == "PING":
        return (_simple("PONG") if len(args) == 1 else _bulk(args[1])), False, False
    if cmd == "AUTH":
        # Real unauth redis: "ERR Client sent AUTH, but no password is set".
        return _error("ERR Client sent AUTH, but no password is set"), False, False
    if cmd == "INFO":
        return _bulk(_FAKE_INFO), False, False
    if cmd == "COMMAND":
        return b"*0\r\n", False, False
    if cmd == "SELECT":
        return _simple("OK"), False, False
    if cmd == "CONFIG":
        sub = args[1].upper() if len(args) > 1 else ""
        if sub == "GET":
            key = args[2] if len(args) > 2 else ""
            # Return a believable value for the keys attackers probe.
            val = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb"}.get(key, "")
            return (b"*2\r\n" + _bulk(key) + _bulk(val)), False, False
        if sub == "SET":
            key = args[2].lower() if len(args) > 2 else ""
            rce = key in ("dir", "dbfilename")
            return _simple("OK"), False, rce
        return _simple("OK"), False, False
    if cmd in ("SET", "RENAME", "RENAMENX", "FLUSHALL", "FLUSHDB", "SAVE", "BGSAVE"):
        return _simple("OK"), False, False
    if cmd == "GET":
        return b"$-1\r\n", False, False        # nil
    if cmd == "QUIT":
        return _simple("OK"), True, False
    return _error(f"ERR unknown command '{args[0]}'"), False, False
