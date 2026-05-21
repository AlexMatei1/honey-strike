"""Unit tests for the Phase 8 protocol parsers — Telnet, SMTP, Redis.

These cover the pure protocol logic (no sockets). The listeners themselves
are exercised by integration against the running stack.
"""

from __future__ import annotations

from honeystrike.services.redis_honeypot import protocol as rproto
from honeystrike.services.smtp import protocol as sproto
from honeystrike.services.telnet import protocol as tproto


# ---------------------------------------------------------------------------
# Telnet
# ---------------------------------------------------------------------------

def test_telnet_refuse_options_replies_dont_wont():
    # Client says WILL ECHO (251 251 1) and DO SGA (253 3).
    data = bytes([tproto.IAC, tproto.WILL, 0x01, tproto.IAC, tproto.DO, 0x03])
    reply = tproto.refuse_options(data)
    assert bytes([tproto.IAC, tproto.DONT, 0x01]) in reply
    assert bytes([tproto.IAC, tproto.WONT, 0x03]) in reply


def test_telnet_strip_iac_removes_command_sequences():
    raw = bytes([tproto.IAC, tproto.DO, 0x18]) + b"root" + bytes([tproto.IAC, tproto.WILL, 0x01])
    assert tproto.strip_iac(raw) == b"root"


def test_telnet_clean_credential_strips_crlf_and_control():
    assert tproto.clean_credential(b"admin\r\n") == "admin"
    assert tproto.clean_credential(b"r\x00oot\r\n") == "root"


def test_telnet_clean_credential_caps_length():
    assert len(tproto.clean_credential(b"a" * 9999)) == 256


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def test_smtp_parse_command_splits_verb_and_arg():
    assert sproto.parse_command(b"EHLO mail.evil.com\r\n") == ("EHLO", "mail.evil.com")
    assert sproto.parse_command(b"QUIT\r\n") == ("QUIT", "")


def test_smtp_parse_command_uppercases_verb():
    verb, _ = sproto.parse_command(b"ehlo x\r\n")
    assert verb == "EHLO"


def test_smtp_quit_closes():
    reply, should_close, _ = sproto.reply_for("QUIT", "", helo_seen=True)
    assert should_close is True
    assert reply.startswith("221")


def test_smtp_external_rcpt_is_flagged_relay_and_refused():
    reply, _, is_relay = sproto.reply_for("RCPT", "<victim@gmail.com>", helo_seen=True)
    assert is_relay is True
    assert reply.startswith("554")


def test_smtp_local_rcpt_not_relay():
    reply, _, is_relay = sproto.reply_for("RCPT", "<postmaster@example.com>", helo_seen=True)
    assert is_relay is False
    assert reply.startswith("250")


def test_smtp_auth_always_refused():
    reply, _, _ = sproto.reply_for("AUTH", "LOGIN", helo_seen=True)
    assert reply.startswith("535")


# ---------------------------------------------------------------------------
# Redis (RESP)
# ---------------------------------------------------------------------------

def test_redis_parse_resp_array():
    buf = b"*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"
    args, rest = rproto.parse_command(buf)
    assert args == ["AUTH", "secret"]
    assert rest == b""


def test_redis_parse_inline_command():
    args, rest = rproto.parse_command(b"PING\r\n")
    assert args == ["PING"]
    assert rest == b""


def test_redis_parse_incomplete_returns_none():
    # Bulk header promises 6 bytes but only 3 present.
    args, rest = rproto.parse_command(b"*1\r\n$6\r\nfoo")
    assert args is None
    assert rest == b"*1\r\n$6\r\nfoo"


def test_redis_parse_two_commands_in_one_buffer():
    buf = b"PING\r\n*1\r\n$4\r\nINFO\r\n"
    args1, rest1 = rproto.parse_command(buf)
    assert args1 == ["PING"]
    args2, rest2 = rproto.parse_command(rest1)
    assert args2 == ["INFO"]
    assert rest2 == b""


def test_redis_ping_pong():
    reply, close, rce = rproto.reply_for(["PING"])
    assert reply == b"+PONG\r\n"
    assert close is False and rce is False


def test_redis_info_is_bulk_string():
    reply, _, _ = rproto.reply_for(["INFO"])
    assert reply.startswith(b"$")
    assert b"redis_version" in reply


def test_redis_config_set_dir_flagged_as_rce():
    reply, _, rce = rproto.reply_for(["CONFIG", "SET", "dir", "/root/.ssh"])
    assert rce is True
    assert reply == b"+OK\r\n"


def test_redis_config_set_dbfilename_flagged_as_rce():
    _, _, rce = rproto.reply_for(["CONFIG", "SET", "dbfilename", "authorized_keys"])
    assert rce is True


def test_redis_normal_set_not_rce():
    _, _, rce = rproto.reply_for(["SET", "k", "v"])
    assert rce is False


def test_redis_auth_returns_no_password_set_error():
    reply, _, _ = rproto.reply_for(["AUTH", "x"])
    assert reply.startswith(b"-ERR")
    assert b"no password is set" in reply
