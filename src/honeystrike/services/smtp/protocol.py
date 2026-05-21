"""SMTP protocol helpers — pure logic, no sockets.

Implements just enough of RFC 5321 to keep a spam/relay scanner talking:
greet, answer HELO/EHLO, accept MAIL FROM / RCPT TO, then refuse to actually
relay. Every command line is parsed into (verb, argument) so the listener
can record it and decide the canned reply.
"""

from __future__ import annotations

BANNER = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"

# EHLO advertises capabilities; we offer a believable but useless set.
EHLO_REPLY_TEMPLATE = (
    "250-mail.example.com\r\n"
    "250-PIPELINING\r\n"
    "250-SIZE 10240000\r\n"
    "250-AUTH LOGIN PLAIN\r\n"
    "250 HELP\r\n"
)


def parse_command(line: bytes, *, max_len: int = 512) -> tuple[str, str]:
    """Parse one SMTP command line into (VERB_UPPER, argument). Strips CRLF,
    caps length, and is binary-safe (decodes with replacement)."""
    text = line.decode("utf-8", errors="replace").rstrip("\r\n")[:max_len]
    if not text:
        return "", ""
    parts = text.split(" ", 1)
    verb = parts[0].upper()
    arg = parts[1] if len(parts) > 1 else ""
    return verb, arg


def reply_for(verb: str, arg: str, *, helo_seen: bool) -> tuple[str, bool, bool]:
    """Return (reply_text, should_close, is_relay_attempt) for a command.

    We never actually relay; RCPT TO to a non-local domain is recorded as a
    relay attempt and refused with 554.
    """
    if verb in ("HELO",):
        return ("250 mail.example.com\r\n", False, False)
    if verb == "EHLO":
        return (EHLO_REPLY_TEMPLATE, False, False)
    if verb == "MAIL":
        return ("250 2.1.0 Ok\r\n", False, False)
    if verb == "RCPT":
        # A real relay would accept local recipients only; scanners probe with
        # an external domain to test open-relay. Refuse + flag.
        is_relay = "@" in arg and not arg.lower().endswith("example.com>")
        if is_relay:
            return ("554 5.7.1 Relay access denied\r\n", False, True)
        return ("250 2.1.5 Ok\r\n", False, False)
    if verb == "DATA":
        return ("354 End data with <CR><LF>.<CR><LF>\r\n", False, False)
    if verb == "AUTH":
        return ("535 5.7.8 Authentication credentials invalid\r\n", False, False)
    if verb == "RSET":
        return ("250 2.0.0 Ok\r\n", False, False)
    if verb == "NOOP":
        return ("250 2.0.0 Ok\r\n", False, False)
    if verb == "QUIT":
        return ("221 2.0.0 Bye\r\n", True, False)
    if verb == "":
        return ("500 5.5.2 Error: bad syntax\r\n", False, False)
    return ("502 5.5.2 Error: command not recognized\r\n", False, False)
