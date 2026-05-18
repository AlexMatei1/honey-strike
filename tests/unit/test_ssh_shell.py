"""Tests for the canned-output and line-splitting logic of FakeShell.

The interactive `run()` loop drives a Paramiko channel; we test the pure
pieces in isolation.
"""

from __future__ import annotations

from honeystrike.services.ssh.shell import FakeShell, _output_for


def test_canned_outputs_have_reasonable_content() -> None:
    assert "root" in _output_for("whoami")
    assert "uid=0" in _output_for("id")
    assert "Linux" in _output_for("uname -a")
    assert "srv-01" in _output_for("hostname")
    assert "/root" in _output_for("pwd")
    assert "backup" in _output_for("ls -la")
    assert "root:x:0" in _output_for("cat /etc/passwd")
    assert "systemd" in _output_for("ps aux")
    assert _output_for("clear") == ""
    # Unknown command returns a bash-style "not found".
    assert "command not found" in _output_for("zorblax --foo")


def test_canned_output_for_empty_command_is_empty() -> None:
    assert _output_for("") == ""
    assert _output_for("   ") == ""


def test_line_splitter_handles_lf_cr_crlf() -> None:
    line, rest = FakeShell._split_one_line(bytearray(b"whoami\nrest"))
    assert line == b"whoami"
    assert bytes(rest) == b"rest"

    line, rest = FakeShell._split_one_line(bytearray(b"id\rextra"))
    assert line == b"id"
    assert bytes(rest) == b"extra"

    line, rest = FakeShell._split_one_line(bytearray(b"uname -a\r\nnext"))
    assert line == b"uname -a"
    assert bytes(rest) == b"next"


def test_line_splitter_returns_none_when_no_terminator() -> None:
    line, rest = FakeShell._split_one_line(bytearray(b"partial"))
    assert line is None
    assert bytes(rest) == b"partial"
