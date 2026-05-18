"""Tests for the persistent SSH host-key helper.

RSA-2048 generation is slow (~1s on most hardware); these tests use a fresh
tmp directory per case so they don't share state but each test still pays
the cost of at most one keygen.
"""

from __future__ import annotations

from pathlib import Path

import paramiko

from honeystrike.services.ssh.host_key import load_or_create_host_key


def test_load_or_create_generates_a_new_key_when_dir_is_empty(tmp_path: Path) -> None:
    key = load_or_create_host_key(str(tmp_path))
    assert isinstance(key, paramiko.RSAKey)
    # The keyfile must now exist on disk for the next boot to reuse it.
    assert (tmp_path / "ssh_host_rsa_key").is_file()


def test_load_or_create_is_idempotent_across_calls(tmp_path: Path) -> None:
    first = load_or_create_host_key(str(tmp_path))
    second = load_or_create_host_key(str(tmp_path))
    # Same fingerprint means the second call read the existing file rather
    # than regenerating — which is the whole point of the persistent volume.
    assert first.get_fingerprint() == second.get_fingerprint()


def test_load_or_create_creates_missing_directory(tmp_path: Path) -> None:
    nested = tmp_path / "deeper" / "still-deeper"
    assert not nested.exists()
    load_or_create_host_key(str(nested))
    assert nested.is_dir()
    assert (nested / "ssh_host_rsa_key").is_file()
