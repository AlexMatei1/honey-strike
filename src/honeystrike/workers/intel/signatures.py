"""Multi-service tool signature library.

Operates on a full *session-level* view (a session plus its ordered events)
and returns the set of attacker-tools that match. Rules consider:

  - HTTP User-Agent matches (reuses `services.http.detectors`)
  - SSH client version banner (`client_version` payload field)
  - SSH credential sequence (Hydra default wordlists leak distinctive ordering)
  - FTP USER/PASS pairs (Hydra typically alternates user-then-pass tightly)
  - Cross-service: short bursts of distinct services from one IP suggest Masscan

Each rule is a `ToolSignatureRule` with a pure `match_fn` that takes a
`SessionContext` and returns a `(name, confidence)` if it matches, else None.

The signature library is intentionally side-effect-free — it never touches
Redis or PG. The Phase 3 FingerprintWorker calls these from a higher layer.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from honeystrike.core.events import EventType
from honeystrike.services.http.detectors import scanner_signature


@dataclass(slots=True, frozen=True)
class ToolMatch:
    name: str
    confidence: float       # 0.0-1.0


@dataclass(slots=True)
class SessionContext:
    """Frozen view of a session and its events used by signature rules.

    Built once per fingerprint evaluation. `events` MUST be ordered ascending
    by `ts` so timing rules can rely on inter-event deltas.
    """

    service: str                                # 'ssh' | 'http' | 'ftp' | 'rdp'
    src_ip: str
    started_at: datetime
    events: list[dict[str, Any]]
    sibling_sessions: list[dict[str, Any]] = field(default_factory=list)

    def payloads(self, event_type: EventType) -> list[dict[str, Any]]:
        return [
            e["payload"] for e in self.events
            if e.get("event_type") == event_type.value
        ]

    def first_payload(self, event_type: EventType) -> dict[str, Any] | None:
        for e in self.events:
            if e.get("event_type") == event_type.value:
                payload: dict[str, Any] = e["payload"]
                return payload
        return None


MatchFn = Callable[[SessionContext], ToolMatch | None]


@dataclass(slots=True, frozen=True)
class ToolSignatureRule:
    name: str
    description: str
    match_fn: MatchFn


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------

# SSH client-version regexes. Specific tools win over the libssh fallback.
# Ordering matters: the first match wins.
_SSH_CLIENT_VERSION_PATTERNS: tuple[tuple[re.Pattern[str], ToolMatch], ...] = (
    (re.compile(r"hydra", re.I), ToolMatch("Hydra", 0.95)),
    (re.compile(r"medusa", re.I), ToolMatch("Medusa", 0.95)),
    (re.compile(r"crowbar", re.I), ToolMatch("Crowbar", 0.90)),
    (re.compile(r"PUTTY", re.I), ToolMatch("PuTTY", 0.30)),
    # libssh-anything is a catch-all for brute-force tooling that links libssh.
    (re.compile(r"libssh[_-](?:0\.|1\.|2\.)", re.I), ToolMatch("libssh-based tool", 0.55)),
)


def _ssh_banner_rule(ctx: SessionContext) -> ToolMatch | None:
    if ctx.service != "ssh":
        return None
    payload = ctx.first_payload(EventType.SSH_BANNER_GRAB)
    if not payload:
        return None
    version = (payload.get("client_version") or "").strip()
    if not version:
        return None
    for pattern, match in _SSH_CLIENT_VERSION_PATTERNS:
        if pattern.search(version):
            return match
    return None


# Hydra's default `-V` wordlist hits common creds in a recognisable order:
# root:root, root:toor, root:123456, admin:admin … with very fast iteration.
_HYDRA_FAST_CREDS = frozenset(
    {("root", "root"), ("root", "toor"), ("root", "123456"),
     ("root", "password"), ("admin", "admin"), ("admin", "password"),
     ("test", "test"), ("user", "user"), ("oracle", "oracle")}
)


def _ssh_credential_pattern_rule(ctx: SessionContext) -> ToolMatch | None:
    if ctx.service != "ssh":
        return None
    creds = [
        (p.get("username"), p.get("password"))
        for p in ctx.payloads(EventType.SSH_AUTH_ATTEMPT)
        if p.get("auth_type") == "password"
    ]
    if len(creds) < 3:
        return None
    hits = sum(1 for c in creds if c in _HYDRA_FAST_CREDS)
    if hits >= 2:
        # Name collides with the banner-rule "Hydra" output by design — the
        # dedup pass in `evaluate()` keeps the higher-confidence version.
        return ToolMatch("Hydra", 0.70)
    return None


def _ftp_credential_pattern_rule(ctx: SessionContext) -> ToolMatch | None:
    if ctx.service != "ftp":
        return None
    paired: list[tuple[str | None, str | None]] = []
    username: str | None = None
    for ev in ctx.events:
        cmd = ev["payload"].get("command", "").upper()
        if cmd == "USER":
            username = ev["payload"].get("argument")
        elif cmd == "PASS" and username is not None:
            paired.append((username, ev["payload"].get("argument")))
            username = None
    if len(paired) < 3:
        return None
    hits = sum(1 for c in paired if c in _HYDRA_FAST_CREDS)
    if hits >= 2:
        return ToolMatch("Hydra", 0.70)
    return None


# Burst timing: many auth attempts in a very short window = automated tool.
def _ssh_attempt_burst_rule(ctx: SessionContext) -> ToolMatch | None:
    if ctx.service != "ssh":
        return None
    auth_events = [
        e for e in ctx.events
        if e.get("event_type") == EventType.SSH_AUTH_ATTEMPT.value
    ]
    if len(auth_events) < 5:
        return None
    first_ts = auth_events[0]["ts"]
    last_ts = auth_events[-1]["ts"]
    # Caller passes datetimes; tolerate ISO strings as well.
    first = first_ts if isinstance(first_ts, datetime) else datetime.fromisoformat(first_ts)
    last = last_ts if isinstance(last_ts, datetime) else datetime.fromisoformat(last_ts)
    span_seconds = max(0.001, (last - first).total_seconds())
    rate = len(auth_events) / span_seconds
    if rate > 10:  # 600/min
        return ToolMatch("Automated brute-force (high-rate)", 0.65)
    if rate > 2:   # ~120/min
        return ToolMatch("Automated brute-force (medium-rate)", 0.45)
    return None


# Cross-service: same IP hitting >= 2 services in 60s screams Masscan/Nmap.
def _multi_service_scan_rule(ctx: SessionContext) -> ToolMatch | None:
    if not ctx.sibling_sessions:
        return None
    seen_services = {ctx.service}
    for sess in ctx.sibling_sessions:
        if sess.get("src_ip") != ctx.src_ip:
            continue
        sess_started = sess.get("started_at")
        if not isinstance(sess_started, datetime):
            continue
        if abs((sess_started - ctx.started_at).total_seconds()) <= 60:
            svc = sess.get("service")
            if isinstance(svc, str):
                seen_services.add(svc)
    if len(seen_services) >= 3:
        return ToolMatch("Masscan / port-scan", 0.95)
    if len(seen_services) >= 2:
        return ToolMatch("Multi-service scanner", 0.75)
    return None


# HTTP — defer to detectors.scanner_signature, which already maps a UA → tool.
def _http_user_agent_rule(ctx: SessionContext) -> ToolMatch | None:
    if ctx.service != "http":
        return None
    payload = ctx.first_payload(EventType.HTTP_REQUEST)
    if not payload:
        return None
    headers = payload.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    scanner = scanner_signature(headers)
    if scanner is None:
        return None
    return ToolMatch(scanner.name, scanner.confidence)


# RDP — the Negotiation Request bits leak the client family.
def _rdp_protocols_rule(ctx: SessionContext) -> ToolMatch | None:
    if ctx.service != "rdp":
        return None
    payload = ctx.first_payload(EventType.RDP_CONNECT)
    if not payload:
        return None
    requested = payload.get("requested_protocols")
    if requested == 0:
        # PROTOCOL_RDP only — many Internet-wide scanners (Censys, Shodan, zmap).
        return ToolMatch("Internet-wide RDP scanner", 0.60)
    return None


ALL_RULES: tuple[ToolSignatureRule, ...] = (
    ToolSignatureRule("ssh-banner", "Match SSH client_version against known tool patterns",
                      _ssh_banner_rule),
    ToolSignatureRule("ssh-cred-wordlist", "SSH credentials hitting common Hydra wordlist entries",
                      _ssh_credential_pattern_rule),
    ToolSignatureRule("ssh-attempt-burst", "High-rate SSH auth attempts indicating automation",
                      _ssh_attempt_burst_rule),
    ToolSignatureRule("ftp-cred-wordlist", "FTP USER/PASS pairs matching Hydra wordlist",
                      _ftp_credential_pattern_rule),
    ToolSignatureRule("http-user-agent", "HTTP User-Agent matches a scanner signature",
                      _http_user_agent_rule),
    ToolSignatureRule("rdp-protocols", "RDP requested-protocols bitfield suggests a scanner",
                      _rdp_protocols_rule),
    ToolSignatureRule("multi-service-scan", "Same IP hit multiple services within 60s",
                      _multi_service_scan_rule),
)


def evaluate(
    ctx: SessionContext, *, rules: tuple[ToolSignatureRule, ...] = ALL_RULES
) -> list[ToolMatch]:
    """Run every rule against `ctx` and return all matches, de-duplicated.

    De-dup keeps the highest-confidence variant when two rules name the same
    tool (e.g. two rules both label something "Hydra").
    """
    best: dict[str, ToolMatch] = {}
    for rule in rules:
        match = rule.match_fn(ctx)
        if match is None:
            continue
        existing = best.get(match.name)
        if existing is None or match.confidence > existing.confidence:
            best[match.name] = match
    return sorted(best.values(), key=lambda m: m.confidence, reverse=True)
