"""MITRE ATT&CK TTP rule framework + STIX bundle loader.

A `TTPRule` is a pure-Python dataclass with a `match_fn` that accepts the same
`SessionContext` the tool-signature library uses and returns a `TTPMatch` if
the rule fires. `evaluate()` runs every rule and returns the matched list.

This file ships only the *framework* + the framework's first two rules so
later phases (Week 9) can drop in more without touching the worker. The full
catalogue lives in `docs/01_SPEC_Master.md` §M3.

STIX bundle loader:
  - `load_attack_bundle()` parses a STIX 2.1 JSON (the official MITRE
    ATT&CK Enterprise file) and returns a lookup table mapping
    `technique_id` → `(name, tactic)`. Rules can validate themselves against
    the table at startup so a typo doesn't ship to prod.
  - If the bundle is missing or invalid we fall back to a tiny embedded table
    that covers the v1.0 rules so partial-stack deploys without the bundle
    still work.

The bundle file is downloaded out-of-band by the operator (or by a Phase 5
cron) into `$MAXMIND_DB_DIR/../mitre/enterprise-attack.json` — its presence
is optional.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from honeystrike.core.events import EventType
from honeystrike.core.logging import get_logger
from honeystrike.workers.intel.signatures import SessionContext

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class TTPMatch:
    """One technique attribution for a session."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    trigger_event_id: str | None       # uuid as string, or None if rule has no anchor


@dataclass(slots=True, frozen=True)
class TechniqueInfo:
    name: str
    tactic: str                         # human-readable tactic name


MatchFn = Callable[[SessionContext], TTPMatch | None]


@dataclass(slots=True, frozen=True)
class TTPRule:
    """A single rule. `technique_id` MUST exist in the technique table at load."""

    technique_id: str
    name: str                           # short rule label (not the technique name)
    description: str
    confidence: float
    match_fn: MatchFn


# ---------------------------------------------------------------------------
# Embedded fallback table — covers the v1.0 rule set in docs/01 §M3.
# Used when the operator hasn't downloaded the official STIX bundle.
# ---------------------------------------------------------------------------

EMBEDDED_TECHNIQUES: dict[str, TechniqueInfo] = {
    "T1110.001": TechniqueInfo("Brute Force: Password Guessing", "Credential Access"),
    "T1110.004": TechniqueInfo("Brute Force: Credential Stuffing", "Credential Access"),
    "T1190":     TechniqueInfo("Exploit Public-Facing Application", "Initial Access"),
    "T1083":     TechniqueInfo("File and Directory Discovery", "Discovery"),
    "T1595.001": TechniqueInfo("Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    "T1592":     TechniqueInfo("Gather Victim Host Information", "Reconnaissance"),
    "T1078":     TechniqueInfo("Valid Accounts", "Defense Evasion"),
}


# ---------------------------------------------------------------------------
# STIX loader
# ---------------------------------------------------------------------------

def load_attack_bundle(path: str | Path | None) -> dict[str, TechniqueInfo]:
    """Parse a MITRE ATT&CK STIX 2.1 bundle and return a lookup table.

    On any failure (missing file, malformed JSON, schema mismatch) we log and
    return the embedded fallback so the worker can keep running.
    """
    if path is None:
        return dict(EMBEDDED_TECHNIQUES)
    p = Path(path)
    if not p.is_file():
        log.warning("ttp.stix_bundle_missing", path=str(p))
        return dict(EMBEDDED_TECHNIQUES)

    try:
        bundle = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("ttp.stix_bundle_read_failed", path=str(p), error=str(exc))
        return dict(EMBEDDED_TECHNIQUES)

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        log.warning("ttp.stix_bundle_malformed", path=str(p))
        return dict(EMBEDDED_TECHNIQUES)

    table: dict[str, TechniqueInfo] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        external_refs = obj.get("external_references") or []
        tid = next(
            (
                ref.get("external_id")
                for ref in external_refs
                if ref.get("source_name") == "mitre-attack"
                and ref.get("external_id", "").startswith("T")
            ),
            None,
        )
        if not tid:
            continue
        name = obj.get("name") or tid
        kill_chains = obj.get("kill_chain_phases") or []
        tactic = "Unknown"
        for phase in kill_chains:
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = phase.get("phase_name", "Unknown").replace("-", " ").title()
                break
        table[tid] = TechniqueInfo(name=name, tactic=tactic)

    if not table:
        log.warning("ttp.stix_bundle_empty", path=str(p))
        return dict(EMBEDDED_TECHNIQUES)

    log.info("ttp.stix_bundle_loaded", techniques=len(table), path=str(p))
    return table


def validate_rules(
    rules: tuple[TTPRule, ...], techniques: dict[str, TechniqueInfo]
) -> None:
    """Raise if any rule references an unknown technique_id."""
    missing = [r.technique_id for r in rules if r.technique_id not in techniques]
    if missing:
        raise ValueError(
            f"TTPRule references unknown MITRE technique ids: {sorted(set(missing))}"
        )


# ---------------------------------------------------------------------------
# Rule implementations — framework demo. The full v1.0 catalogue lands in Week 9.
# ---------------------------------------------------------------------------

def _password_guessing_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1110.001 — Brute Force: Password Guessing.

    Fires for any session with >5 SSH/FTP auth attempts.
    """
    auth_events: list[dict[str, Any]] = []
    if ctx.service == "ssh":
        auth_events = ctx.payloads(EventType.SSH_AUTH_ATTEMPT)
    elif ctx.service == "ftp":
        auth_events = [
            p for p in ctx.payloads(EventType.FTP_COMMAND)
            if p.get("command", "").upper() == "PASS"
        ]
    if len(auth_events) <= 5:
        return None
    return TTPMatch(
        technique_id="T1110.001",
        technique_name=EMBEDDED_TECHNIQUES["T1110.001"].name,
        tactic=EMBEDDED_TECHNIQUES["T1110.001"].tactic,
        confidence=0.90,
        trigger_event_id=None,
    )


def _multi_service_scan_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1595.001 — Scanning IP Blocks.

    Fires when an IP hits >= 2 services within 60s — same heuristic the
    tool-signature library uses, but mapped to MITRE.
    """
    if not ctx.sibling_sessions:
        return None
    seen = {ctx.service}
    for sess in ctx.sibling_sessions:
        if sess.get("src_ip") != ctx.src_ip:
            continue
        sess_started = sess.get("started_at")
        if not isinstance(sess_started, datetime):
            continue
        if abs((sess_started - ctx.started_at).total_seconds()) <= 60:
            svc = sess.get("service")
            if isinstance(svc, str):
                seen.add(svc)
    if len(seen) < 2:
        return None
    return TTPMatch(
        technique_id="T1595.001",
        technique_name=EMBEDDED_TECHNIQUES["T1595.001"].name,
        tactic=EMBEDDED_TECHNIQUES["T1595.001"].tactic,
        confidence=0.95,
        trigger_event_id=None,
    )


def _credential_stuffing_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1110.004 — Brute Force: Credential Stuffing.

    Stuffing != guessing: the attacker iterates pairs harvested from breach
    dumps, so each attempt usually has a different username. We flag sessions
    with >=5 auth attempts AND >=4 distinct usernames — the password-guessing
    rule's >5-attempt heuristic still fires alongside, the worker dedups by id.
    """
    if ctx.service == "ssh":
        attempts = ctx.payloads(EventType.SSH_AUTH_ATTEMPT)
        usernames = [p.get("username") for p in attempts if p.get("username")]
    elif ctx.service == "ftp":
        attempts = [
            p for p in ctx.payloads(EventType.FTP_COMMAND)
            if p.get("command", "").upper() in {"USER", "PASS"}
        ]
        usernames = [
            p.get("argument") for p in attempts
            if p.get("command", "").upper() == "USER" and p.get("argument")
        ]
    else:
        return None
    if len(attempts) < 5:
        return None
    if len({u for u in usernames if u}) < 4:
        return None
    return TTPMatch(
        technique_id="T1110.004",
        technique_name=EMBEDDED_TECHNIQUES["T1110.004"].name,
        tactic=EMBEDDED_TECHNIQUES["T1110.004"].tactic,
        confidence=0.85,
        trigger_event_id=None,
    )


def _exploit_public_app_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1190 — Exploit Public-Facing Application.

    Fires when any HTTP_REQUEST in the session carries a CVE signature or an
    SQLi pattern flag. Both indicate a deliberate attempt to exercise a known
    vulnerability path, which is the textbook MITRE definition.
    """
    if ctx.service != "http":
        return None
    for ev in ctx.events:
        if ev.get("event_type") != EventType.HTTP_REQUEST.value:
            continue
        p = ev.get("payload") or {}
        if p.get("cve_signature") or p.get("sqli_pattern"):
            return TTPMatch(
                technique_id="T1190",
                technique_name=EMBEDDED_TECHNIQUES["T1190"].name,
                tactic=EMBEDDED_TECHNIQUES["T1190"].tactic,
                confidence=0.85,
                trigger_event_id=ev.get("event_id"),
            )
    return None


# Discovery commands attackers typically run after landing a shell.
_DISCOVERY_TOKENS: re.Pattern[str] = re.compile(
    r"\b(?:ls|dir|find|cat|cd|pwd|ps|tree|locate|stat|wc|head|tail)\b",
    re.IGNORECASE,
)


def _file_discovery_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1083 — File and Directory Discovery.

    Fires on either:
      - HTTP requests flagged with path_traversal, or
      - SSH commands containing standard discovery tokens.
    """
    if ctx.service == "http":
        for ev in ctx.events:
            if ev.get("event_type") != EventType.HTTP_REQUEST.value:
                continue
            if (ev.get("payload") or {}).get("path_traversal"):
                return TTPMatch(
                    technique_id="T1083",
                    technique_name=EMBEDDED_TECHNIQUES["T1083"].name,
                    tactic=EMBEDDED_TECHNIQUES["T1083"].tactic,
                    confidence=0.75,
                    trigger_event_id=ev.get("event_id"),
                )
    elif ctx.service == "ssh":
        for ev in ctx.events:
            if ev.get("event_type") != EventType.SSH_COMMAND.value:
                continue
            raw = (ev.get("payload") or {}).get("raw") or ""
            if _DISCOVERY_TOKENS.search(raw):
                return TTPMatch(
                    technique_id="T1083",
                    technique_name=EMBEDDED_TECHNIQUES["T1083"].name,
                    tactic=EMBEDDED_TECHNIQUES["T1083"].tactic,
                    confidence=0.70,
                    trigger_event_id=ev.get("event_id"),
                )
    return None


# Information-disclosure paths and SSH host-info commands.
_HOST_INFO_PATHS = (
    "/.env",
    "/.git",
    "/server-status",
    "/server-info",
    "/phpinfo",
    "/wp-config",
    "/.aws/",
    "/.ssh/",
)
_HOST_INFO_CMD = re.compile(
    r"\b(?:uname|whoami|id|hostname|lsb_release|uptime|w\b|who\b|env\b|printenv|"
    r"cat\s+/etc/(?:passwd|os-release|hostname|issue))",
    re.IGNORECASE,
)


def _victim_host_info_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1592 — Gather Victim Host Information.

    HTTP: a request to a well-known info-disclosure path.
    SSH:  a command querying host/kernel/user info after landing a shell.
    """
    if ctx.service == "http":
        for ev in ctx.events:
            if ev.get("event_type") != EventType.HTTP_REQUEST.value:
                continue
            uri = (ev.get("payload") or {}).get("uri_decoded") or ""
            uri_l = uri.lower()
            if any(p in uri_l for p in _HOST_INFO_PATHS):
                return TTPMatch(
                    technique_id="T1592",
                    technique_name=EMBEDDED_TECHNIQUES["T1592"].name,
                    tactic=EMBEDDED_TECHNIQUES["T1592"].tactic,
                    confidence=0.65,
                    trigger_event_id=ev.get("event_id"),
                )
    elif ctx.service == "ssh":
        for ev in ctx.events:
            if ev.get("event_type") != EventType.SSH_COMMAND.value:
                continue
            raw = (ev.get("payload") or {}).get("raw") or ""
            if _HOST_INFO_CMD.search(raw):
                return TTPMatch(
                    technique_id="T1592",
                    technique_name=EMBEDDED_TECHNIQUES["T1592"].name,
                    tactic=EMBEDDED_TECHNIQUES["T1592"].tactic,
                    confidence=0.65,
                    trigger_event_id=ev.get("event_id"),
                )
    return None


def _valid_accounts_rule(ctx: SessionContext) -> TTPMatch | None:
    """T1078 — Valid Accounts.

    Hits when the attacker got past auth AND issued any post-auth action
    (i.e. an SSH_COMMAND event). On its own a granted auth attempt is
    suggestive; pairing it with a command is direct evidence of use.
    """
    if ctx.service != "ssh":
        return None
    granted = any(
        (ev.get("payload") or {}).get("success") is True
        for ev in ctx.events
        if ev.get("event_type") == EventType.SSH_AUTH_ATTEMPT.value
    )
    if not granted:
        return None
    used = any(
        ev.get("event_type") == EventType.SSH_COMMAND.value for ev in ctx.events
    )
    if not used:
        return None
    return TTPMatch(
        technique_id="T1078",
        technique_name=EMBEDDED_TECHNIQUES["T1078"].name,
        tactic=EMBEDDED_TECHNIQUES["T1078"].tactic,
        confidence=0.90,
        trigger_event_id=None,
    )


BUILTIN_RULES: tuple[TTPRule, ...] = (
    TTPRule(
        technique_id="T1110.001",
        name="password-guessing",
        description="More than 5 password auth attempts on SSH/FTP",
        confidence=0.90,
        match_fn=_password_guessing_rule,
    ),
    TTPRule(
        technique_id="T1110.004",
        name="credential-stuffing",
        description="5+ auth attempts with 4+ distinct usernames",
        confidence=0.85,
        match_fn=_credential_stuffing_rule,
    ),
    TTPRule(
        technique_id="T1190",
        name="exploit-public-app",
        description="HTTP request with CVE signature or SQLi pattern",
        confidence=0.85,
        match_fn=_exploit_public_app_rule,
    ),
    TTPRule(
        technique_id="T1083",
        name="file-directory-discovery",
        description="Path-traversal HTTP or SSH discovery commands",
        confidence=0.75,
        match_fn=_file_discovery_rule,
    ),
    TTPRule(
        technique_id="T1592",
        name="victim-host-info",
        description="Info-disclosure HTTP path or SSH host-info command",
        confidence=0.65,
        match_fn=_victim_host_info_rule,
    ),
    TTPRule(
        technique_id="T1078",
        name="valid-accounts",
        description="Granted SSH auth followed by post-auth commands",
        confidence=0.90,
        match_fn=_valid_accounts_rule,
    ),
    TTPRule(
        technique_id="T1595.001",
        name="ip-block-scanning",
        description="Same IP touches >=2 services within 60s",
        confidence=0.95,
        match_fn=_multi_service_scan_rule,
    ),
)


def evaluate(
    ctx: SessionContext,
    *,
    rules: tuple[TTPRule, ...] = BUILTIN_RULES,
) -> list[TTPMatch]:
    """Run every rule. Returns the matched techniques in confidence order."""
    matches: list[TTPMatch] = []
    seen_tids: set[str] = set()
    for rule in rules:
        m = rule.match_fn(ctx)
        if m is None:
            continue
        if m.technique_id in seen_tids:
            continue
        seen_tids.add(m.technique_id)
        matches.append(m)
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches
