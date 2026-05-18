"""Pattern-based detection for HTTP requests.

Three independent checks run on every captured request:

  1. `scanner_signature(headers)`     — User-Agent → known tool name + confidence
  2. `sqli_pattern_found(text)`       — fragment of input matches an SQLi pattern
  3. `path_traversal_found(uri)`      — `../`, `..%2f`, encoded variants
  4. `xss_pattern_found(text)`        — script/event-handler injection markers

Each function is intentionally permissive: false positives are fine because
nothing reaching this honeypot is a legitimate request. The TTP mapper
downstream uses these flags to decide which MITRE techniques to attribute.

All regexes are compiled once at import time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Scanner / brute-force tool signatures
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class ScannerMatch:
    name: str
    confidence: float  # 0.0–1.0


# Order matters only for tie-breaks; first match wins.
_SCANNER_RULES: tuple[tuple[re.Pattern[str], ScannerMatch], ...] = (
    (re.compile(r"sqlmap", re.I), ScannerMatch("sqlmap", 0.99)),
    (re.compile(r"nikto", re.I), ScannerMatch("Nikto", 0.95)),
    (re.compile(r"\bnmap\b", re.I), ScannerMatch("Nmap", 0.90)),
    (re.compile(r"masscan", re.I), ScannerMatch("Masscan", 0.95)),
    (re.compile(r"hydra", re.I), ScannerMatch("Hydra", 0.95)),
    (re.compile(r"medusa", re.I), ScannerMatch("Medusa", 0.95)),
    (re.compile(r"metasploit|msfconsole|meterpreter", re.I), ScannerMatch("Metasploit", 0.90)),
    (re.compile(r"\bwpscan\b", re.I), ScannerMatch("WPScan", 0.90)),
    (re.compile(r"dirb(uster)?", re.I), ScannerMatch("DirBuster", 0.85)),
    (re.compile(r"gobuster", re.I), ScannerMatch("gobuster", 0.85)),
    (re.compile(r"ffuf", re.I), ScannerMatch("ffuf", 0.85)),
    (re.compile(r"acunetix|netsparker|burp(?!suite-community-test)", re.I),
     ScannerMatch("Commercial scanner", 0.80)),
    (re.compile(r"zgrab", re.I), ScannerMatch("zgrab", 0.85)),
    (re.compile(r"censys|shodan", re.I), ScannerMatch("Internet-wide scanner", 0.75)),
    # Generic giveaways — lower confidence, last to match.
    (re.compile(r"python-requests/", re.I), ScannerMatch("python-requests", 0.40)),
    (re.compile(r"curl/", re.I), ScannerMatch("curl", 0.30)),
    (re.compile(r"libwww-perl", re.I), ScannerMatch("libwww-perl", 0.55)),
    (re.compile(r"go-http-client", re.I), ScannerMatch("Go HTTP client", 0.35)),
)


def scanner_signature(headers: dict[str, str]) -> ScannerMatch | None:
    """Return the first scanner signature matching any header value.

    Most rules are anchored on User-Agent but some scanners leak their name
    in other headers too, so we scan every header value.
    """
    for value in headers.values():
        if not value:
            continue
        for pattern, match in _SCANNER_RULES:
            if pattern.search(value):
                return match
    return None


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

_SQLI_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?:'|%27).*(or|and).*(=|like)"),
    re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b"),
    re.compile(r"(?i)\b(select|insert|update|delete|drop|create|alter)\b\s+.*\b(from|into|table|database)\b"),
    re.compile(r"(?i)\bor\s+1\s*=\s*1\b"),
    re.compile(r"(?i)\band\s+1\s*=\s*1\b"),
    re.compile(r"(?i);\s*(drop|truncate|delete)\s"),
    re.compile(r"(?i)/\*.*?\*/"),  # SQL comment used to obfuscate
    re.compile(r"(?i)\bsleep\s*\(\s*\d+\s*\)"),
    re.compile(r"(?i)\bbenchmark\s*\("),
    re.compile(r"(?i)\bwaitfor\s+delay\b"),
    re.compile(r"(?i)\bxp_cmdshell\b"),
)


def sqli_pattern_found(text: str | None) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in _SQLI_PATTERNS)


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

_TRAVERSAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"(?i)\.\.%2f"),
    re.compile(r"(?i)\.\.%5c"),
    re.compile(r"(?i)%2e%2e%2f"),
    re.compile(r"(?i)/etc/passwd"),
    re.compile(r"(?i)/etc/shadow"),
    re.compile(r"(?i)\bproc/self/"),
    re.compile(r"(?i)c:\\windows\\"),
)


def path_traversal_found(uri: str | None) -> bool:
    if not uri:
        return False
    return any(p.search(uri) for p in _TRAVERSAL_PATTERNS)


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

_XSS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)<script\b"),
    re.compile(r"(?i)\bon(?:error|load|click|mouseover|focus)\s*="),
    re.compile(r"(?i)javascript:"),
    re.compile(r"(?i)<iframe\b"),
    re.compile(r"(?i)<img[^>]+src\s*=\s*['\"]?javascript:"),
)


def xss_pattern_found(text: str | None) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in _XSS_PATTERNS)


# ---------------------------------------------------------------------------
# CVE / common exploit URI patterns
# ---------------------------------------------------------------------------

_CVE_URI_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)/\.env\b"),                          "CONFIG_FILE_PROBE"),
    (re.compile(r"(?i)\.git/(config|HEAD)\b"),             "GIT_REPO_LEAK"),
    (re.compile(r"(?i)/wp-login\.php"),                    "WP_LOGIN_PROBE"),
    (re.compile(r"(?i)/xmlrpc\.php"),                      "WP_XMLRPC_PROBE"),
    (re.compile(r"(?i)/(?:cgi-bin/.*|bin)/sh"),            "SHELL_CGI_PROBE"),
    (re.compile(r"(?i)/manager/html"),                     "TOMCAT_MANAGER_PROBE"),
    (re.compile(r"(?i)/jenkins/script"),                   "JENKINS_SCRIPT_CONSOLE"),
    (re.compile(r"(?i)/console/login\.do"),                "WEBLOGIC_CONSOLE"),
    (re.compile(r"(?i)/_ignition/execute-solution"),       "CVE-2021-3129"),
    (re.compile(r"(?i)\${jndi:"),                           "CVE-2021-44228"),  # Log4Shell
    (re.compile(r"(?i)/api/v1/(?:pods|secrets)"),          "K8S_API_PROBE"),
    (re.compile(r"(?i)/actuator/(?:env|heapdump|gateway)"), "SPRING_ACTUATOR"),
)


def cve_signature(uri: str | None, body: str | None = None) -> str | None:
    """Return a stable identifier for the first matching CVE/exploit pattern."""
    haystack_parts = [p for p in (uri, body) if p]
    if not haystack_parts:
        return None
    haystack = " ".join(haystack_parts)
    for pattern, label in _CVE_URI_PATTERNS:
        if pattern.search(haystack):
            return label
    return None
