"""
Offline Unit Tests for ThreatForge Scanner Modules
===================================================
Tests each check function (including Windows/WAMP Command Injection and
cookie secret redaction) and report builder without network access.

Run with:
    python tests/test_modules.py
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.payload_injector import CMDI_PAYLOADS, SQL_PAYLOADS, XSS_PAYLOADS
from scanner.reporter import build_report
from scanner.response_analyzer import (
    check_clickjacking,
    check_command_injection,
    check_cookie_flags,
    check_csrf,
    check_security_headers,
    check_sql_injection,
)


def run_test(name: str, fn) -> bool:
    """Run a single test function and print PASS or FAIL."""
    try:
        fn()
        print(f"[PASS] {name}")
        return True
    except AssertionError as exc:
        print(f"[FAIL] {name}: Assertion failed - {exc}")
        return False
    except Exception as exc:
        print(f"[FAIL] {name}: Unexpected error - {exc}")
        return False


def test_non_destructive_payloads():
    """Verify no payload contains destructive SQL or shell commands."""
    forbidden = ("DROP ", "DELETE ", "TRUNCATE ", "UPDATE ", "INSERT ", "RM ", "DEL ")
    for p in SQL_PAYLOADS + XSS_PAYLOADS + CMDI_PAYLOADS:
        upper_p = p.upper()
        for word in forbidden:
            assert word not in upper_p, f"Destructive keyword '{word}' found in {p}"


def test_cookie_flags():
    """Test check_cookie_flags and verify cookie secret values are never stored."""
    secret_val = "SUPER_SECRET_SESSION_VALUE_999"
    res_http = check_cookie_flags(
        [f"PHPSESSID={secret_val}; path=/"], "http://localhost/dvwa"
    )
    assert any(
        f["field"] == "PHPSESSID" and f["severity"] == "High" and "HttpOnly" in f["detail"]
        for f in res_http
    ), "Expected High severity for PHPSESSID missing HttpOnly"
    assert any(
        f["field"] == "PHPSESSID" and f["severity"] == "Low" and "SameSite" in f["detail"]
        for f in res_http
    ), "Expected Low severity for PHPSESSID missing SameSite"

    # Ensure the secret cookie value is NEVER present in evidence or detail
    for f in res_http:
        assert secret_val not in f["evidence"], "Cookie secret value leaked in evidence!"
        assert secret_val not in f["detail"], "Cookie secret value leaked in detail!"

    # Non-session cookie missing Secure on HTTPS + SameSite=None without Secure
    res_https = check_cookie_flags(
        ["theme=dark; HttpOnly; SameSite=None"], "https://example.com"
    )
    assert any("missing the Secure flag" in f["detail"] for f in res_https)
    assert any("SameSite=None without the Secure flag" in f["detail"] for f in res_https)

    # Fully hardened cookie on HTTPS -> no findings
    res_safe = check_cookie_flags(
        ["PHPSESSID=xyz; Path=/; Secure; HttpOnly; SameSite=Strict"],
        "https://example.com",
    )
    assert res_safe == [], f"Expected no findings for secure cookie, got {res_safe}"


def test_clickjacking():
    """Test check_clickjacking with various header dictionaries."""
    res_none = check_clickjacking({}, "http://localhost")
    assert len(res_none) == 1
    assert res_none[0]["type"] == "Clickjacking"
    assert res_none[0]["severity"] == "Medium"
    assert res_none[0]["field"] == "X-Frame-Options / frame-ancestors"

    assert check_clickjacking({"X-Frame-Options": "DENY"}, "http://localhost") == []
    assert (
        check_clickjacking(
            {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"},
            "http://localhost",
        )
        == []
    )

    res_weak = check_clickjacking(
        {"X-Frame-Options": "ALLOW-FROM https://example.com"}, "http://localhost"
    )
    assert len(res_weak) == 1 and res_weak[0]["severity"] == "Low"

    sec_headers = check_security_headers({})
    assert all(f["field"] != "X-Frame-Options" for f in sec_headers)


def test_csrf():
    """Test check_csrf with sample form dictionaries."""
    get_form = {
        "action": "http://localhost/search",
        "method": "get",
        "inputs": [{"name": "q", "type": "text", "value": ""}],
    }
    assert check_csrf([get_form], "http://localhost") == []

    valid_post = {
        "action": "http://localhost/dvwa/csrf",
        "method": "post",
        "inputs": [
            {"name": "password_new", "type": "password", "value": ""},
            {"name": "user_token", "type": "hidden", "value": "9f8e7d6c5b4a3210"},
        ],
    }
    assert check_csrf([valid_post], "http://localhost") == []

    missing_post = {
        "action": "http://localhost/transfer",
        "method": "post",
        "inputs": [{"name": "amount", "type": "text", "value": "100"}],
    }
    res_missing = check_csrf([missing_post], "http://localhost")
    assert len(res_missing) == 1
    assert res_missing[0]["type"] == "Missing CSRF Token"
    assert res_missing[0]["severity"] == "Medium"

    weak_post = {
        "action": "http://localhost/update",
        "method": "post",
        "inputs": [{"name": "csrf_token", "type": "hidden", "value": "123"}],
    }
    res_weak = check_csrf([weak_post], "http://localhost")
    assert len(res_weak) == 1
    assert res_weak[0]["type"] == "Weak or Empty CSRF Token"
    assert res_weak[0]["severity"] == "Low"


def test_command_injection_unix_and_windows():
    """Test check_command_injection for both Unix (TF1337) and Windows (TFWINWindows_NT) markers."""
    # 1. Unix hit
    unix_hit = [
        {
            "field": "ip",
            "payload": ";echo TF$((7*191))",
            "status_code": 200,
            "body": "PING 127.0.0.1: 56 data bytes\nTF1337\n",
        }
    ]
    res_unix = check_command_injection(unix_hit)
    assert len(res_unix) == 1
    assert res_unix[0]["severity"] == "High"
    assert "Unix shell" in res_unix[0]["evidence"]

    # 2. Windows WAMP cmd.exe hit
    win_hit = [
        {
            "field": "ip",
            "payload": "&echo TFWIN%OS%",
            "status_code": 200,
            "body": "Reply from 127.0.0.1: bytes=32 time<1ms\r\nTFWINWindows_NT\r\n",
        }
    ]
    res_win = check_command_injection(win_hit)
    assert len(res_win) == 1
    assert res_win[0]["severity"] == "High"
    assert "Windows cmd" in res_win[0]["evidence"]

    # 3. Reflection of Unix or Windows raw expressions must NOT be flagged
    reflections = [
        {
            "field": "ip",
            "payload": ";echo TF$((7*191))",
            "status_code": 200,
            "body": "Error: invalid host ';echo TF$((7*191))' TF1337",
        },
        {
            "field": "ip",
            "payload": "&echo TFWIN%OS%",
            "status_code": 200,
            "body": "Echoed input: &echo TFWIN%OS% (TFWINWindows_NT)",
        },
    ]
    assert check_command_injection(reflections) == []


def test_wamp_mysqli_error_signatures():
    """Verify WAMP PHP mysqli error messages are detected by check_sql_injection."""
    wamp_res = [
        {
            "field": "id",
            "payload": "' OR '1'='1",
            "status_code": 200,
            "body": "Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax",
        }
    ]
    findings = check_sql_injection(wamp_res)
    assert len(findings) == 1 and findings[0]["type"] == "SQL Injection"


def test_reporter_dedup_and_sorting():
    """Test build_report deduplication, severity sorting, and counts."""
    raw_findings = [
        {
            "type": "Missing Security Header",
            "severity": "Medium",
            "field": "Content-Security-Policy",
            "payload": "N/A",
            "evidence": "Missing",
            "detail": "CSP missing",
        },
        {
            "type": "Missing Security Header",
            "severity": "Medium",
            "field": "Content-Security-Policy",
            "payload": "N/A",
            "evidence": "Missing",
            "detail": "CSP missing",
        },
        {
            "type": "SQL Injection",
            "severity": "High",
            "field": "id",
            "payload": "' OR '1'='1",
            "evidence": "SQL syntax error",
            "detail": "SQLi",
        },
        {
            "type": "Weak or Empty CSRF Token",
            "severity": "Low",
            "field": "http://localhost/post",
            "payload": "N/A",
            "evidence": "short",
            "detail": "Weak token",
        },
    ]
    report = build_report("http://localhost", raw_findings, authenticated_scan=True)

    assert report["total_findings"] == 3
    assert sum(report["summary"].values()) == report["total_findings"]
    assert [f["severity"] for f in report["findings"]] == ["High", "Medium", "Low"]
    assert report["severity_counts"] == {"High": 1, "Medium": 1, "Low": 1}
    assert report["authenticated_scan"] is True
    assert "risk_score" in report and "grade" in report


def test_orchestrator_resilience_and_404():
    """Verify _run_module catches exceptions and validate_url accepts HTTP 4xx."""
    from unittest.mock import MagicMock, patch
    from scanner.scanner import _run_module
    from scanner.url_input import validate_url

    def crashing_module():
        raise RuntimeError("Simulated module failure")

    assert _run_module("CrashingTestModule", crashing_module) == []

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("scanner.url_input.requests.get", return_value=mock_resp):
        res = validate_url("http://localhost/missing-page")
        assert res["valid"] is True, f"Expected 404 to be valid reachable host, got {res}"


if __name__ == "__main__":
    print("Running ThreatForge offline module tests...\n")
    tests = [
        ("Non-destructive payloads check", test_non_destructive_payloads),
        ("check_cookie_flags (incl. secret redaction)", test_cookie_flags),
        ("check_clickjacking", test_clickjacking),
        ("check_csrf", test_csrf),
        ("check_command_injection (Unix + Windows WAMP)", test_command_injection_unix_and_windows),
        ("WAMP mysqli SQLi error signatures", test_wamp_mysqli_error_signatures),
        ("check_rate_limiting (SKIPPED - requires network)", lambda: None),
        ("reporter build_report (dedup + severity + risk score)", test_reporter_dedup_and_sorting),
        ("orchestrator resilience + HTTP 4xx validation", test_orchestrator_resilience_and_404),
    ]
    results = [run_test(name, fn) for name, fn in tests]
    print("\n" + "=" * 50)
    if all(results):
        print(f"ALL {len(results)} CHECKS PASSED")
        sys.exit(0)
    else:
        print("SOME CHECKS FAILED")
        sys.exit(1)
