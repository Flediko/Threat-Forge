"""
Risk Score & Security Grade Unit Tests
======================================
Tests ``services.scoring.compute_risk`` and integration with
``scanner.reporter.build_report``.

Run with:
    python tests/test_scoring.py
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.reporter import build_report
from services.scoring import compute_risk


def run_test(name: str, fn) -> bool:
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


def test_zero_findings():
    """No findings -> risk_score 0, Grade A ('Excellent')."""
    res = compute_risk([])
    assert res["risk_score"] == 0
    assert res["grade"] == "A"
    assert res["label"] == "Excellent"
    assert res["top_fixes"] == []


def test_single_high_sqli():
    """One High SQLi -> 15 points, Grade B ('Good')."""
    findings = [
        {
            "type": "SQL Injection",
            "severity": "High",
            "field": "id",
            "payload": "' OR '1'='1",
            "evidence": "SQL syntax error",
            "detail": "SQLi",
        }
    ]
    res = compute_risk(findings)
    assert res["risk_score"] == 15
    assert res["grade"] == "B"
    assert res["label"] == "Good"
    assert len(res["top_fixes"]) == 1
    assert res["top_fixes"][0]["type"] == "SQL Injection"


def test_per_type_cap():
    """Six missing-header findings (6 * 6 = 36 raw) are capped at 30 points."""
    findings = [
        {
            "type": "Missing Security Header",
            "severity": "Medium",
            "field": f"Header-{i}",
            "payload": "N/A",
            "evidence": "Missing",
            "detail": "Missing header",
        }
        for i in range(6)
    ]
    res = compute_risk(findings)
    assert res["breakdown"]["Missing Security Header"] == 30
    assert res["risk_score"] == 30
    assert res["grade"] == "C"


def test_score_never_exceeds_100():
    """Many findings across multiple categories never exceed risk_score 100 (Grade F)."""
    categories = [
        ("SQL Injection", "High"),
        ("Cross-Site Scripting (XSS)", "High"),
        ("Command Injection", "High"),
        ("Insecure Cookie Flags", "High"),
        ("Missing Security Header", "Medium"),
        ("Clickjacking", "Medium"),
    ]
    findings = []
    for ctype, sev in categories:
        for i in range(5):
            findings.append(
                {
                    "type": ctype,
                    "severity": sev,
                    "field": f"field_{i}",
                    "payload": f"p_{i}",
                    "evidence": "ev",
                    "detail": f"detail_{i}",
                }
            )
    res = compute_risk(findings)
    assert res["risk_score"] == 100
    assert res["grade"] == "F"
    assert res["label"] == "Critical"
    assert len(res["top_fixes"]) == 3

    # Verify build_report integration
    report = build_report("http://localhost/dvwa", findings)
    assert report["risk_score"] == 100
    assert report["grade"] == "F"
    assert "top_fixes" in report


if __name__ == "__main__":
    print("Running ThreatForge risk scoring tests...\n")
    suite = [
        ("0 findings = 0 / Grade A", test_zero_findings),
        ("1 High SQLi = 15 / Grade B", test_single_high_sqli),
        ("Per-type cap at 30 points", test_per_type_cap),
        ("Score cap at 100 / Grade F + reporter integration", test_score_never_exceeds_100),
    ]
    results = [run_test(name, fn) for name, fn in suite]
    print("\n" + "=" * 50)
    if all(results):
        print(f"ALL {len(results)} SCORING CHECKS PASSED")
        sys.exit(0)
    else:
        print("SOME SCORING CHECKS FAILED")
        sys.exit(1)

