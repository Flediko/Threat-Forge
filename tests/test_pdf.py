"""
PDF Report Generator Unit Tests
===============================
Tests ``services.pdf_report.build_pdf`` against:
  (a) an empty report (zero findings)
  (b) a report with unescaped XSS payload text ``<script>alert(1)</script>``
  (c) a large report with 300 findings

Asserts each returns valid PDF bytes starting with ``b"%PDF"``.

Run with:
    python tests/test_pdf.py
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.reporter import build_report
from services.pdf_report import build_pdf


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


def test_empty_report_pdf():
    """(a) Empty report with zero findings generates valid PDF bytes."""
    rep = build_report("http://localhost/dvwa/", [])
    pdf_bytes = build_pdf(rep, generated_for="alice_tester")
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF"), "Output must start with %PDF header"
    assert len(pdf_bytes) > 200


def test_xss_payload_report_pdf():
    """(b) Report containing <script>alert(1)</script> escapes markup cleanly."""
    findings = [
        {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "field": "name",
            "payload": '<script>alert(1)</script><img src=x onerror=alert("XSS")>',
            "evidence": '<script>alert(1)</script> & "quotes" <unclosed',
            "detail": 'Reflected <script>alert(1)</script> payload in response.',
        }
    ]
    rep = build_report("http://localhost/dvwa/vulnerabilities/xss_r/", findings)
    pdf_bytes = build_pdf(rep, generated_for="alice_tester")
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


def test_large_300_findings_report_pdf():
    """(c) Report with 300 findings paginates without crashing."""
    findings = [
        {
            "type": "SQL Injection" if i % 3 == 0 else ("Missing Security Header" if i % 3 == 1 else "Insecure Cookie Flags"),
            "severity": "High" if i % 3 == 0 else ("Medium" if i % 3 == 1 else "Low"),
            "field": f"param_{i}",
            "payload": f"' OR '{i}'='{i}" if i % 3 == 0 else "N/A",
            "evidence": f"Evidence snippet #{i} " + ("X" * 280),
            "detail": f"Synthetic finding #{i} for multi-page stress testing.",
        }
        for i in range(300)
    ]
    rep = build_report("http://localhost/dvwa/", findings)
    assert len(rep["findings"]) == 300
    pdf_bytes = build_pdf(rep, generated_for="stress_tester")
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


if __name__ == "__main__":
    print("Running ThreatForge PDF report generator tests...\n")
    suite = [
        ("(a) Empty report PDF generation", test_empty_report_pdf),
        ("(b) XSS <script> payload escaping in PDF", test_xss_payload_report_pdf),
        ("(c) 300-finding multi-page PDF stress test", test_large_300_findings_report_pdf),
    ]
    results = [run_test(name, fn) for name, fn in suite]
    print("\n" + "=" * 50)
    if all(results):
        print(f"ALL {len(results)} PDF CHECKS PASSED")
        sys.exit(0)
    else:
        print("SOME PDF CHECKS FAILED")
        sys.exit(1)

