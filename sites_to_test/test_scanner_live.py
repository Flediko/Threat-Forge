"""
Live Scanner Integration Test Against All 4 Test Targets
=========================================================
Runs ThreatForge's live ``scanner.scanner.run_scan`` against the 4 local test sites
and asserts that findings and risk grades match expected security profiles:

  - Site 1 (Port 8001): Critical Risk (SQLi + XSS + CMDi + Headers + CSRF) -> Grade F / D
  - Site 2 (Port 8002): Moderate Risk (XSS + CSRF + Cookies) -> Grade C
  - Site 3 (Port 8003): Hardened Fortress (Zero vulnerabilities) -> Grade A
  - Site 4 (Port 8004): Information Leak (Open Directory Listing) -> Detects Index of /

Run:
    python sites_to_test/test_scanner_live.py
"""

from pathlib import Path
import sys
import threading
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scanner import run_scan
from sites_to_test.site1_critical import start_server as start_site1
from sites_to_test.site2_moderate import start_server as start_site2
from sites_to_test.site3_hardened import start_server as start_site3
from sites_to_test.site4_directory import start_server as start_site4


def start_all_background():
    """Start all 4 servers in daemon threads if not already started."""
    servers = []
    starters = [
        ("Site 1", start_site1, 8001),
        ("Site 2", start_site2, 8002),
        ("Site 3", start_site3, 8003),
        ("Site 4", start_site4, 8004),
    ]
    for name, starter, port in starters:
        try:
            srv = starter()
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            servers.append(srv)
        except OSError:
            # Port already bound / running
            pass
    time.sleep(0.5)
    return servers


def main():
    print("=" * 72)
    print("  ThreatForge Automated Live Multi-Target Validation Suite")
    print("=" * 72)

    servers = start_all_background()

    targets = [
        ("http://127.0.0.1:8001/", "Site 1 (Critical / Full Exploit Suite)", ["SQL Injection", "Cross-Site Scripting (XSS)", "Command Injection", "Missing Security Header", "Clickjacking"]),
        ("http://127.0.0.1:8002/", "Site 2 (Moderate / XSS + CSRF)", ["Cross-Site Scripting (XSS)", "Missing CSRF Token"]),
        ("http://127.0.0.1:8003/", "Site 3 (Hardened / Zero Trust)", []),
        ("http://127.0.0.1:8004/", "Site 4 (Open Directory Listing)", ["Open Directory Listing"]),
    ]

    results = []

    for url, desc, expected_types in targets:
        print(f"\n[+] Scanning {desc} at {url}...")
        report = run_scan(url, scan_mode="high")
        findings = report.get("findings", [])
        score = report.get("risk_score", 0)
        grade = report.get("grade", "N/A")
        found_types = {f.get("type") for f in findings}

        print(f"    --> Score: {score}/100 | Grade: {grade} | Total Findings: {len(findings)}")
        print(f"    --> Types Detected: {sorted(list(found_types)) if found_types else 'None (Clean)'}")

        # Assert expectations
        matched_expected = all(exp in found_types for exp in expected_types)
        if desc.startswith("Site 3"):
            passed = len(findings) == 0 and score == 0 and grade == "A"
        else:
            passed = matched_expected and len(findings) > 0

        status = "[PASS]" if passed else "[FAIL]"
        results.append((status, desc, score, grade, len(findings)))

    print("\n" + "=" * 72)
    print("  Live Multi-Target Scanner Results Matrix:")
    print("=" * 72)
    for status, desc, score, grade, count in results:
        print(f"  {status} {desc.ljust(42)} Score: {str(score).rjust(3)} | Grade: {grade} | Findings: {count}")
    print("=" * 72)

    # Clean up servers
    for s in servers:
        try:
            s.shutdown()
        except Exception:
            pass

    all_passed = all(r[0] == "[PASS]" for r in results)
    if all_passed:
        print("\n[✔] ALL LIVE SCANS PASSED EXPECTATIONS SUCCESSFULLY!")
        return 0
    else:
        print("\n[!] SOME SCANS DID NOT MATCH EXPECTATIONS.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

