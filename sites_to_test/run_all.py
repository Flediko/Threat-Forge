"""
ThreatForge Multi-Target Test Environment Launcher
==================================================
Starts all 4 distinct test applications concurrently on local ports:
  - Port 8001: Critical Risk Target (SQLi, XSS, CMDi, Insecure Cookies, Missing CSRF, No Headers)
  - Port 8002: Moderate Risk Target (XSS, Missing CSRF, Insecure Cookie Flags, Missing Headers)
  - Port 8003: Hardened Enterprise Target (Grade A - Full headers, CSRF tokens, Escaped, Rate-limited)
  - Port 8004: Open Directory Target (Apache Index of /backups listing)

Usage:
    python sites_to_test/run_all.py
"""

import sys
import threading
import time

try:
    from sites_to_test.site1_critical import start_server as start_site1
    from sites_to_test.site2_moderate import start_server as start_site2
    from sites_to_test.site3_hardened import start_server as start_site3
    from sites_to_test.site4_directory import start_server as start_site4
except ImportError:
    # When running directly inside sites_to_test folder
    from site1_critical import start_server as start_site1
    from site2_moderate import start_server as start_site2
    from site3_hardened import start_server as start_site3
    from site4_directory import start_server as start_site4


def main():
    print("=" * 72)
    print("  ThreatForge — Autonomous Test Target Environment Launcher")
    print("=" * 72)
    print("[*] Initializing test servers...\n")

    servers = []
    configs = [
        ("Site 1 (Critical / Grade F)", start_site1, 8001, "SQLi, XSS, CMDi, Insecure Cookies, No CSRF"),
        ("Site 2 (Moderate / Grade C)", start_site2, 8002, "Reflected XSS, Missing CSRF, Insecure Cookie Flags"),
        ("Site 3 (Hardened / Grade A)", start_site3, 8003, "Zero Vulnerabilities (CSP, HSTS, CSRF, Rate-Limited)"),
        ("Site 4 (Information Leak)", start_site4, 8004, "Open Directory Listing (Index of /backups)"),
    ]

    for name, starter, port, vulns in configs:
        try:
            srv = starter()
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            servers.append((name, srv, port, vulns))
        except OSError as exc:
            print(f"[!] Warning: Port {port} could not be bound ({exc}). Is it already running?")

    print("\n" + "=" * 72)
    print("  All 4 ThreatForge Test Targets Are ACTIVE and Listening:")
    print("=" * 72)
    for name, _, port, vulns in servers:
        print(f"  • http://127.0.0.1:{port}/  ->  {name}")
        print(f"    Vulnerabilities: {vulns}\n")

    print("-" * 72)
    print("  You can now scan any of these URLs inside ThreatForge UI or CLI.")
    print("  Press Ctrl+C at any time to terminate all test servers.")
    print("-" * 72)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping all test servers...")
        for _, srv, port, _ in servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        print("[✔] All test servers stopped cleanly.")


if __name__ == "__main__":
    main()

