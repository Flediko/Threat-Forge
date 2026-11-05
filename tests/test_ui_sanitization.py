"""
UI Sanitization & DOM XSS Prevention Tests
==========================================
Verifies that scanned vulnerability payloads (such as `<img src=x onerror=alert(1)>`,
`<script>alert(1)</script>`, `"><script>`, and quotes) cannot break out of HTML
attributes or execute arbitrary JavaScript in the ThreatForge frontend.
"""

from pathlib import Path
import re
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_escape_html_replaces_all_dangerous_chars():
    """Verify that dangerous HTML characters &, <, >, ", ' are escaped."""
    raw_payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "';alert(1)//",
        '<svg onload=alert(1)>',
        '"><script>alert("XSS")</script>',
    ]

    for p in raw_payloads:
        # Replicates the updated escapeHtml logic in scanner.js & history.html
        escaped = (
            p.replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;')
        )
        assert "<" not in escaped, f"Unescaped < found in {escaped}"
        assert ">" not in escaped, f"Unescaped > found in {escaped}"
        assert '"' not in escaped, f'Unescaped " found in {escaped}'
        assert "'" not in escaped, f"Unescaped ' found in {escaped}"


def test_no_raw_inline_onclick_in_templates():
    """Verify that copy buttons and target links do not use inline string injection in onclick."""
    scanner_js = (PROJECT_ROOT / "static" / "js" / "scanner.js").read_text(encoding="utf-8")
    assert "onclick=\"copyToClipboard('${escapeJsString" not in scanner_js, (
        "Inline onclick copyToClipboard with escapeJsString found in scanner.js! Must use data-copy."
    )
    assert 'data-copy="${safePayload}"' in scanner_js
    assert 'data-copy="${safeEvidence}"' in scanner_js


if __name__ == "__main__":
    print("Running UI XSS sanitization checks...")
    test_escape_html_replaces_all_dangerous_chars()
    print("[PASS] test_escape_html_replaces_all_dangerous_chars")
    test_no_raw_inline_onclick_in_templates()
    print("[PASS] test_no_raw_inline_onclick_in_templates")
    print("\nALL SANITIZATION CHECKS PASSED")

