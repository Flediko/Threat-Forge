"""
ThreatForge Test Target 3: Fully Hardened Enterprise Application
================================================================
Port: 8003
Security Posture: Grade A (Risk Score: 0/100)
Protections & Defenses:
  - All 6 Required Security Headers Present:
      * Content-Security-Policy: default-src 'self'; frame-ancestors 'none';
      * Strict-Transport-Security: max-age=31536000; includeSubDomains
      * X-Content-Type-Options: nosniff
      * X-XSS-Protection: 1; mode=block
      * Referrer-Policy: strict-origin-when-cross-origin
      * X-Frame-Options: DENY
  - Robust Anti-CSRF Tokens on all POST forms
  - Hardened Session Cookies (HttpOnly; SameSite=Strict; Secure)
  - Full Output Sanitization (HTML escaping eliminates XSS reflections)
  - Parameterized Database Query Simulation (Zero SQLi errors)
  - Strict Input Whitelisting (Eliminates OS command execution)
  - Rate Limiting Defense (HTTP 429 Too Many Requests on brute-force attempts)

Run standalone:
    python sites_to_test/site3_hardened.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import html
import time
from urllib.parse import parse_qs, urlparse

PORT = 8003

# Tracks recent failed logins per client IP for rate limiting test
LOGIN_ATTEMPTS: dict[str, list[float]] = {}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VaultGuard Enterprise - Port 8003 (Hardened Target)</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #061e16; color: #ecfdf5; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; background: #064e3b; border: 1px solid #10b981; border-radius: 10px; padding: 2rem; box-shadow: 0 10px 25px rgba(16,185,129,0.2); }
        .badge { display: inline-block; background: #10b981; color: #022c22; font-size: 0.75rem; font-weight: 800; padding: 0.3rem 0.6rem; border-radius: 4px; margin-bottom: 1rem; text-transform: uppercase; }
        h1 { font-size: 1.8rem; margin-bottom: 0.5rem; color: #fff; }
        p.subtitle { color: #a7f3d0; font-size: 0.95rem; margin-bottom: 1.5rem; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
        .card { background: #022c22; border: 1px solid #059669; border-radius: 8px; padding: 1.25rem; }
        .card h2 { font-size: 1.1rem; color: #34d399; margin-bottom: 0.75rem; }
        label { display: block; font-size: 0.85rem; color: #6ee7b7; margin-bottom: 0.35rem; font-weight: 600; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.65rem 0.85rem; background: #064e3b; border: 1px solid #10b981; border-radius: 6px; color: #ecfdf5; margin-bottom: 0.75rem; font-size: 0.9rem; }
        input[type="submit"] { background: #10b981; color: #022c22; border: none; padding: 0.65rem 1.25rem; border-radius: 6px; font-weight: 700; cursor: pointer; transition: background 0.2s; }
        input[type="submit"]:hover { background: #34d399; }
        .output-box { margin-top: 1.5rem; padding: 1rem; border-radius: 6px; font-size: 0.9rem; background: rgba(16,185,129,0.2); border: 1px solid #10b981; color: #a7f3d0; }
        .defenses-list { list-style: none; margin-top: 1rem; font-size: 0.85rem; color: #a7f3d0; }
        .defenses-list li { margin-bottom: 0.35rem; display: flex; align-items: center; gap: 0.4rem; }
    </style>
</head>
<body>
    <div class="container">
        <span class="badge">Target Vulnerability Profile: Hardened / Grade A</span>
        <h1>VaultGuard Financial &middot; Zero-Trust Portal (Port 8003)</h1>
        <p class="subtitle">Fully protected application configured according to OWASP Top 10 recommendations and NIST hardening standards.</p>

        <div class="grid">
            <!-- Form 1: Safe Search (HTML Escaped, Prepared SQL) -->
            <div class="card">
                <h2>1. Asset Lookup (Escaped &amp; Parameterized)</h2>
                <form action="/search" method="GET">
                    <label for="q">Asset ID / Code:</label>
                    <input type="text" id="q" name="q" placeholder="e.g. SEC-9021">
                    <input type="submit" value="Search Database">
                </form>
            </div>

            <!-- Form 2: Login with Anti-CSRF & Rate Limiting -->
            <div class="card">
                <h2>2. SSO Gateway (Anti-CSRF &amp; Rate-Limited)</h2>
                <form action="/login" method="POST">
                    <!-- Strong 24-character CSRF Token -->
                    <input type="hidden" name="csrf_token" value="f7a83d91b2c4e56019a823c4">
                    <label for="user">Officer ID:</label>
                    <input type="text" id="user" name="user" placeholder="officer_01">
                    <label for="password">Security Key:</label>
                    <input type="password" id="password" name="password" placeholder="••••••••••••">
                    <input type="submit" value="Authenticate">
                </form>
            </div>
        </div>

        <div class="card">
            <h2>Active Defense Controls Matrix</h2>
            <ul class="defenses-list">
                <li>&#10004; Content-Security-Policy &amp; frame-ancestors 'none'</li>
                <li>&#10004; Strict-Transport-Security (HSTS) 1-Year Preload</li>
                <li>&#10004; X-Frame-Options: DENY (Zero clickjacking risk)</li>
                <li>&#10004; X-Content-Type-Options: nosniff</li>
                <li>&#10004; HttpOnly; SameSite=Strict; Secure Session Cookies</li>
                <li>&#10004; Automated Brute-Force Rate Limiting (HTTP 429 Throttle)</li>
            </ul>
        </div>

        <!-- Dynamic Output Feed -->
        {DYNAMIC_CONTENT}
    </div>
</body>
</html>
"""


class HardenedTargetHandler(BaseHTTPRequestHandler):
    """HTTP handler fully hardened against all ThreatForge vulnerability checks."""

    def log_message(self, format, *args):
        pass

    def _set_hardened_headers(self):
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Full Security Header Suite
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none'")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        # Hardened Cookie
        self.send_header(
            "Set-Cookie",
            "vault_session=auth_token_84719203; Path=/; HttpOnly; SameSite=Strict; Secure",
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        dynamic_content = ""
        if parsed.path == "/search" or "q" in params:
            raw_q = params.get("q", [""])[0]
            if raw_q:
                # Safe HTML escaping prevents XSS; clean response prevents SQLi errors
                safe_q = html.escape(raw_q)
                dynamic_content = f"""
                <div class="output-box">
                    <strong>Asset Search:</strong> Zero records matched query: <code>{safe_q}</code>
                </div>
                """

        html_body = HTML_TEMPLATE.replace("{DYNAMIC_CONTENT}", dynamic_content)
        self.send_response(200)
        self._set_hardened_headers()
        self.end_headers()
        self.wfile.write(html_body.encode("utf-8"))

    def do_POST(self):
        client_ip = self.client_address[0]
        now = time.time()

        # Check rate-limiting on login endpoint
        attempts = LOGIN_ATTEMPTS.get(client_ip, [])
        # Keep attempts within last 10 seconds
        recent = [t for t in attempts if now - t < 10.0]
        recent.append(now)
        LOGIN_ATTEMPTS[client_ip] = recent

        # Trigger 429 Too Many Requests if > 3 rapid requests sent
        if len(recent) > 3:
            self.send_response(429)
            self._set_hardened_headers()
            self.send_header("Retry-After", "5")
            self.end_headers()
            self.wfile.write(b"<h1>429 Too Many Requests</h1><p>Rate limit exceeded.</p>")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(post_body)

        user_val = params.get("user", [""])[0]
        safe_user = html.escape(user_val)

        dynamic_content = f"""
        <div class="output-box">
            Authentication rejected: Invalid identity token for <code>{safe_user}</code>.
        </div>
        """

        html_body = HTML_TEMPLATE.replace("{DYNAMIC_CONTENT}", dynamic_content)
        self.send_response(200)
        self._set_hardened_headers()
        self.end_headers()
        self.wfile.write(html_body.encode("utf-8"))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_server():
    server = ThreadedHTTPServer(("127.0.0.1", PORT), HardenedTargetHandler)
    print(f"[*] [Site 3 - Hardened Target] running at http://127.0.0.1:{PORT}/")
    return server


if __name__ == "__main__":
    server = start_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Site 3...")
        server.shutdown()

