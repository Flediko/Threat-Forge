"""
ThreatForge Test Target 2: Moderate Risk Web Application
========================================================
Port: 8002
Vulnerabilities:
  - Reflected Cross-Site Scripting (XSS) (Unescaped newsletter / comment reflection)
  - Missing CSRF Protection (Contact POST form lacks anti-CSRF token)
  - Insecure Cookie Flags (Missing SameSite and HttpOnly flags on non-session cookie)
  - Clickjacking Defenses (Missing X-Frame-Options)
  - Missing Security Headers (Missing CSP and HSTS; has X-Content-Type-Options: nosniff)
  - Protected Against: SQL Injection (parameterized queries) and OS Command Injection.

Run standalone:
    python sites_to_test/site2_moderate.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

PORT = 8002

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NexusTech Insights - Port 8002 (Moderate Risk Target)</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0b1329; color: #e2e8f0; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; background: #131e3a; border: 1px solid #f59e0b; border-radius: 10px; padding: 2rem; box-shadow: 0 10px 25px rgba(245,158,11,0.15); }
        .badge { display: inline-block; background: #f59e0b; color: #000; font-size: 0.75rem; font-weight: 700; padding: 0.3rem 0.6rem; border-radius: 4px; margin-bottom: 1rem; text-transform: uppercase; }
        h1 { font-size: 1.8rem; margin-bottom: 0.5rem; color: #fff; }
        p.subtitle { color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
        .card { background: #0b1329; border: 1px solid #1e293b; border-radius: 8px; padding: 1.25rem; }
        .card h2 { font-size: 1.1rem; color: #38bdf8; margin-bottom: 0.75rem; }
        label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.35rem; font-weight: 600; }
        input[type="text"], input[type="email"] { width: 100%; padding: 0.65rem 0.85rem; background: #131e3a; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; margin-bottom: 0.75rem; font-size: 0.9rem; }
        input[type="submit"] { background: #f59e0b; color: #000; border: none; padding: 0.65rem 1.25rem; border-radius: 6px; font-weight: 700; cursor: pointer; transition: background 0.2s; }
        input[type="submit"]:hover { background: #d97706; }
        .output-box { margin-top: 1.5rem; padding: 1rem; border-radius: 6px; font-size: 0.9rem; background: rgba(56,189,248,0.1); border: 1px solid #38bdf8; color: #bae6fd; }
    </style>
</head>
<body>
    <div class="container">
        <span class="badge">Target Vulnerability Profile: Moderate / Grade C</span>
        <h1>NexusTech Media &middot; Developer Blog (Port 8002)</h1>
        <p class="subtitle">Realistic corporate web application featuring partial defenses (parameterized SQL database) but remaining vulnerable to XSS, CSRF, and missing security headers.</p>

        <div class="grid">
            <!-- Form 1: Article Search (Reflected XSS, Safe against SQLi) -->
            <div class="card">
                <h2>1. Search Articles (Reflected XSS)</h2>
                <form action="/search" method="GET">
                    <label for="q">Keyword Search:</label>
                    <input type="text" id="q" name="q" placeholder="e.g. devops or <script>alert(1)</script>">
                    <input type="submit" value="Search Articles">
                </form>
            </div>

            <!-- Form 2: Reader Feedback (Missing CSRF Token) -->
            <div class="card">
                <h2>2. Reader Feedback (No Anti-CSRF Token)</h2>
                <form action="/feedback" method="POST">
                    <label for="email">Your Email:</label>
                    <input type="email" id="email" name="email" placeholder="dev@nexustech.io">
                    <label for="msg">Comments:</label>
                    <input type="text" id="msg" name="msg" placeholder="Share your thoughts...">
                    <input type="submit" value="Submit Feedback">
                </form>
            </div>
        </div>

        <!-- Dynamic Output Feed -->
        {DYNAMIC_CONTENT}
    </div>
</body>
</html>
"""


class ModerateTargetHandler(BaseHTTPRequestHandler):
    """HTTP handler with partial security controls and moderate vulnerabilities."""

    def log_message(self, format, *args):
        pass

    def _set_moderate_headers(self):
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Included good header
        self.send_header("X-Content-Type-Options", "nosniff")
        # Insecure cookie: non-session cookie missing SameSite and HttpOnly
        self.send_header("Set-Cookie", "theme_pref=obsidian; Path=/")
        # Intentionally Omitted:
        # - Content-Security-Policy
        # - Strict-Transport-Security
        # - X-Frame-Options

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        dynamic_content = ""
        if parsed.path == "/search" or "q" in params:
            query_val = params.get("q", [""])[0]
            if query_val:
                # Reflected XSS: User input reflected verbatim without sanitization
                # Safe against SQLi: Returns clean message, NO SQL syntax errors
                dynamic_content = f"""
                <div class="output-box">
                    <strong>Search Index Results:</strong> Found 3 matching articles for query: {query_val}
                </div>
                """

        html = HTML_TEMPLATE.replace("{DYNAMIC_CONTENT}", dynamic_content)
        self.send_response(200)
        self._set_moderate_headers()
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(post_body)
        parsed = urlparse(self.path)

        dynamic_content = ""
        if parsed.path == "/feedback" or "msg" in params:
            msg_val = params.get("msg", [""])[0]
            # Reflect msg unescaped (XSS in POST)
            dynamic_content = f"""
            <div class="output-box">
                <strong>Feedback Received:</strong> Thank you for your submission: {msg_val}
            </div>
            """

        html = HTML_TEMPLATE.replace("{DYNAMIC_CONTENT}", dynamic_content)
        self.send_response(200)
        self._set_moderate_headers()
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_server():
    server = ThreadedHTTPServer(("127.0.0.1", PORT), ModerateTargetHandler)
    print(f"[*] [Site 2 - Moderate Target] running at http://127.0.0.1:{PORT}/")
    return server


if __name__ == "__main__":
    server = start_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Site 2...")
        server.shutdown()

