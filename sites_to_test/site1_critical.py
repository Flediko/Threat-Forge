"""
ThreatForge Test Target 1: Critical Risk Web Application
========================================================
Port: 8001
Vulnerabilities:
  - SQL Injection (MySQL syntax error signatures on ' or UNION probes)
  - Reflected Cross-Site Scripting (XSS) (Unescaped search reflection)
  - OS Command Injection (Unix & Windows arithmetic/variable canary evaluation)
  - Insecure Cookie Flags (Missing HttpOnly, SameSite, Secure)
  - Missing CSRF Protection (POST forms lack anti-CSRF token)
  - Clickjacking (Missing X-Frame-Options & frame-ancestors)
  - Missing Security Headers (CSP, HSTS, X-Content-Type-Options, etc.)
  - No Rate Limiting (Allows continuous rapid login attempts)

Run standalone:
    python sites_to_test/site1_critical.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import re
from urllib.parse import parse_qs, urlparse


PORT = 8001

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>InsecureCorp Portal - Port 8001 (Critical Risk Target)</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0f172a; color: #f8fafc; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; background: #1e293b; border: 1px solid #ef4444; border-radius: 10px; padding: 2rem; box-shadow: 0 10px 25px rgba(239,68,68,0.2); }
        .badge { display: inline-block; background: #ef4444; color: #fff; font-size: 0.75rem; font-weight: 700; padding: 0.3rem 0.6rem; border-radius: 4px; margin-bottom: 1rem; text-transform: uppercase; }
        h1 { font-size: 1.8rem; margin-bottom: 0.5rem; color: #fff; }
        p.subtitle { color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
        .card { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 1.25rem; }
        .card h2 { font-size: 1.1rem; color: #38bdf8; margin-bottom: 0.75rem; }
        label { display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.35rem; font-weight: 600; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.65rem 0.85rem; background: #1e293b; border: 1px solid #475569; border-radius: 6px; color: #f8fafc; margin-bottom: 0.75rem; font-size: 0.9rem; }
        input[type="submit"] { background: #ef4444; color: #fff; border: none; padding: 0.65rem 1.25rem; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        input[type="submit"]:hover { background: #dc2626; }
        .output-box { margin-top: 1.5rem; padding: 1rem; border-radius: 6px; font-size: 0.9rem; }
        .error-box { background: rgba(239,68,68,0.15); border: 1px solid #ef4444; color: #fca5a5; }
        .success-box { background: rgba(56,189,248,0.15); border: 1px solid #38bdf8; color: #bae6fd; }
        pre { background: #000; padding: 0.75rem; border-radius: 4px; overflow-x: auto; margin-top: 0.5rem; color: #f87171; font-family: monospace; font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        <span class="badge">Target Vulnerability Profile: Critical / Grade F</span>
        <h1>InsecureCorp Enterprise Portal (Port 8001)</h1>
        <p class="subtitle">Simulated high-risk legacy web application intentionally vulnerable to SQLi, XSS, Command Injection, and CSRF for ThreatForge testing.</p>

        <div class="grid">
            <!-- Form 1: Product Catalog Search (SQLi + Reflected XSS) -->
            <div class="card">
                <h2>1. Catalog Search (SQLi &amp; XSS)</h2>
                <form action="/search" method="GET">
                    <label for="q">Search Database Product / SKU:</label>
                    <input type="text" id="q" name="q" value="" placeholder="e.g. laptop or ' OR '1'='1">
                    <input type="submit" value="Execute Query">
                </form>
            </div>

            <!-- Form 2: Server Health Diagnostics (Command Injection) -->
            <div class="card">
                <h2>2. Network Diagnostic (OS CMDi)</h2>
                <form action="/diagnostic" method="POST">
                    <label for="host">Target IP / Host to Ping:</label>
                    <input type="text" id="host" name="host" value="" placeholder="e.g. 127.0.0.1 or ;echo TF1337">
                    <input type="submit" value="Run Ping Probe">
                </form>
            </div>
        </div>

        <!-- Form 3: User Authentication (Insecure Cookie, Missing CSRF, No Rate Limit) -->
        <div class="card" style="margin-bottom:1.5rem;">
            <h2>3. Employee Access Gateway (No CSRF &middot; Insecure Session Cookie)</h2>
            <form action="/login" method="POST">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
                    <div>
                        <label for="username">Username / ID:</label>
                        <input type="text" id="username" name="username" placeholder="admin">
                    </div>
                    <div>
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" placeholder="admin123">
                    </div>
                </div>
                <input type="submit" value="Sign In to Gateway">
            </form>
        </div>

        <!-- Dynamic Output Feed -->
        {DYNAMIC_CONTENT}
    </div>
</body>
</html>
"""


class CriticalTargetHandler(BaseHTTPRequestHandler):
    """HTTP handler mimicking an unhardened, highly vulnerable web server."""

    def log_message(self, format, *args):
        # Suppress noisy standard request logging in test runs
        pass

    def _set_insecure_headers(self):
        """Intentionally omit all modern security headers and set insecure cookies."""
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Insecure cookie: Missing HttpOnly, missing SameSite, missing Secure
        self.send_header("Set-Cookie", "session_id=sess_vuln_99812; Path=/")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu) InsecureCorp/1.0")
        # Intentionally NO: Content-Security-Policy
        # Intentionally NO: X-Frame-Options
        # Intentionally NO: X-Content-Type-Options
        # Intentionally NO: Strict-Transport-Security
        # Intentionally NO: X-XSS-Protection
        # Intentionally NO: Referrer-Policy

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        dynamic_content = ""

        if parsed.path == "/search" or "q" in params or "query" in params:
            query_val = params.get("q", params.get("query", [""]))[0]

            # 1. Check for SQL Injection payloads
            sqli_indicators = ["'", '"', "OR", "UNION", "SELECT", "--", "/*", "1=1"]
            has_sqli = any(ind.lower() in query_val.lower() for ind in sqli_indicators)

            if has_sqli:
                dynamic_content = f"""
                <div class="output-box error-box">
                    <strong>[!] Database Exception Triggered:</strong>
                    <pre>Warning: mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{query_val}' at line 1 in /var/www/catalog.php on line 42</pre>
                </div>
                """
            elif query_val:
                # 2. Reflected XSS (unescaped reflection of user input)
                dynamic_content = f"""
                <div class="output-box success-box">
                    <strong>Search Results:</strong> 0 items found matching: {query_val}
                </div>
                """

        html = HTML_TEMPLATE.replace("{DYNAMIC_CONTENT}", dynamic_content)
        self.send_response(200)
        self._set_insecure_headers()
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        params = parse_qs(post_body)
        parsed = urlparse(self.path)

        dynamic_content = ""

        # Endpoint 1: Diagnostic Ping (Command Injection)
        if parsed.path == "/diagnostic" or "host" in params:
            host_val = params.get("host", ["127.0.0.1"])[0]

            # Evaluate ThreatForge arithmetic probe: TF$((7*191)) -> TF1337
            # Evaluate ThreatForge Windows probe: %OS% -> TFWINWindows_NT
            if "TF$((7*191))" in host_val or "7*191" in host_val:
                eval_output = "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.038 ms\nTF1337\n--- ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss"
            elif "%OS%" in host_val or "TFWIN" in host_val:
                eval_output = "Pinging 127.0.0.1 with 32 bytes of data:\nReply from 127.0.0.1: bytes=32 time<1ms TTL=128\nTFWINWindows_NT\nPing statistics for 127.0.0.1:\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss)"
            else:
                eval_output = f"PING {host_val} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.045 ms"

            dynamic_content = f"""
            <div class="output-box error-box">
                <strong>System Shell Output:</strong>
                <pre>{eval_output}</pre>
            </div>
            """

        # Endpoint 2: Authentication Gateway (SQLi in username/password + Reflected XSS)
        elif parsed.path == "/login" or "username" in params:
            u_val = params.get("username", [""])[0]
            p_val = params.get("password", [""])[0]

            # SQLi Check in login
            if any(ind in u_val or ind in p_val for ind in ("'", '"', "OR", "--")):
                dynamic_content = f"""
                <div class="output-box error-box">
                    <strong>Auth Backend Failure:</strong>
                    <pre>Warning: mysql_query(): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{u_val}' AND password='{p_val}'</pre>
                </div>
                """
            else:
                # Reflected reflection for XSS check
                dynamic_content = f"""
                <div class="output-box error-box">
                    Invalid credentials supplied for operator identity: {u_val}
                </div>
                """

        html = HTML_TEMPLATE.replace("{DYNAMIC_CONTENT}", dynamic_content)
        self.send_response(200)
        self._set_insecure_headers()
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread for concurrency during scanner probing."""
    daemon_threads = True
    allow_reuse_address = True


def start_server():
    server = ThreadedHTTPServer(("127.0.0.1", PORT), CriticalTargetHandler)
    print(f"[*] [Site 1 - Critical Target] running at http://127.0.0.1:{PORT}/")
    return server


if __name__ == "__main__":
    server = start_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Site 1...")
        server.shutdown()

