"""
ThreatForge Test Target 4: Open Directory Listing & Legacy Storage
==================================================================
Port: 8004
Vulnerabilities:
  - Open Directory Listing (Index of / exposing server directory structure)
  - Information Disclosure (Exposes database backups and configuration dumps)
  - Missing Security Headers (No CSP, No X-Frame-Options, No HSTS)

Run standalone:
    python sites_to_test/site4_directory.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

PORT = 8004

DIRECTORY_HTML = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /backups</title>
  <style>
    body { font-family: monospace; padding: 2rem; background: #fff; color: #000; }
    h1 { border-bottom: 1px solid #ccc; padding-bottom: 0.5rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 0.35rem 0.5rem; font-size: 0.95rem; }
    a { text-decoration: none; color: #0000ee; font-weight: bold; }
    a:hover { text-decoration: underline; }
    address { margin-top: 1.5rem; border-top: 1px solid #ccc; padding-top: 0.5rem; font-size: 0.85rem; color: #555; }
  </style>
 </head>
 <body>
<h1>Index of /backups</h1>
<table>
  <tr><th>Icon</th><th>Name</th><th>Last modified</th><th>Size</th><th>Description</th></tr>
  <tr><td colspan="5"><hr></td></tr>
  <tr><td>📁</td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td>-</td><td>&nbsp;</td></tr>
  <tr><td>📄</td><td><a href="mysql_dump_2026.sql.gz">mysql_dump_2026.sql.gz</a></td><td>2026-03-14 09:12</td><td>142M</td><td>Full Production Database Dump</td></tr>
  <tr><td>📄</td><td><a href="wp-config.php.bak">wp-config.php.bak</a></td><td>2026-02-18 14:05</td><td>4.2K</td><td>WordPress DB Credentials</td></tr>
  <tr><td>📄</td><td><a href="admin_vpn_keys.zip">admin_vpn_keys.zip</a></td><td>2026-01-02 11:40</td><td>890K</td><td>OpenVPN Private Certificates</td></tr>
  <tr><td>📄</td><td><a href="customers_pii_export.csv">customers_pii_export.csv</a></td><td>2026-04-20 16:30</td><td>28M</td><td>Stripe Customer Billing PII</td></tr>
  <tr><td colspan="5"><hr></td></tr>
</table>
<address>Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.2 Server at 127.0.0.1 Port 8004</address>
</body>
</html>
"""


class DirectoryListingHandler(BaseHTTPRequestHandler):
    """HTTP handler exposing simulated Apache open directory listings."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.52 (Win64) OpenSSL/1.1.1m")
        # Intentionally no security headers
        self.end_headers()
        self.wfile.write(DIRECTORY_HTML.encode("utf-8"))


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_server():
    server = ThreadedHTTPServer(("127.0.0.1", PORT), DirectoryListingHandler)
    print(f"[*] [Site 4 - Open Directory] running at http://127.0.0.1:{PORT}/")
    return server


if __name__ == "__main__":
    server = start_server()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down Site 4...")
        server.shutdown()

