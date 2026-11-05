"""
Response Analyzer Module
========================
Analyses HTTP responses for signs of SQL Injection, XSS,
missing security headers, open directory listings, insecure cookie flags,
clickjacking, missing CSRF tokens, and OS command injection.
"""

import re

# ── SQL error signatures (case-insensitive, incl. WAMP MySQL/MariaDB/PHP) ────

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"warning:\s+mysql_",
    r"mysqli_sql_exception",
    r"mysqli::query",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"SQLSTATE\[",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"SQLite3::query",
    r"org\.postgresql\.util\.PSQLException",
    r"com\.mysql\.jdbc\.exceptions",
    r"supplied argument is not a valid MySQL",
    r"Syntax error.*in query expression",
]

_SQL_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# ── Required security headers (X-Frame-Options audited in check_clickjacking) ─

REQUIRED_HEADERS = {
    "Content-Security-Policy":   "Prevents XSS and data injection attacks.",
    "X-Content-Type-Options":    "Prevents MIME-type sniffing.",
    "Strict-Transport-Security": "Enforces HTTPS connections.",
    "X-XSS-Protection":         "Enables browser-level XSS filtering.",
    "Referrer-Policy":           "Controls referrer information leakage.",
}

# ── Open-directory signatures (Apache WAMP, Nginx, IIS) ──────────────────────

DIR_LISTING_PATTERNS = [
    r"Index of /",
    r"<title>Directory listing for",
    r"Parent Directory",
    r"\[To Parent Directory\]",
]

_DIR_RE = re.compile("|".join(DIR_LISTING_PATTERNS), re.IGNORECASE)

# ── Session cookie name indicators ───────────────────────────────────────────

SESSION_COOKIE_KEYWORDS = (
    "sess",
    "sid",
    "token",
    "auth",
    "jsessionid",
    "phpsessid",
)

# ── Recognized anti-CSRF hidden input names ──────────────────────────────────

CSRF_TOKEN_NAMES = (
    "csrf",
    "xsrf",
    "token",
    "authenticity_token",
    "_token",
    "nonce",
    "__requestverificationtoken",
    "user_token",
)


# ═══════════════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════════════

def check_sql_injection(injection_results: list[dict]) -> list[dict]:
    """
    Scan injection results for SQL error messages in the response body.

    Returns a list of finding dicts.
    """
    findings = []
    for res in injection_results:
        match = _SQL_RE.search(res["body"])
        if match:
            findings.append({
                "type": "SQL Injection",
                "severity": "High",
                "field": res["field"],
                "payload": res["payload"],
                "evidence": match.group()[:200],
                "detail": (
                    f"The payload '{res['payload']}' injected into the "
                    f"'{res['field']}' field triggered a database error, "
                    f"indicating a possible SQL injection vulnerability."
                ),
            })
    return findings


def check_xss(injection_results: list[dict]) -> list[dict]:
    """
    Check whether injected XSS payloads are reflected in the response body.
    """
    findings = []
    for res in injection_results:
        if res["payload"] in res["body"]:
            findings.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "field": res["field"],
                "payload": res["payload"],
                "evidence": res["payload"],
                "detail": (
                    f"The payload '{res['payload']}' was reflected unescaped "
                    f"in the server response for the '{res['field']}' field, "
                    f"indicating a possible reflected XSS vulnerability."
                ),
            })
    return findings


def check_security_headers(headers: dict) -> list[dict]:
    """
    Check for missing security headers.

    Parameters
    ----------
    headers : dict
        Response headers (case-insensitive dict from ``requests``).
    """
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, description in REQUIRED_HEADERS.items():
        if header.lower() not in lower_headers:
            findings.append({
                "type": "Missing Security Header",
                "severity": "Medium",
                "field": header,
                "payload": "N/A",
                "evidence": f"Header '{header}' is not present in the response.",
                "detail": description,
            })
    return findings


def check_open_directories(body: str, url: str) -> list[dict]:
    """
    Detect open directory listings in the response body.
    """
    findings = []
    match = _DIR_RE.search(body)
    if match:
        findings.append({
            "type": "Open Directory Listing",
            "severity": "Medium",
            "field": "N/A",
            "payload": "N/A",
            "evidence": match.group()[:200],
            "detail": (
                f"The page at '{url}' appears to expose a directory listing, "
                f"which may leak sensitive file names and paths."
            ),
        })
    return findings


def check_cookie_flags(set_cookie_headers: list[str], url: str) -> list[dict]:
    """
    Audit raw Set-Cookie header strings for missing or insecure attributes
    (HttpOnly, Secure, and SameSite).

    Important: Cookie values are stripped and NEVER included in ``evidence``
    or ``detail``—only the cookie name and attribute flags are recorded.
    """
    findings = []
    is_https = url.strip().lower().startswith("https")

    for raw_header in set_cookie_headers:
        if not raw_header or not raw_header.strip():
            continue

        parts = [part.strip() for part in raw_header.split(";") if part.strip()]
        if not parts:
            continue

        # Extract cookie name ONLY (never store the secret cookie value)
        name_value = parts[0]
        cookie_name = name_value.split("=", 1)[0].strip()
        if not cookie_name:
            continue

        raw_attrs = parts[1:]
        attr_map: dict[str, str] = {}
        sanitized_attrs: list[str] = []

        for attr in raw_attrs:
            if "=" in attr:
                k, v = attr.split("=", 1)
                k_clean = k.strip()
                v_clean = v.strip()
                attr_map[k_clean.lower()] = v_clean.lower()
                sanitized_attrs.append(f"{k_clean}={v_clean}")
            else:
                k_clean = attr.strip()
                attr_map[k_clean.lower()] = ""
                sanitized_attrs.append(k_clean)

        evidence_str = (
            "; ".join(sanitized_attrs) if sanitized_attrs else "No attributes set"
        )

        has_httponly = "httponly" in attr_map
        has_secure = "secure" in attr_map
        has_samesite = "samesite" in attr_map
        samesite_val = attr_map.get("samesite", "")

        # 1. Missing HttpOnly flag
        if not has_httponly:
            lower_name = cookie_name.lower()
            is_session_cookie = any(kw in lower_name for kw in SESSION_COOKIE_KEYWORDS)
            severity = "High" if is_session_cookie else "Medium"
            findings.append({
                "type": "Insecure Cookie Flags",
                "severity": severity,
                "field": cookie_name,
                "payload": "N/A",
                "evidence": evidence_str,
                "detail": (
                    f"Cookie '{cookie_name}' is missing the HttpOnly flag, "
                    f"allowing client-side scripts to read it during an XSS attack."
                ),
            })

        # 2. Missing Secure flag on an HTTPS URL
        if is_https and not has_secure:
            findings.append({
                "type": "Insecure Cookie Flags",
                "severity": "Medium",
                "field": cookie_name,
                "payload": "N/A",
                "evidence": evidence_str,
                "detail": (
                    f"Cookie '{cookie_name}' is missing the Secure flag over HTTPS, "
                    f"allowing it to be sent over unencrypted HTTP connections."
                ),
            })

        # 3. SameSite=None without Secure
        if has_samesite and samesite_val == "none" and not has_secure:
            findings.append({
                "type": "Insecure Cookie Flags",
                "severity": "Medium",
                "field": cookie_name,
                "payload": "N/A",
                "evidence": evidence_str,
                "detail": (
                    f"Cookie '{cookie_name}' uses SameSite=None without the Secure flag, "
                    f"exposing cross-site requests to unencrypted transmission."
                ),
            })

        # 4. Missing SameSite attribute
        if not has_samesite:
            findings.append({
                "type": "Insecure Cookie Flags",
                "severity": "Low",
                "field": cookie_name,
                "payload": "N/A",
                "evidence": evidence_str,
                "detail": (
                    f"Cookie '{cookie_name}' is missing the SameSite attribute, "
                    f"increasing risk of Cross-Site Request Forgery (CSRF)."
                ),
            })

    return findings


def check_clickjacking(headers: dict, url: str) -> list[dict]:
    """
    Check HTTP response headers for anti-clickjacking frame protections
    (``X-Frame-Options`` or CSP ``frame-ancestors``).
    """
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    xfo_raw = lower_headers.get("x-frame-options")
    csp_raw = lower_headers.get("content-security-policy", "")

    has_frame_ancestors = False
    if csp_raw:
        directives = [d.strip().lower() for d in csp_raw.split(";") if d.strip()]
        has_frame_ancestors = any(
            d == "frame-ancestors" or d.startswith("frame-ancestors ")
            for d in directives
        )

    has_xfo = xfo_raw is not None and xfo_raw.strip() != ""

    if not has_xfo and not has_frame_ancestors:
        findings.append({
            "type": "Clickjacking",
            "severity": "Medium",
            "field": "X-Frame-Options / frame-ancestors",
            "payload": "N/A",
            "evidence": "Neither 'X-Frame-Options' header nor CSP 'frame-ancestors' directive was found.",
            "detail": (
                f"The page at '{url}' lacks framing protections, allowing it to be "
                f"embedded in an attacker-controlled iframe for clickjacking attacks."
            ),
        })
        return findings

    if has_xfo:
        xfo_val = xfo_raw.strip().upper()
        if xfo_val not in ("DENY", "SAMEORIGIN"):
            findings.append({
                "type": "Clickjacking",
                "severity": "Low",
                "field": "X-Frame-Options",
                "payload": "N/A",
                "evidence": f"X-Frame-Options: {xfo_raw.strip()}",
                "detail": (
                    f"The page at '{url}' sets an obsolete or invalid X-Frame-Options "
                    f"value ('{xfo_raw.strip()}'); use 'DENY' or 'SAMEORIGIN' instead."
                ),
            })

    return findings


def check_csrf(forms: list[dict], page_url: str) -> list[dict]:
    """
    Passively audit extracted HTML POST forms for missing or weak anti-CSRF
    hidden token fields. Does not submit any form.
    """
    findings = []

    for form in forms:
        method = str(form.get("method", "get")).lower()
        if method != "post":
            continue

        action_url = form.get("action") or page_url
        inputs = form.get("inputs", [])
        input_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

        csrf_inputs = []
        for inp in inputs:
            inp_type = str(inp.get("type", "")).lower()
            inp_name = str(inp.get("name", "")).strip().lower()
            if inp_type == "hidden" and (
                inp_name in CSRF_TOKEN_NAMES
                or any(tok in inp_name for tok in CSRF_TOKEN_NAMES)
            ):
                csrf_inputs.append(inp)

        if not csrf_inputs:
            evidence_list = ", ".join(input_names) if input_names else "no named inputs"
            findings.append({
                "type": "Missing CSRF Token",
                "severity": "Medium",
                "field": action_url,
                "payload": "N/A",
                "evidence": f"Inputs found: [{evidence_list}]",
                "detail": (
                    f"POST form submitting to '{action_url}' has no hidden anti-CSRF "
                    f"token field, making state-changing requests vulnerable to CSRF."
                ),
            })
        else:
            for token_inp in csrf_inputs:
                token_name = token_inp.get("name", "token")
                token_val = str(token_inp.get("value", "") or "").strip()
                if len(token_val) < 8:
                    findings.append({
                        "type": "Weak or Empty CSRF Token",
                        "severity": "Low",
                        "field": action_url,
                        "payload": "N/A",
                        "evidence": (
                            f"Hidden token field '{token_name}' has length "
                            f"{len(token_val)} (< 8 chars)"
                        ),
                        "detail": (
                            f"POST form submitting to '{action_url}' contains a CSRF "
                            f"token field ('{token_name}') whose value is empty or "
                            f"shorter than 8 characters."
                        ),
                    })

    return findings


def check_command_injection(injection_results: list[dict]) -> list[dict]:
    """
    Check injection responses for evaluated OS command injection markers:
    - Unix shell arithmetic marker: ``"TF1337"`` without literal ``"TF$((7*191))"``
    - Windows cmd.exe marker: ``"TFWINWindows_NT"`` without literal ``"%OS%"``

    Evidence states which OS shell style matched along with the surrounding
    80 characters of the match.
    """
    findings = []
    unix_marker = "TF1337"
    unix_raw = "TF$((7*191))"

    win_marker = "TFWINWindows_NT"
    win_raw = "%OS%"

    for res in injection_results:
        body = res.get("body", "")
        matched_marker = None
        os_style = None

        if unix_marker in body and unix_raw not in body:
            matched_marker = unix_marker
            os_style = "Unix shell"
        elif win_marker in body and win_raw not in body:
            matched_marker = win_marker
            os_style = "Windows cmd"

        if matched_marker and os_style:
            idx = body.find(matched_marker)
            start = max(0, idx - 30)
            end = min(len(body), idx + len(matched_marker) + 30)
            snippet = body[start:end].strip()
            evidence = f"[{os_style}] {snippet}"[:80]

            findings.append({
                "type": "Command Injection",
                "severity": "High",
                "field": res["field"],
                "payload": res["payload"],
                "evidence": evidence,
                "detail": (
                    f"The command injection probe '{res['payload']}' in field "
                    f"'{res['field']}' produced the evaluated {os_style} marker "
                    f"'{matched_marker}', indicating server-side command execution."
                ),
            })

    return findings
