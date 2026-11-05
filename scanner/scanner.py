"""
Scanner Orchestrator
====================
Ties all 9 scanner modules together into a single ``run_scan`` entry-point.
Supports optional progress callbacks and optional session cookies (never stored
or logged) for scanning authenticated pages on DVWA / WAMP.
"""

from typing import Callable
import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .url_input import validate_url
from .form_extractor import extract_forms, get_page_html
from .payload_injector import (
    inject_payloads,
    SQL_PAYLOADS,
    XSS_PAYLOADS,
    CMDI_PAYLOADS,
)
from .response_analyzer import (
    check_sql_injection,
    check_xss,
    check_security_headers,
    check_open_directories,
    check_cookie_flags,
    check_clickjacking,
    check_csrf,
    check_command_injection,
)
from .bruteforce import check_rate_limiting
from .reporter import build_report

logger = logging.getLogger(__name__)

# ── Scanner constants & request caps ─────────────────────────────────────────

TIMEOUT = 30                # seconds – generous for slower targets
MAX_CMDI_REQUESTS = 60      # maximum total command-injection probes per scan
MAX_BRUTE_ATTEMPTS = 6      # maximum login probes per password form
BRUTE_DELAY = 0.3           # delay in seconds between login probes

MODULES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Open Directory Listing",
    "Missing Security Header",
    "Insecure Cookie Flags",
    "Clickjacking",
    "CSRF Protection",
    "Command Injection",
    "Brute-Force Protection",
]

SCAN_MODES = {
    "low": [
        "Missing Security Header",
        "Insecure Cookie Flags",
        "Clickjacking",
        "Open Directory Listing",
    ],
    "mid": [
        "Missing Security Header",
        "Insecure Cookie Flags",
        "Clickjacking",
        "Open Directory Listing",
        "CSRF Protection",
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Brute-Force Protection",
    ],
    "high": [
        "Missing Security Header",
        "Insecure Cookie Flags",
        "Clickjacking",
        "Open Directory Listing",
        "CSRF Protection",
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Command Injection",
        "Brute-Force Protection",
    ],
}


def _sql_inject_url_params(
    url: str, session: requests.Session | None = None
) -> list[dict]:
    """
    If the URL has query-string parameters (e.g. ?id=1), inject SQL payloads
    directly into each parameter and return raw result dicts compatible with
    ``response_analyzer.check_sql_injection``.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    http = session if session is not None else requests
    results = []
    for param_name in params:
        for payload in SQL_PAYLOADS:
            new_params = {k: v[0] if v else "" for k, v in params.items()}
            new_params[param_name] = payload
            new_query = urlencode(new_params)
            injected_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = http.get(injected_url, timeout=TIMEOUT, allow_redirects=True)
                results.append({
                    "payload": payload,
                    "field": f"URL param '{param_name}'",
                    "status_code": resp.status_code,
                    "body": resp.text,
                })
            except requests.RequestException:
                continue

    return results


def _xss_inject_url_params(
    url: str, session: requests.Session | None = None
) -> list[dict]:
    """
    Same as ``_sql_inject_url_params`` but for XSS payloads.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    http = session if session is not None else requests
    results = []
    for param_name in params:
        for payload in XSS_PAYLOADS:
            new_params = {k: v[0] if v else "" for k, v in params.items()}
            new_params[param_name] = payload
            new_query = urlencode(new_params)
            injected_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = http.get(injected_url, timeout=TIMEOUT, allow_redirects=True)
                results.append({
                    "payload": payload,
                    "field": f"URL param '{param_name}'",
                    "status_code": resp.status_code,
                    "body": resp.text,
                })
            except requests.RequestException:
                continue

    return results


def _cmdi_inject_url_params(
    url: str,
    max_requests: int = MAX_CMDI_REQUESTS,
    session: requests.Session | None = None,
) -> list[dict]:
    """
    If the URL has query-string parameters (e.g. ?host=127.0.0.1), inject safe
    Unix and Windows Command Injection probes into each parameter up to
    *max_requests*.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    http = session if session is not None else requests
    results = []
    requests_sent = 0
    for param_name in params:
        for payload in CMDI_PAYLOADS:
            if requests_sent >= max_requests:
                return results
            requests_sent += 1

            new_params = {k: v[0] if v else "" for k, v in params.items()}
            new_params[param_name] = payload
            new_query = urlencode(new_params)
            injected_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = http.get(injected_url, timeout=TIMEOUT, allow_redirects=True)
                results.append({
                    "payload": payload,
                    "field": f"URL param '{param_name}'",
                    "status_code": resp.status_code,
                    "body": resp.text,
                })
            except requests.RequestException:
                continue

    return results


def _run_module(module_name: str, func, *args, **kwargs) -> list[dict]:
    """
    Execute a single scanner check function inside a protective try/except
    block so that an unexpected failure in one module never crashes the scan.
    """
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        logger.warning("Module '%s' failed with error: %s", module_name, exc)
        return []


def _notify(progress_callback: Callable[[str], None] | None, label: str) -> None:
    """Safely invoke *progress_callback* if provided."""
    if progress_callback is not None:
        try:
            progress_callback(label)
        except Exception:
            pass


def run_scan(
    target_url: str,
    progress_callback: Callable[[str], None] | None = None,
    session_cookie: str | None = None,
    scan_mode: str = "high",
    enabled_modules: list[str] | None = None,
) -> dict:
    """
    Run a vulnerability scan against *target_url* with configurable scan mode
    ('low', 'mid', 'high') or specific enabled modules.

    Parameters
    ----------
    target_url : str
        Target URL to scan.
    progress_callback : Callable[[str], None] | None
        Optional callback invoked with status labels as each scan stage runs.
    session_cookie : str | None
        Optional raw Cookie header string for scanning pages behind a login.
    scan_mode : str
        Intensity mode: 'low' (passive recon), 'mid' (standard), or 'high' (deep full audit).
    enabled_modules : list[str] | None
        Optional explicit list of scanner module names to execute.

    Returns
    -------
    dict
        A structured report produced by ``reporter.build_report``.
    """
    # Configure a single requests.Session for the entire scan
    session = requests.Session()
    authenticated_scan = bool(session_cookie and session_cookie.strip())
    if authenticated_scan:
        clean_cookie = "".join(
            ch for ch in session_cookie.strip() if ord(ch) >= 32 and ord(ch) != 127
        )
        session.headers.update({"Cookie": clean_cookie})

    mode_key = (scan_mode or "high").strip().lower()
    if enabled_modules and len(enabled_modules) > 0:
        active_modules = set(enabled_modules)
    else:
        active_modules = set(SCAN_MODES.get(mode_key, MODULES))

    # 1. Validate URL & target policy ──────────────────────────────────────────
    _notify(progress_callback, "Validating target URL & security policy…")
    validation = validate_url(target_url, timeout=TIMEOUT, session=session)
    if not validation["valid"]:
        return {"error": validation["error"]}

    url = validation["url"]
    findings: list[dict] = []

    # 2. Fetch page & collect raw headers / Set-Cookie strings ─────────────────
    _notify(progress_callback, "Fetching page & collecting HTTP headers…")
    try:
        resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        html = resp.text
        headers = dict(resp.headers)

        set_cookie_headers: list[str] = []
        for hop in resp.history:
            if hop.raw and hasattr(hop.raw, "headers"):
                set_cookie_headers.extend(hop.raw.headers.getlist("Set-Cookie"))
        if resp.raw and hasattr(resp.raw, "headers"):
            set_cookie_headers.extend(resp.raw.headers.getlist("Set-Cookie"))
    except requests.RequestException as exc:
        return {"error": f"Failed to fetch {url}: {exc}"}

    # 3. Passive response audits (Headers, Clickjacking, Open Dirs, Cookies) ───
    _notify(progress_callback, "Auditing security headers, clickjacking & cookies…")
    if "Missing Security Header" in active_modules:
        findings.extend(
            _run_module("Missing Security Header", check_security_headers, headers)
        )
    if "Clickjacking" in active_modules:
        findings.extend(
            _run_module("Clickjacking", check_clickjacking, headers, url)
        )
    if "Open Directory Listing" in active_modules:
        findings.extend(
            _run_module("Open Directory Listing", check_open_directories, html, url)
        )
    if "Insecure Cookie Flags" in active_modules:
        findings.extend(
            _run_module("Insecure Cookie Flags", check_cookie_flags, set_cookie_headers, url)
        )

    # 4. URL-parameter injection (SQLi, XSS, Command Injection) ────────────────
    cmdi_requests_left = MAX_CMDI_REQUESTS if "Command Injection" in active_modules else 0

    if any(m in active_modules for m in ("SQL Injection", "Cross-Site Scripting (XSS)", "Command Injection")):
        _notify(progress_callback, "Testing URL query parameters (SQLi, XSS, CMDI)…")

    if "SQL Injection" in active_modules:
        try:
            sql_url_results = _sql_inject_url_params(url, session=session)
            findings.extend(check_sql_injection(sql_url_results))
        except Exception as exc:
            logger.warning("Module 'SQL Injection (URL params)' failed: %s", exc)

    if "Cross-Site Scripting (XSS)" in active_modules:
        try:
            xss_url_results = _xss_inject_url_params(url, session=session)
            findings.extend(check_xss(xss_url_results))
        except Exception as exc:
            logger.warning("Module 'Cross-Site Scripting (URL params)' failed: %s", exc)

    if "Command Injection" in active_modules:
        try:
            cmdi_url_results = _cmdi_inject_url_params(
                url, max_requests=cmdi_requests_left, session=session
            )
            cmdi_requests_left -= len(cmdi_url_results)
            findings.extend(check_command_injection(cmdi_url_results))
        except Exception as exc:
            logger.warning("Module 'Command Injection (URL params)' failed: %s", exc)

    # 5. Extract forms, passive CSRF audit & rate-limit check ──────────────────
    forms = []
    need_forms = any(m in active_modules for m in ("CSRF Protection", "Brute-Force Protection", "SQL Injection", "Cross-Site Scripting (XSS)", "Command Injection"))
    if need_forms:
        _notify(progress_callback, "Extracting HTML forms & auditing CSRF / rate limits…")
        try:
            forms = extract_forms(url, html=html, session=session)
        except Exception as exc:
            logger.warning("Form extraction failed: %s", exc)
            forms = []

    if "CSRF Protection" in active_modules:
        findings.extend(
            _run_module("CSRF Protection", check_csrf, forms, url)
        )

    if "Brute-Force Protection" in active_modules and not authenticated_scan:
        findings.extend(
            _run_module(
                "Brute-Force Protection",
                check_rate_limiting,
                forms,
                timeout=TIMEOUT,
                max_attempts=MAX_BRUTE_ATTEMPTS,
                delay=BRUTE_DELAY,
                session=session,
            )
        )

    # 6. Form-based payload injection (SQLi, XSS, Command Injection) ───────────
    if forms and any(m in active_modules for m in ("SQL Injection", "Cross-Site Scripting (XSS)", "Command Injection")):
        _notify(progress_callback, f"Testing {len(forms)} form(s) for SQLi, XSS & Command Injection…")
    for form in forms:
        if "SQL Injection" in active_modules:
            try:
                sql_results = inject_payloads(
                    form, SQL_PAYLOADS, timeout=TIMEOUT, session=session
                )
                findings.extend(check_sql_injection(sql_results))
            except Exception as exc:
                logger.warning("Module 'SQL Injection (form)' failed: %s", exc)

        if "Cross-Site Scripting (XSS)" in active_modules:
            try:
                xss_results = inject_payloads(
                    form, XSS_PAYLOADS, timeout=TIMEOUT, session=session
                )
                findings.extend(check_xss(xss_results))
            except Exception as exc:
                logger.warning("Module 'Cross-Site Scripting (form)' failed: %s", exc)

        if "Command Injection" in active_modules and cmdi_requests_left > 0:
            try:
                cmdi_results = inject_payloads(
                    form,
                    CMDI_PAYLOADS,
                    timeout=TIMEOUT,
                    max_requests=cmdi_requests_left,
                    session=session,
                )
                cmdi_requests_left -= len(cmdi_results)
                findings.extend(check_command_injection(cmdi_results))
            except Exception as exc:
                logger.warning("Module 'Command Injection (form)' failed: %s", exc)

    # 7. Build report ──────────────────────────────────────────────────────────
    _notify(progress_callback, "Compiling report & calculating risk score…")
    executed = [m for m in MODULES if m in active_modules]
    report = build_report(
        url,
        findings,
        modules_executed=executed,
        authenticated_scan=authenticated_scan,
    )
    report["scan_mode"] = mode_key
    return report
