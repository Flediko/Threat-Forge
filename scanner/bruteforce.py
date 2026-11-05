"""
Brute-Force / Rate-Limit Protection Detector
============================================
Checks whether login forms implement rate-limiting, account lockout,
or CAPTCHA challenges after a small, bounded number of failed attempts
using random dummy strings (never real wordlists).
"""

import secrets
import time
import requests

PROTECTION_KEYWORDS = (
    "too many",
    "locked",
    "try again later",
    "captcha",
    "recaptcha",
    "hcaptcha",
    "rate limit",
    "temporarily",
)

USERNAME_FIELD_HINTS = (
    "user",
    "uname",
    "login",
    "email",
    "account",
    "id",
)


def _has_protection_signs(status_code: int, headers: dict, body: str) -> bool:
    """
    Return True if the HTTP response indicates throttling, lockout, or CAPTCHA.
    """
    if status_code == 429:
        return True

    lower_headers = {k.lower(): v for k, v in headers.items()}
    if "retry-after" in lower_headers:
        return True

    lower_body = (body or "").lower()
    return any(keyword in lower_body for keyword in PROTECTION_KEYWORDS)


def check_rate_limiting(
    forms: list[dict],
    timeout: int = 30,
    max_attempts: int = 6,
    delay: float = 0.3,
    session: requests.Session | None = None,
) -> list[dict]:
    """
    Test login forms (forms containing a ``password`` input) with a small,
    strictly bounded number of random dummy login requests to observe whether
    rate-limiting or lockout protections are active.
    """
    findings = []
    http = session if session is not None else requests

    for form in forms:
        inputs = form.get("inputs", [])
        has_password_field = any(
            str(inp.get("type", "")).lower() == "password" for inp in inputs
        )
        if not has_password_field:
            continue

        action = form.get("action", "")
        method = str(form.get("method", "post")).lower()
        statuses: list[int] = []
        protection_observed = False

        # Hard cap: never loop beyond max_attempts
        for attempt_idx in range(max_attempts):
            if attempt_idx > 0 and delay > 0:
                time.sleep(delay)

            random_password = f"tf_probe_{secrets.token_hex(6)}"
            data = {}
            for inp in inputs:
                name = inp.get("name")
                if not name:
                    continue
                inp_type = str(inp.get("type", "text")).lower()
                lower_name = name.lower()

                if inp_type == "password":
                    data[name] = random_password
                elif inp_type in ("text", "email") and any(
                    hint in lower_name for hint in USERNAME_FIELD_HINTS
                ):
                    data[name] = "tf_test_user"
                else:
                    data[name] = inp.get("value") or "tf_test_user"

            try:
                if method == "post":
                    resp = http.post(
                        action, data=data, timeout=timeout, allow_redirects=True
                    )
                else:
                    resp = http.get(
                        action, params=data, timeout=timeout, allow_redirects=True
                    )

                statuses.append(resp.status_code)
                if _has_protection_signs(
                    resp.status_code, dict(resp.headers), resp.text
                ):
                    protection_observed = True
                    break
            except requests.RequestException:
                continue

        if statuses and not protection_observed:
            findings.append({
                "type": "No Brute-Force Protection",
                "severity": "Medium",
                "field": action,
                "payload": "N/A",
                "evidence": (
                    f"{len(statuses)} attempts, statuses: {statuses}, "
                    f"no throttling observed"
                ),
                "detail": (
                    f"Observation (not a compromise): Login form at '{action}' "
                    f"accepted {len(statuses)} consecutive failed login probes "
                    f"without triggering HTTP 429, Retry-After, lockout messages, "
                    f"or CAPTCHA challenges."
                ),
            })

    return findings
