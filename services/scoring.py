"""
Risk Score & Security Grade Engine
==================================
Computes a 0–100 risk score (higher = riskier), derives a letter grade
(A to F), and produces prioritized remediation guidance.
"""

# ── Tunable Scoring Constants ────────────────────────────────────────────────

POINTS_BY_SEVERITY = {
    "High": 15,
    "Medium": 6,
    "Low": 2,
}

MAX_POINTS_PER_TYPE = 30
MAX_RISK_SCORE = 100

GRADE_THRESHOLDS = [
    (10, "A", "Excellent"),
    (25, "B", "Good"),
    (45, "C", "Needs attention"),
    (65, "D", "Poor"),
    (100, "F", "Critical"),
]

# One-line remediation lookup for all 9 modules / finding types
FIX_SUGGESTIONS = {
    "SQL Injection": (
        "Use parameterized queries / prepared statements for all database access and never concatenate user input into SQL."
    ),
    "Cross-Site Scripting (XSS)": (
        "Contextually HTML-encode all user-supplied output and deploy a strict Content-Security-Policy."
    ),
    "Command Injection": (
        "Avoid passing user input to OS shells; use safe library APIs or argument arrays with strict allowlist validation."
    ),
    "Insecure Cookie Flags": (
        "Set HttpOnly, Secure (over HTTPS), and SameSite=Lax or Strict on all session and sensitive cookies."
    ),
    "Missing Security Header": (
        "Configure the web server to send Content-Security-Policy, X-Content-Type-Options: nosniff, HSTS, and Referrer-Policy."
    ),
    "Clickjacking": (
        "Send X-Frame-Options: DENY (or SAMEORIGIN) and a CSP frame-ancestors directive on all framing-sensitive pages."
    ),
    "Missing CSRF Token": (
        "Include a cryptographically random, per-session hidden anti-CSRF token in every state-changing POST form."
    ),
    "Weak or Empty CSRF Token": (
        "Generate anti-CSRF tokens using at least 128 bits (16+ hex bytes) of cryptographic randomness."
    ),
    "Open Directory Listing": (
        "Disable auto-indexing in the web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx)."
    ),
    "No Brute-Force Protection": (
        "Enforce rate-limiting (HTTP 429 / Retry-After), progressive delays, account lockout, or CAPTCHA on login forms."
    ),
}


def compute_risk(findings: list[dict]) -> dict:
    """
    Compute the overall risk score, letter grade, per-type point breakdown,
    and top 3 prioritized remediation actions from *findings*.

    Parameters
    ----------
    findings : list[dict]
        Deduplicated list of finding dicts.

    Returns
    -------
    dict
        {
            "risk_score": int (0..100),
            "grade": "A" | "B" | "C" | "D" | "F",
            "label": str,
            "breakdown": {finding_type: int},
            "by_severity": {"High": int, "Medium": int, "Low": int},
            "top_fixes": [
                {"type": str, "points": int, "fix": str},
                ...
            ],
        }
    """
    raw_by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}

    for f in findings:
        vtype = f.get("type", "Unknown")
        sev = f.get("severity", "Low")
        pts = POINTS_BY_SEVERITY.get(sev, 2)

        raw_by_type[vtype] = raw_by_type.get(vtype, 0) + pts
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity[sev] = 1

    # Cap points per finding type at MAX_POINTS_PER_TYPE (30)
    breakdown: dict[str, int] = {
        vtype: min(MAX_POINTS_PER_TYPE, total_pts)
        for vtype, total_pts in raw_by_type.items()
    }

    risk_score = min(MAX_RISK_SCORE, sum(breakdown.values()))

    grade = "F"
    label = "Critical"
    for max_score, g_letter, g_label in GRADE_THRESHOLDS:
        if risk_score <= max_score:
            grade = g_letter
            label = g_label
            break

    # Top 3 finding types contributing the most points
    sorted_types = sorted(
        breakdown.items(), key=lambda kv: (-kv[1], kv[0])
    )[:3]

    top_fixes = [
        {
            "type": vtype,
            "points": pts,
            "fix": FIX_SUGGESTIONS.get(
                vtype,
                "Review and remediate the affected endpoint according to OWASP guidance.",
            ),
        }
        for vtype, pts in sorted_types
    ]

    return {
        "risk_score": int(risk_score),
        "grade": grade,
        "label": label,
        "breakdown": breakdown,
        "by_severity": by_severity,
        "top_fixes": top_fixes,
    }

