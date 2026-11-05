"""
Vulnerability Reporter Module
==============================
Collects findings and produces a structured, deduplicated,
severity-sorted, and risk-scored vulnerability report.
"""

from datetime import datetime, timezone
from services.scoring import compute_risk

ALL_MODULES = [
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

_SEVERITY_RANK = {
    "High": 0,
    "Medium": 1,
    "Low": 2,
}


def build_report(
    target_url: str,
    findings: list[dict],
    modules_executed: list[str] | None = None,
    authenticated_scan: bool = False,
) -> dict:
    """
    Build a structured scan report including risk score, grade, and top fixes.

    Parameters
    ----------
    target_url : str
        The URL that was scanned.
    findings : list[dict]
        List of individual vulnerability findings.
    modules_executed : list[str] | None
        Optional list of module names executed by the orchestrator.
    authenticated_scan : bool
        True if a custom session cookie was supplied for this scan (the cookie
        value itself is never stored).

    Returns
    -------
    dict
        Structured report dictionary with deduplicated findings, severity counts,
        risk score (0..100), grade (A..F), label, breakdown, and top_fixes.
    """
    # 1. Deduplicate findings FIRST
    seen = set()
    unique_findings = []
    for f in findings:
        payload = f.get("payload", "")
        if payload == "N/A":
            key = (f["type"], f.get("field", ""), payload, f.get("detail", ""))
        else:
            key = (f["type"], f.get("field", ""), payload)

        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # 2. Sort findings by severity (High, Medium, Low), then by type
    unique_findings.sort(
        key=lambda f: (
            _SEVERITY_RANK.get(f.get("severity", "Low"), 99),
            f.get("type", ""),
        )
    )

    # 3. Compute summary and severity_counts from unique_findings
    summary: dict[str, int] = {}
    severity_counts: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}

    for f in unique_findings:
        vtype = f["type"]
        summary[vtype] = summary.get(vtype, 0) + 1

        sev = f.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts[sev] = 1

    # 4. Compute risk score, letter grade, breakdown, and top 3 fixes
    risk_data = compute_risk(unique_findings)

    # 5. Build modules_run (sorted union of the 9 module names + distinct finding types)
    base_modules = list(modules_executed) if modules_executed else list(ALL_MODULES)
    distinct_types = {f["type"] for f in unique_findings}
    modules_run = sorted(set(base_modules) | distinct_types)

    return {
        "target": target_url,
        "scan_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "authenticated_scan": bool(authenticated_scan),
        "total_findings": len(unique_findings),
        "summary": summary,
        "severity_counts": severity_counts,
        "risk_score": risk_data["risk_score"],
        "grade": risk_data["grade"],
        "label": risk_data["label"],
        "breakdown": risk_data["breakdown"],
        "top_fixes": risk_data["top_fixes"],
        "modules_run": modules_run,
        "findings": unique_findings,
    }
