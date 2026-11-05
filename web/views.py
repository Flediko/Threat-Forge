"""
ThreatForge Web Views
=====================
Handles authentication, scanning, history, reports, and admin operations.
"""

from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import io
import json
import time

from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from scanner.scanner import MODULES, run_scan
from services.activity import get_activity_events, log_event
from services.auth import (
    change_password,
    check_scan_rate_limit,
    login as auth_login,
    perform_admin_user_action,
    register_user,
)
from services.db import (
    delete_scan,
    delete_user,
    get_scan,
    get_user_by_id,
    init_db,
    insert_scan,
    list_all_scans,
    list_scans_for_user,
    list_users,
    update_user,
    utc_now_iso,
)
from services.pdf_report import build_pdf, make_pdf_filename
from services.target_policy import is_target_allowed

# Ensure tables exist on boot
init_db()


def _get_current_user(request):
    """Return the authenticated user dict or None."""
    uid = request.session.get("auth_user_id")
    if not uid:
        return None
    user = get_user_by_id(uid)
    if not user or not user.get("is_active", 1):
        request.session.pop("auth_user_id", None)
        return None
    return user


def landing_view(request):
    """Modern enterprise landing page for ThreatForge."""
    user = _get_current_user(request)
    all_scans = list_all_scans()
    total_scans = len(all_scans)
    avg_score = (
        round(sum(int(s.get("risk_score") or 0) for s in all_scans) / total_scans, 1)
        if total_scans
        else 14.2
    )

    return render(
        request,
        "landing.html",
        {
            "user": user,
            "modules": MODULES,
            "total_scans": total_scans,
            "avg_score": avg_score,
            "engine_count": len(MODULES),
        },
    )


def login_view(request):
    """Login and registration page."""
    current = _get_current_user(request)
    if current:
        return redirect("scan")

    login_error = None
    register_error = None
    register_success = None
    logout_success = "You have been securely signed out." if request.GET.get("logged_out") == "1" else None

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "login":
            ident = request.POST.get("ident", "").strip()
            password = request.POST.get("password", "")
            res = auth_login(ident, password)
            if res["ok"]:
                request.session["auth_user_id"] = res["user"]["id"]
                return redirect("scan")
            else:
                login_error = res["error"]

        elif action == "register":
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            password = request.POST.get("password", "")
            confirm = request.POST.get("confirm_password", "")

            if password != confirm:
                register_error = "Passwords do not match."
            else:
                res = register_user(username, email, password)
                if res["ok"]:
                    register_success = "Account created successfully! You can now sign in."
                else:
                    register_error = res["error"]

    return render(
        request,
        "login.html",
        {
            "login_error": login_error,
            "register_error": register_error,
            "register_success": register_success,
            "logout_success": logout_success,
        },
    )


def logout_view(request):
    """Logs out the user and clears session state."""
    user = _get_current_user(request)
    if user:
        log_event(
            action="logout",
            user_id=user["id"],
            username=user["username"],
            detail="User logged out",
        )
    request.session.flush()
    return redirect("/login/?logged_out=1")


def profile_view(request):
    """User profile, security settings, and overall audit performance summary."""
    user = _get_current_user(request)
    if not user:
        return redirect("login")

    scans = list_scans_for_user(user["id"])
    total_scans = len(scans)
    avg_score = 0
    best_score = 0
    worst_score = 0
    grade_rank = {"A": 1, "B": 2, "C": 3, "D": 4, "F": 5}
    best_grade = "A"
    worst_grade = "A"
    total_findings = sum(int(s.get("total_findings") or 0) for s in scans)
    total_high = sum(int(s.get("high_count") or 0) for s in scans)
    total_med = sum(int(s.get("medium_count") or 0) for s in scans)
    total_low = sum(int(s.get("low_count") or 0) for s in scans)

    grade_counts = Counter()
    target_summary_map = {}

    if total_scans > 0:
        scores = [int(s.get("risk_score") or 0) for s in scans]
        avg_score = round(sum(scores) / total_scans, 1)
        best_score = min(scores)
        worst_score = max(scores)
        grades = [str(s.get("grade") or "A") for s in scans]
        best_grade = min(grades, key=lambda g: grade_rank.get(g, 99))
        worst_grade = max(grades, key=lambda g: grade_rank.get(g, 0))

        for s in scans:
            grade_counts[str(s.get("grade") or "A")] += 1
            tgt = s["target"]
            if tgt not in target_summary_map:
                target_summary_map[tgt] = {
                    "target": tgt,
                    "count": 0,
                    "latest_date": str(s.get("started_at", ""))[:16],
                    "latest_grade": s.get("grade", "A"),
                    "latest_score": s.get("risk_score", 0),
                    "latest_id": s["id"],
                }
            target_summary_map[tgt]["count"] += 1

    target_summaries = list(target_summary_map.values())

    return render(
        request,
        "profile.html",
        {
            "user": user,
            "total_scans": total_scans,
            "avg_score": avg_score,
            "best_score": best_score,
            "worst_score": worst_score,
            "best_grade": best_grade,
            "worst_grade": worst_grade,
            "total_findings": total_findings,
            "total_high": total_high,
            "total_med": total_med,
            "total_low": total_low,
            "grade_counts": grade_counts,
            "target_summaries": target_summaries,
            "distinct_targets": list(target_summary_map.keys()),
        },
    )


@require_POST
def api_change_password(request):
    """JSON API to update account password."""
    user = _get_current_user(request)
    if not user:
        return JsonResponse({"ok": False, "error": "Authentication required."}, status=401)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        data = request.POST

    current_pwd = str(data.get("current_password", ""))
    new_pwd = str(data.get("new_password", ""))
    confirm_pwd = str(data.get("confirm_password", ""))

    if not current_pwd:
        return JsonResponse({"ok": False, "error": "Please enter your current password."})
    if new_pwd != confirm_pwd:
        return JsonResponse({"ok": False, "error": "New passwords do not match."})

    ok, msg = change_password(user["id"], current_pwd, new_pwd)
    if not ok:
        return JsonResponse({"ok": False, "error": msg})

    return JsonResponse({"ok": True, "message": msg})


def scan_view(request):
    """Main vulnerability scan interface."""
    user = _get_current_user(request)
    if not user:
        return redirect("login")

    recent_scans = list_scans_for_user(user["id"])[:8]

    return render(
        request,
        "scan.html",
        {
            "user": user,
            "modules": MODULES,
            "recent_scans": recent_scans,
        },
    )


@require_POST
def api_run_scan(request):
    """
    Asynchronous JSON API endpoint for executing a vulnerability scan.
    """
    user = _get_current_user(request)
    if not user:
        return JsonResponse({"ok": False, "error": "Authentication required."}, status=401)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        data = request.POST

    target_url = str(data.get("target_url", "")).strip()
    authorized = bool(data.get("authorized", False))
    session_cookie = data.get("session_cookie", "").strip() or None
    scan_mode = str(data.get("scan_mode", "high")).strip().lower()
    enabled_modules = data.get("enabled_modules")
    if not isinstance(enabled_modules, list):
        enabled_modules = None

    if not target_url:
        return JsonResponse({"ok": False, "error": "Please enter a target URL."})

    if not authorized:
        return JsonResponse(
            {"ok": False, "error": "You must confirm you are authorized to scan this target."}
        )

    # Check target policy
    allowed, policy_msg = is_target_allowed(target_url)
    if not allowed:
        return JsonResponse({"ok": False, "error": policy_msg})

    # Check rate limit (10 scans / hour)
    allowed_rate, rate_msg = check_scan_rate_limit(user["id"])
    if not allowed_rate:
        return JsonResponse({"ok": False, "error": rate_msg})

    started_iso = utc_now_iso()
    t0 = time.perf_counter()
    log_event(
        action="scan_started",
        user_id=user["id"],
        username=user["username"],
        detail=f"Scan started ({scan_mode.upper()} mode) for {target_url[:200]}",
    )

    # Execute scanner
    report = run_scan(
        target_url,
        session_cookie=session_cookie,
        scan_mode=scan_mode,
        enabled_modules=enabled_modules,
    )
    duration_sec = round(time.perf_counter() - t0, 2)

    if "error" in report:
        log_event(
            action="scan_failed",
            user_id=user["id"],
            username=user["username"],
            detail=f"Target: {target_url[:200]} | Error: {report['error']}",
        )
        return JsonResponse({"ok": False, "error": report["error"]})

    sev = report.get("severity_counts", {"High": 0, "Medium": 0, "Low": 0})
    scan_id = insert_scan(
        user_id=user["id"],
        target=report["target"],
        started_at=started_iso,
        duration_sec=duration_sec,
        risk_score=report["risk_score"],
        grade=report["grade"],
        total_findings=report["total_findings"],
        high_count=sev.get("High", 0),
        medium_count=sev.get("Medium", 0),
        low_count=sev.get("Low", 0),
        report_json=json.dumps(report),
        authorized_confirmed=1 if authorized else 0,
    )

    log_event(
        action="scan_finished",
        user_id=user["id"],
        username=user["username"],
        detail=f"Scan #{scan_id} finished: {report['target']} (Score={report['risk_score']}, Grade={report['grade']})",
    )

    # Fetch updated scan history for instant real-time UI refresh
    raw_recent = list_scans_for_user(user["id"])[:8]
    clean_recent = []
    for s in raw_recent:
        clean_recent.append({
            "id": s["id"],
            "target": s["target"],
            "started_at": s["started_at"],
            "duration_sec": s.get("duration_sec", 0),
            "risk_score": s.get("risk_score", 0),
            "grade": s.get("grade", "A"),
            "total_findings": s.get("total_findings", 0),
            "high_count": s.get("high_count", 0),
            "medium_count": s.get("medium_count", 0),
            "low_count": s.get("low_count", 0),
        })

    return JsonResponse(
        {
            "ok": True,
            "scan_id": scan_id,
            "duration_sec": duration_sec,
            "report": report,
            "recent_scans": clean_recent,
        }
    )


def history_view(request):
    """View scan history, trend analytics, and compare scans."""
    user = _get_current_user(request)
    if not user:
        return redirect("login")

    scans = list_scans_for_user(user["id"])
    total_scans = len(scans)

    avg_score = 0
    best_grade = "A"
    worst_grade = "F"
    scans_this_month = 0

    if total_scans > 0:
        scores = [int(s.get("risk_score") or 0) for s in scans]
        avg_score = round(sum(scores) / total_scans, 1)

        grade_rank = {"A": 1, "B": 2, "C": 3, "D": 4, "F": 5}
        grades = [str(s.get("grade") or "A") for s in scans]
        best_grade = min(grades, key=lambda g: grade_rank.get(g, 99))
        worst_grade = max(grades, key=lambda g: grade_rank.get(g, 0))

        cur_month = datetime.now(timezone.utc).strftime("%Y-%m")
        scans_this_month = sum(
            1 for s in scans if str(s.get("started_at", "")).startswith(cur_month)
        )

    # Distinct targets for dropdowns
    targets = sorted({s["target"] for s in scans})

    return render(
        request,
        "history.html",
        {
            "user": user,
            "scans": scans,
            "scans_json": json.dumps(scans),
            "total_scans": total_scans,
            "avg_score": avg_score,
            "best_grade": best_grade,
            "worst_grade": worst_grade,
            "scans_this_month": scans_this_month,
            "targets": targets,
        },
    )


def api_scan_detail(request, scan_id):
    """Return full report JSON for a scan owned by the user (or admin)."""
    user = _get_current_user(request)
    if not user:
        return JsonResponse({"ok": False, "error": "Unauthorized"}, status=401)

    is_admin = user.get("role") == "admin"
    scan = get_scan(scan_id, user_id=None if is_admin else user["id"])
    if not scan:
        return JsonResponse({"ok": False, "error": "Scan not found"}, status=404)

    try:
        rep = json.loads(scan["report_json"])
    except Exception:
        rep = {}

    return JsonResponse({"ok": True, "scan": scan, "report": rep})


@require_POST
def api_delete_scan(request, scan_id):
    """Delete a scan owned by the current user."""
    user = _get_current_user(request)
    if not user:
        return JsonResponse({"ok": False, "error": "Unauthorized"}, status=401)

    ok = delete_scan(scan_id, user_id=user["id"])
    if ok:
        log_event(
            action="scan_deleted",
            user_id=user["id"],
            username=user["username"],
            detail=f"Deleted scan #{scan_id}",
        )
        return JsonResponse({"ok": True})
    return JsonResponse({"ok": False, "error": "Scan not found or permission denied"}, status=404)


def download_pdf_view(request, scan_id):
    """Build and download the executive PDF vulnerability report."""
    user = _get_current_user(request)
    if not user:
        return redirect("login")

    is_admin = user.get("role") == "admin"
    scan = get_scan(scan_id, user_id=None if is_admin else user["id"])
    if not scan:
        return HttpResponseNotFound("Scan report not found.")

    try:
        rep = json.loads(scan["report_json"])
    except Exception:
        rep = {"target": scan.get("target", "target"), "findings": []}

    pdf_bytes = build_pdf(rep, generated_for=user["username"])
    filename = make_pdf_filename(scan.get("target", "target"), scan.get("started_at"))

    log_event(
        action="pdf_downloaded",
        user_id=user["id"],
        username=user["username"],
        detail=f"PDF downloaded for scan #{scan_id} ({scan.get('target', '')})",
    )

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def download_csv_view(request, scan_id):
    """Export findings of a scan as CSV."""
    user = _get_current_user(request)
    if not user:
        return redirect("login")

    is_admin = user.get("role") == "admin"
    scan = get_scan(scan_id, user_id=None if is_admin else user["id"])
    if not scan:
        return HttpResponseNotFound("Scan not found.")

    try:
        rep = json.loads(scan["report_json"])
        findings = rep.get("findings", [])
    except Exception:
        findings = []

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "severity", "field", "payload", "evidence", "detail"])
    for f in findings:
        writer.writerow(
            [
                f.get("type", ""),
                f.get("severity", ""),
                f.get("field", ""),
                f.get("payload", ""),
                f.get("evidence", ""),
                f.get("detail", ""),
            ]
        )

    response = HttpResponse(buf.getvalue().encode("utf-8"), content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="threatforge_findings_{scan_id}.csv"'
    return response


def admin_panel_view(request):
    """Administrator management panel."""
    admin = _get_current_user(request)
    if not admin or admin.get("role") != "admin":
        return HttpResponseForbidden("Access Denied: Administrator role required.")

    all_users = list_users()
    all_scans = list_all_scans()
    all_activity = get_activity_events(limit=500)

    now = datetime.now(timezone.utc)
    seven_days_ago = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    twenty_four_h_ago = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    today_prefix = now.strftime("%Y-%m-%d")

    total_users = len(all_users)
    active_7d = sum(
        1
        for u in all_users
        if u.get("last_login_at") and str(u["last_login_at"]) >= seven_days_ago
    )
    total_scans = len(all_scans)
    scans_today = sum(
        1
        for s in all_scans
        if str(s.get("started_at", "")).startswith(today_prefix)
    )
    avg_score = (
        round(sum(int(s.get("risk_score") or 0) for s in all_scans) / total_scans, 1)
        if total_scans
        else 0
    )
    failed_24h = sum(
        1
        for a in all_activity
        if a.get("action") == "login_failed"
        and str(a.get("created_at", "")) >= twenty_four_h_ago
    )

    grade_counts = Counter(str(s.get("grade") or "A") for s in all_scans)

    return render(
        request,
        "admin_panel.html",
        {
            "admin": admin,
            "users": all_users,
            "scans": all_scans,
            "activity": all_activity,
            "total_users": total_users,
            "active_7d": active_7d,
            "total_scans": total_scans,
            "scans_today": scans_today,
            "avg_score": avg_score,
            "failed_24h": failed_24h,
            "grade_counts": grade_counts,
        },
    )


@require_POST
def admin_user_action(request):
    """Handles admin actions on users (enable, disable, unlock, promote, demote, delete)."""
    admin = _get_current_user(request)
    if not admin or admin.get("role") != "admin":
        return JsonResponse({"ok": False, "error": "Forbidden"}, status=403)

    try:
        target_user_id = int(request.POST.get("user_id", 0))
    except (ValueError, TypeError):
        return JsonResponse({"ok": False, "error": "Invalid user ID."})

    action_type = request.POST.get("action_type", "")
    ok, msg = perform_admin_user_action(admin, target_user_id, action_type)
    if not ok:
        return JsonResponse({"ok": False, "error": msg})
    return JsonResponse({"ok": True, "message": msg})
