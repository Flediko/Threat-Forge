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
import secrets
import smtplib
import time
import zipfile

from django.conf import settings
from django.core import signing
from django.core.mail import send_mail
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from scanner.scanner import MODULES, run_scan
from services.activity import get_activity_events, log_event
from services.auth import (
    change_password,
    check_scan_rate_limit,
    login as auth_login,
    perform_admin_user_action,
    register_user,
    hash_password,
    validate_user_identity,
)
from services.db import (
    delete_scan,
    delete_user,
    get_scan,
    get_user_by_id,
    get_user_by_email,
    get_user_by_username,
    get_conn,
    finish_scan_activity,
    init_db,
    insert_scan,
    list_all_scans,
    list_scans_for_user,
    list_scan_activity,
    list_users,
    start_scan_activity,
    update_scan_activity,
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
    if user and user.get("role") == "admin":
        return redirect("admin_panel")
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
        return redirect("admin_panel" if current.get("role") == "admin" else "scan")

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
                return redirect("admin_panel" if res["user"].get("role") == "admin" else "scan")
            else:
                login_error = res["error"]

        elif action == "register":
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            password = request.POST.get("password", "")
            confirm = request.POST.get("confirm_password", "")

            if request.POST.get("agree_terms") != "on":
                register_error = "Please agree to the Terms of Use before creating an account."
            elif password != confirm:
                register_error = "Passwords do not match."
            else:
                res = register_user(username, email, password, terms_version="1.0")
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


def terms_view(request):
    return render(request, "terms.html")


def forgot_password_view(request):
    message = None
    error = None
    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        user = get_user_by_email(email) if email else None
        if user and user.get("is_active", 1):
            token = signing.dumps(
                {"user_id": user["id"], "password_hash": user["password_hash"]},
                salt="threatforge.password-reset",
            )
            reset_path = reverse("reset_password", kwargs={"token": token})
            reset_url = request.build_absolute_uri(reset_path)
            try:
                send_mail(
                    "Reset your ThreatForge password",
                    f"Hello {user['username']},\n\nUse this link within one hour to reset your password:\n{reset_url}\n\nIf you did not request this, you can ignore this message.",
                    None,
                    [user["email"]],
                    fail_silently=False,
                )
                log_event("password_reset_requested", user["id"], user["username"], "Password reset email sent")
            except (OSError, smtplib.SMTPException):
                log_event("password_reset_email_failed", user["id"], user["username"], "Password reset email delivery failed")
        message = "If an active account matches that email, we’ve sent a password reset link. Check your inbox."
        if settings.EMAIL_BACKEND.endswith("console.EmailBackend"):
            message += " In local development, reset links appear in the server output."
    return render(request, "forgot_password.html", {"message": message, "error": error})


def reset_password_view(request, token):
    error = None
    success = False
    user = None
    try:
        payload = signing.loads(token, salt="threatforge.password-reset", max_age=3600)
        user = get_user_by_id(int(payload["user_id"]))
        if not user or not user.get("is_active", 1) or not secrets.compare_digest(
            str(user.get("password_hash", "")), str(payload.get("password_hash", ""))
        ):
            user = None
    except (signing.BadSignature, signing.SignatureExpired, KeyError, TypeError, ValueError):
        user = None

    valid_link = user is not None
    if not user:
        error = "This password reset link is invalid or has expired. Request a new link to continue."
    elif request.method == "POST":
        password = request.POST.get("password", "")
        confirmation = request.POST.get("confirm_password", "")
        if len(password) < 10 or not any(char.isalpha() for char in password) or not any(char.isdigit() for char in password):
            error = "Use at least 10 characters with at least one letter and one digit."
        elif password != confirmation:
            error = "The passwords do not match."
        else:
            password_hash, salt = hash_password(password)
            update_user(user["id"], password_hash=password_hash, salt=salt, failed_logins=0, locked_until=None)
            log_event("password_reset_completed", user["id"], user["username"], "Password reset completed")
            success = True
            valid_link = False
            user = None
    return render(request, "reset_password.html", {"error": error, "success": success, "valid_link": valid_link})


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
    if user.get("role") == "admin":
        return redirect("admin_panel")

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
    if user.get("role") == "admin":
        return JsonResponse({"ok": False, "error": "Administrator accounts cannot run scans."}, status=403)

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
    activity_id = start_scan_activity(
        user_id=user["id"],
        username=user["username"],
        target=target_url,
        scan_mode=scan_mode,
    )

    # Execute scanner
    try:
        report = run_scan(
            target_url,
            progress_callback=lambda stage: update_scan_activity(activity_id, stage),
            session_cookie=session_cookie,
            scan_mode=scan_mode,
            enabled_modules=enabled_modules,
        )
    except Exception as exc:
        finish_scan_activity(activity_id, "failed", "Scan failed", error=str(exc))
        log_event(
            action="scan_failed",
            user_id=user["id"],
            username=user["username"],
            detail=f"Target: {target_url[:200]} | Error: {exc}",
        )
        return JsonResponse({"ok": False, "error": "The scan could not be completed."}, status=500)
    duration_sec = round(time.perf_counter() - t0, 2)

    if "error" in report:
        finish_scan_activity(activity_id, "failed", "Scan failed", error=report["error"])
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
    finish_scan_activity(activity_id, "completed", "Scan complete", scan_id=scan_id)

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
    scan_runs = list_scan_activity(limit=100)
    active_scan_count = sum(1 for run in scan_runs if run.get("status") == "running")
    for event in all_activity:
        event["action_label"] = str(event.get("action") or "system event").replace("_", " ").capitalize()

    safe_user_fields = (
        "id", "username", "email", "role", "is_active", "failed_logins",
        "locked_until", "created_at", "last_login_at", "scan_count",
    )
    safe_users = [
        {key: user.get(key) for key in safe_user_fields}
        for user in all_users
    ]

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

    scan_usage = []
    daily_counts = Counter(str(scan.get("started_at", ""))[:10] for scan in all_scans)
    for days_ago in range(6, -1, -1):
        day = now.date() - timedelta(days=days_ago)
        scan_usage.append({
            "date": day.strftime("%Y-%m-%d"),
            "label": day.strftime("%a"),
            "count": daily_counts.get(day.strftime("%Y-%m-%d"), 0),
        })
    max_daily_scans = max((day["count"] for day in scan_usage), default=0)
    for day in scan_usage:
        day["height"] = round(day["count"] / max_daily_scans * 100) if max_daily_scans else 0

    finding_counts = Counter()
    with get_conn() as conn:
        report_rows = conn.execute("SELECT report_json FROM scans;").fetchall()
        for row in report_rows:
            try:
                report = json.loads(row["report_json"] or "{}")
            except (TypeError, ValueError):
                continue
            for finding in report.get("findings", []):
                finding_type = str(finding.get("type") or finding.get("category") or "Other")
                finding_counts[finding_type] += 1
    top_findings = [
        {"name": name, "count": count}
        for name, count in finding_counts.most_common(8)
    ]
    max_finding_count = max((finding["count"] for finding in top_findings), default=0)
    for finding in top_findings:
        finding["width"] = round(finding["count"] / max_finding_count * 100) if max_finding_count else 0

    database_tables = _admin_database_table_stats()

    return render(
        request,
        "admin_panel.html",
        {
            "admin": admin,
            "users": safe_users,
            "scans": all_scans,
            "activity": all_activity,
            "scan_runs": scan_runs,
            "active_scan_count": active_scan_count,
            "total_users": total_users,
            "active_7d": active_7d,
            "total_scans": total_scans,
            "scans_today": scans_today,
            "avg_score": avg_score,
            "failed_24h": failed_24h,
            "grade_counts": grade_counts,
            "scan_usage": scan_usage,
            "top_findings": top_findings,
            "database_tables": database_tables,
        },
    )


_ADMIN_DATABASE_QUERIES = {
    "users": (
        "id, username, email, role, is_active, failed_logins, created_at, last_login_at",
        "SELECT id, username, email, role, is_active, failed_logins, created_at, last_login_at FROM users ORDER BY id DESC LIMIT ?;",
    ),
    "scans": (
        "id, user_id, username, target, started_at, duration_sec, risk_score, grade, total_findings, high_count, medium_count, low_count, authorized_confirmed",
        "SELECT s.id, s.user_id, u.username, s.target, s.started_at, s.duration_sec, s.risk_score, s.grade, s.total_findings, s.high_count, s.medium_count, s.low_count, s.authorized_confirmed FROM scans s LEFT JOIN users u ON u.id = s.user_id ORDER BY s.id DESC LIMIT ?;",
    ),
    "activity_log": (
        "id, user_id, username, action, detail, ip, created_at",
        "SELECT id, user_id, username, action, detail, ip, created_at FROM activity_log ORDER BY id DESC LIMIT ?;",
    ),
    "scan_activity": (
        "id, user_id, username, target, scan_mode, status, progress, started_at, updated_at, finished_at, scan_id",
        "SELECT id, user_id, username, target, scan_mode, status, progress, started_at, updated_at, finished_at, scan_id FROM scan_activity ORDER BY id DESC LIMIT ?;",
    ),
}


def _admin_database_table_stats():
    labels = {
        "users": "User accounts",
        "scans": "Scan results",
        "activity_log": "Activity log",
        "scan_activity": "Scan runs",
    }
    with get_conn() as conn:
        return [
            {"name": name, "label": label, "count": int(conn.execute(f"SELECT COUNT(*) AS row_count FROM {name};").fetchone()["row_count"])}
            for name, label in labels.items()
        ]


@require_GET
def admin_database_preview(request):
    """Return a paged, credential-safe preview of a whitelisted database table."""
    admin = _get_current_user(request)
    if not admin or admin.get("role") != "admin":
        return JsonResponse({"ok": False, "error": "Forbidden"}, status=403)
    table = request.GET.get("table", "scans")
    if table not in _ADMIN_DATABASE_QUERIES:
        return JsonResponse({"ok": False, "error": "Unknown dataset"}, status=400)
    columns, query = _ADMIN_DATABASE_QUERIES[table]
    with get_conn() as conn:
        rows = conn.execute(query, (100,)).fetchall()
    return JsonResponse({"ok": True, "table": table, "columns": columns.split(", "), "rows": [dict(row) for row in rows]})


@require_GET
def admin_export_dataset(request):
    """Export the application dataset as a zip of CSV tables, excluding credentials."""
    admin = _get_current_user(request)
    if not admin or admin.get("role") != "admin":
        return HttpResponseForbidden("Administrator role required.")

    exports = {
        "users.csv": "SELECT id, username, email, role, is_active, failed_logins, locked_until, created_at, last_login_at FROM users ORDER BY id;",
        "scans.csv": "SELECT s.id, s.user_id, u.username, s.target, s.started_at, s.duration_sec, s.risk_score, s.grade, s.total_findings, s.high_count, s.medium_count, s.low_count, s.authorized_confirmed, s.report_json FROM scans s LEFT JOIN users u ON u.id = s.user_id ORDER BY s.id;",
        "activity_log.csv": "SELECT id, user_id, username, action, detail, ip, created_at FROM activity_log ORDER BY id;",
        "scan_activity.csv": "SELECT id, user_id, username, target, scan_mode, status, progress, started_at, updated_at, finished_at, scan_id FROM scan_activity ORDER BY id;",
    }
    archive_buffer = io.BytesIO()
    with get_conn() as conn, zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, query in exports.items():
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            output = io.StringIO(newline="")
            writer = csv.writer(output)
            writer.writerow([column[0] for column in cursor.description])
            for row in rows:
                writer.writerow([_csv_safe_value(value) for value in row])
            archive.writestr(filename, "\ufeff" + output.getvalue())

        finding_rows = conn.execute("SELECT s.id, s.target, s.started_at, u.username, s.report_json FROM scans s LEFT JOIN users u ON u.id = s.user_id ORDER BY s.id;").fetchall()
        findings_output = io.StringIO(newline="")
        findings_writer = csv.writer(findings_output)
        finding_columns = ("scan_id", "username", "target", "started_at", "type", "severity", "category", "detail", "description", "field", "location", "payload", "evidence")
        findings_writer.writerow(finding_columns)
        for row in finding_rows:
            try:
                report = json.loads(row["report_json"] or "{}")
            except (TypeError, ValueError):
                report = {}
            for finding in report.get("findings", []):
                values = [row["id"], row["username"], row["target"], row["started_at"]]
                values.extend(finding.get(column, "") for column in finding_columns[4:])
                findings_writer.writerow([_csv_safe_value(value) for value in values])
        archive.writestr("findings.csv", "\ufeff" + findings_output.getvalue())

    archive_buffer.seek(0)
    response = HttpResponse(archive_buffer.getvalue(), content_type="application/zip")
    response["Content-Disposition"] = 'attachment; filename="threatforge_dataset.zip"'
    return response


def _csv_safe_value(value):
    """Prevent exported text cells from being interpreted as spreadsheet formulas."""
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@require_GET
def admin_scan_activity(request):
    """Return recent scan progress for the administrator portal."""
    admin = _get_current_user(request)
    if not admin or admin.get("role") != "admin":
        return JsonResponse({"ok": False, "error": "Forbidden"}, status=403)
    return JsonResponse({"ok": True, "runs": list_scan_activity(limit=100)})


@require_POST
def admin_user_edit(request):
    """Update a user's username and email from the admin portal."""
    admin = _get_current_user(request)
    if not admin or admin.get("role") != "admin":
        return JsonResponse({"ok": False, "error": "Forbidden"}, status=403)

    try:
        target_user_id = int(request.POST.get("user_id", 0))
    except (TypeError, ValueError):
        return JsonResponse({"ok": False, "error": "Invalid user ID."}, status=400)

    target = get_user_by_id(target_user_id)
    if not target:
        return JsonResponse({"ok": False, "error": "User not found."}, status=404)

    username = request.POST.get("username", "").strip()
    email = request.POST.get("email", "").strip().lower()
    error = validate_user_identity(username, email)
    if error:
        return JsonResponse({"ok": False, "error": error}, status=400)

    existing_username = get_user_by_username(username)
    if existing_username and existing_username["id"] != target_user_id:
        return JsonResponse({"ok": False, "error": "That username is already in use."}, status=409)
    existing_email = get_user_by_email(email)
    if existing_email and existing_email["id"] != target_user_id:
        return JsonResponse({"ok": False, "error": "That email is already in use."}, status=409)

    update_user(target_user_id, username=username, email=email)
    log_event(
        action="admin_edit_user",
        user_id=admin["id"],
        username=admin["username"],
        detail=f"Updated profile for user id={target_user_id}",
    )
    return JsonResponse({"ok": True, "message": "User details updated."})


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
