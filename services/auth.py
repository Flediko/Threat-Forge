"""
Authentication, Role & Rate-Limit Service
=========================================
Handles PBKDF2-HMAC-SHA256 password hashing (200,000 iterations),
registration validation, account lockout after 5 failed logins,
Streamlit session management, and server-side scan rate limiting.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import hmac
import re
import secrets

from .db import (
    create_user,
    delete_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    list_users,
    update_user,
    count_recent_scans_for_user,
    utc_now_iso,
)
from .activity import log_event

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
MAX_SCANS_PER_HOUR = 10

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str, salt: str | bytes | None = None) -> tuple[str, str]:
    """
    Hash *password* using ``hashlib.pbkdf2_hmac("sha256", ..., 200_000)``
    with a 16-byte random salt.

    Returns
    -------
    tuple[str, str]
        ``(hash_hex, salt_hex)``
    """
    if salt is None:
        salt_bytes = secrets.token_bytes(SALT_BYTES)
    elif isinstance(salt, str):
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = salt

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
    )
    return derived.hex(), salt_bytes.hex()


def verify_password(password: str, expected_hash_hex: str, salt_hex: str) -> bool:
    """Verify *password* in constant time using ``hmac.compare_digest``."""
    try:
        computed_hex, _ = hash_password(password, salt_hex)
        return hmac.compare_digest(computed_hex, expected_hash_hex)
    except Exception:
        return False


def validate_registration_input(
    username: str, email: str, password: str
) -> str | None:
    """
    Validate username, email, and password policy.
    Returns an error message string if invalid, or ``None`` when valid.
    """
    uname = (username or "").strip()
    mail = (email or "").strip()
    pwd = password or ""

    if not _USERNAME_RE.match(uname):
        return (
            "Username must be 3 to 30 characters and contain only letters, "
            "digits, or underscores."
        )
    if not _EMAIL_RE.match(mail) or len(mail) > 254:
        return "Please enter a valid email address."
    if len(pwd) < 10:
        return "Password must be at least 10 characters long."
    if not any(ch.isalpha() for ch in pwd) or not any(ch.isdigit() for ch in pwd):
        return "Password must contain at least one letter and one digit."
    return None


def register_user(
    username: str,
    email: str,
    password: str,
    db_path: str | Path | None = None,
) -> dict:
    """
    Register a new standard user account (always assigned role ``"user"``).

    Returns
    -------
    dict
        ``{"ok": bool, "user_id": int | None, "error": str | None}``
    """
    err = validate_registration_input(username, email, password)
    if err:
        return {"ok": False, "user_id": None, "error": err}

    uname = username.strip()
    mail = email.strip().lower()

    if get_user_by_username(uname, db_path=db_path):
        return {"ok": False, "user_id": None, "error": "Username is already taken."}
    if get_user_by_email(mail, db_path=db_path):
        return {"ok": False, "user_id": None, "error": "Email is already registered."}

    pwd_hash, salt_hex = hash_password(password)
    user_id = create_user(
        username=uname,
        email=mail,
        password_hash=pwd_hash,
        salt=salt_hex,
        role="user",
        db_path=db_path,
    )
    log_event(
        action="register",
        user_id=user_id,
        username=uname,
        detail=f"New user registered ({mail})",
        db_path=db_path,
    )
    return {"ok": True, "user_id": user_id, "error": None}


def login(
    username_or_email: str,
    password: str,
    db_path: str | Path | None = None,
) -> dict:
    """
    Authenticate a user by username or email.

    - Returns a generic ``"Invalid credentials"`` message for unknown users or
      wrong passwords.
    - Increments ``failed_logins`` and locks the account for 15 minutes after
      5 consecutive failures.
    - Refuses disabled accounts (``is_active = 0``).

    Returns
    -------
    dict
        ``{"ok": bool, "user": dict | None, "error": str | None}``
    """
    ident = (username_or_email or "").strip()
    if not ident or not password:
        return {"ok": False, "user": None, "error": "Invalid credentials"}

    user = get_user_by_username(ident, db_path=db_path)
    if user is None and "@" in ident:
        user = get_user_by_email(ident, db_path=db_path)

    if user is None:
        log_event(
            action="login_failed",
            user_id=None,
            username=ident[:60],
            detail="Unknown username or email",
            db_path=db_path,
        )
        return {"ok": False, "user": None, "error": "Invalid credentials"}

    if not user.get("is_active", 1):
        log_event(
            action="login_failed",
            user_id=user["id"],
            username=user["username"],
            detail="Attempted login on disabled account",
            db_path=db_path,
        )
        return {
            "ok": False,
            "user": None,
            "error": "This account has been disabled by an administrator.",
        }

    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    locked_until = user.get("locked_until")
    if locked_until and locked_until > now_iso:
        log_event(
            action="login_failed",
            user_id=user["id"],
            username=user["username"],
            detail=f"Account locked until {locked_until}",
            db_path=db_path,
        )
        return {
            "ok": False,
            "user": None,
            "error": f"Account is temporarily locked due to too many failed attempts (until {locked_until}).",
        }

    if not verify_password(password, user["password_hash"], user["salt"]):
        new_failures = int(user.get("failed_logins", 0)) + 1
        lock_iso = None
        if new_failures >= MAX_FAILED_LOGINS:
            lock_dt = now_dt + timedelta(minutes=LOCKOUT_MINUTES)
            lock_iso = lock_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        update_user(
            user["id"],
            db_path=db_path,
            failed_logins=new_failures,
            locked_until=lock_iso,
        )
        log_event(
            action="login_failed",
            user_id=user["id"],
            username=user["username"],
            detail=(
                f"Wrong password (failure {new_failures}/{MAX_FAILED_LOGINS})"
                + (f" — locked until {lock_iso}" if lock_iso else "")
            ),
            db_path=db_path,
        )
        return {"ok": False, "user": None, "error": "Invalid credentials"}

    # Success: reset lockout counters and record last_login_at
    update_user(
        user["id"],
        db_path=db_path,
        failed_logins=0,
        locked_until=None,
        last_login_at=now_iso,
    )
    refreshed = get_user_by_id(user["id"], db_path=db_path) or user
    safe_user = {
        "id": refreshed["id"],
        "username": refreshed["username"],
        "email": refreshed["email"],
        "role": refreshed["role"],
        "is_active": refreshed["is_active"],
        "last_login_at": refreshed["last_login_at"],
    }
    log_event(
        action="login",
        user_id=safe_user["id"],
        username=safe_user["username"],
        detail="User logged in successfully",
        db_path=db_path,
    )
    return {"ok": True, "user": safe_user, "error": None}


def check_scan_rate_limit(
    user_id: int, db_path: str | Path | None = None
) -> tuple[bool, str | None]:
    """
    Enforce the per-user scan rate limit (max ``MAX_SCANS_PER_HOUR`` scans
    in the last 60 minutes) server-side.
    """
    one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    recent_count = count_recent_scans_for_user(
        user_id, since_iso=one_hour_ago, db_path=db_path
    )
    if recent_count >= MAX_SCANS_PER_HOUR:
        return (
            False,
            f"Rate limit reached: You have run {recent_count} scans in the last hour "
            f"(maximum {MAX_SCANS_PER_HOUR} per hour). Please wait before starting another scan.",
        )
    return True, None


# ── Streamlit Session Helpers ────────────────────────────────────────────────

def current_user(db_path: str | Path | None = None) -> dict | None:
    """
    Return the currently logged-in user dict from ``st.session_state``,
    re-verifying that the account still exists and is active in the DB.
    """
    import streamlit as st

    sess_user = st.session_state.get("auth_user")
    if not sess_user:
        return None

    db_user = get_user_by_id(sess_user["id"], db_path=db_path)
    if not db_user or not db_user.get("is_active", 1):
        st.session_state.pop("auth_user", None)
        return None

    synced = {
        "id": db_user["id"],
        "username": db_user["username"],
        "email": db_user["email"],
        "role": db_user["role"],
        "is_active": db_user["is_active"],
        "last_login_at": db_user["last_login_at"],
    }
    st.session_state["auth_user"] = synced
    return synced


def logout(db_path: str | Path | None = None) -> None:
    """Log out the current user and clear session state."""
    import streamlit as st

    user = st.session_state.get("auth_user")
    if user:
        log_event(
            action="logout",
            user_id=user.get("id"),
            username=user.get("username"),
            detail="User logged out",
            db_path=db_path,
        )
    st.session_state.pop("auth_user", None)
    st.session_state.pop("last_report", None)
    st.session_state.pop("last_scan_id", None)


def require_login(db_path: str | Path | None = None) -> dict:
    """
    Ensure a user is logged in before rendering a view.
    If not logged in, displays a warning and halts execution with ``st.stop()``.
    """
    import streamlit as st

    user = current_user(db_path=db_path)
    if not user:
        st.warning("🔒 Please sign in to access this page.")
        st.stop()
    return user


def require_admin(db_path: str | Path | None = None) -> dict:
    """
    Ensure the logged-in user has ``role == 'admin'``.
    Raises ``PermissionError`` when called outside Streamlit (or halts the
    Streamlit script with an access denied message before loading any data).
    """
    import streamlit as st

    user = current_user(db_path=db_path)
    if not user or user.get("role") != "admin":
        st.error("🚫 Access Denied: Administrator privileges are required to view this page.")
        st.stop()
    return user


def assert_admin_user(user: dict | None) -> None:
    """
    Server-side role guard for service/admin operations that raises
    ``PermissionError`` if *user* is None or not an admin.
    """
    if not user or user.get("role") != "admin" or not user.get("is_active", 1):
        raise PermissionError("Administrator privileges required.")


def perform_admin_user_action(
    admin_user: dict,
    target_user_id: int,
    action_type: str,
    db_path=None,
) -> tuple[bool, str]:
    """
    Execute an administrative user management action with server-side role
    checks, self-protection, and last-admin protection. Every action is
    logged to ``activity_log``.
    """
    assert_admin_user(admin_user)

    target = get_user_by_id(target_user_id, db_path=db_path)
    if not target:
        return False, "Target user not found."

    all_users = list_users(db_path=db_path)
    active_admins = [
        u for u in all_users if u.get("role") == "admin" and u.get("is_active", 1)
    ]

    # Guard 1: Admin cannot disable, demote, or delete themselves
    if target["id"] == admin_user["id"] and action_type in (
        "disable",
        "demote",
        "delete",
    ):
        return False, "You cannot disable, demote, or delete your own admin account."

    # Guard 2: The last remaining active admin cannot be disabled, demoted, or deleted
    if (
        target.get("role") == "admin"
        and len(active_admins) <= 1
        and action_type in ("disable", "demote", "delete")
    ):
        return (
            False,
            "Cannot disable, demote, or delete the last remaining active administrator.",
        )

    t_uname = target["username"]
    if action_type == "disable":
        update_user(target["id"], db_path=db_path, is_active=0)
        log_event(
            action="admin_disable_user",
            user_id=admin_user["id"],
            username=admin_user["username"],
            detail=f"Disabled user '{t_uname}' (id={target['id']})",
            db_path=db_path,
        )
        return True, f"Disabled account '{t_uname}'."

    if action_type == "enable":
        update_user(target["id"], db_path=db_path, is_active=1)
        log_event(
            action="admin_enable_user",
            user_id=admin_user["id"],
            username=admin_user["username"],
            detail=f"Enabled user '{t_uname}' (id={target['id']})",
            db_path=db_path,
        )
        return True, f"Enabled account '{t_uname}'."

    if action_type == "unlock":
        update_user(
            target["id"],
            db_path=db_path,
            failed_logins=0,
            locked_until=None,
        )
        log_event(
            action="admin_unlock_user",
            user_id=admin_user["id"],
            username=admin_user["username"],
            detail=f"Unlocked user '{t_uname}' (id={target['id']})",
            db_path=db_path,
        )
        return True, f"Unlocked account '{t_uname}'."

    if action_type == "promote":
        update_user(target["id"], db_path=db_path, role="admin")
        log_event(
            action="admin_promote_user",
            user_id=admin_user["id"],
            username=admin_user["username"],
            detail=f"Promoted user '{t_uname}' (id={target['id']}) to admin",
            db_path=db_path,
        )
        return True, f"Promoted '{t_uname}' to administrator."

    if action_type == "demote":
        update_user(target["id"], db_path=db_path, role="user")
        log_event(
            action="admin_demote_user",
            user_id=admin_user["id"],
            username=admin_user["username"],
            detail=f"Demoted admin '{t_uname}' (id={target['id']}) to user",
            db_path=db_path,
        )
        return True, f"Demoted '{t_uname}' to standard user."

    if action_type == "delete":
        delete_user(target["id"], db_path=db_path)
        log_event(
            action="admin_delete_user",
            user_id=admin_user["id"],
            username=admin_user["username"],
            detail=f"Deleted user '{t_uname}' (id={target['id']})",
            db_path=db_path,
        )
        return True, f"Deleted user '{t_uname}'."

    return False, f"Unknown action '{action_type}'."


def change_password(
    user_id: int,
    current_password: str,
    new_password: str,
    db_path: str | Path | None = None,
) -> tuple[bool, str]:
    """
    Safely change a user's password after validating current password and policy.
    """
    user = get_user_by_id(user_id, db_path=db_path)
    if not user:
        return False, "User account not found."

    if not verify_password(current_password, user["password_hash"], user["salt"]):
        return False, "Current password does not match our records."

    if len(new_password) < 10:
        return False, "New password must be at least 10 characters long."

    if not any(ch.isalpha() for ch in new_password) or not any(ch.isdigit() for ch in new_password):
        return False, "New password must contain at least one letter and one digit."

    new_hash, new_salt = hash_password(new_password)
    update_user(
        user_id,
        db_path=db_path,
        password_hash=new_hash,
        salt=new_salt,
    )

    log_event(
        action="password_changed",
        user_id=user["id"],
        username=user["username"],
        detail="User changed their account password",
        db_path=db_path,
    )
    return True, "Password updated successfully."


