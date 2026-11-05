"""
Database, Authentication, Access-Control & Target Policy Tests
==============================================================
Tests SQLite round-tripping, PBKDF2 password hashing, 5-attempt lockout,
per-user scan ownership isolation, admin role enforcement, and
ALLOW_PRIVATE_TARGETS policy using a temporary database.

Run with:
    python tests/test_db.py
"""

import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.auth import (
    hash_password,
    login,
    perform_admin_user_action,
    register_user,
    verify_password,
)
from services.db import (
    create_user,
    delete_scan,
    get_scan,
    get_user_by_id,
    get_user_by_username,
    init_db,
    insert_activity,
    insert_scan,
    list_activity,
    list_scans_for_user,
    utc_now_iso,
)
from services.target_policy import is_target_allowed


def run_test(name: str, fn) -> bool:
    try:
        fn()
        print(f"[PASS] {name}")
        return True
    except AssertionError as exc:
        print(f"[FAIL] {name}: Assertion failed - {exc}")
        return False
    except Exception as exc:
        print(f"[FAIL] {name}: Unexpected error - {exc}")
        return False


def test_db_roundtrip_and_isolation():
    """Create tables and round-trip users, scans, and activity logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_threatforge.db"
        init_db(db_file)
        # Safe to call repeatedly
        init_db(db_file)

        res1 = register_user("alice_sec", "alice@example.com", "SecurePass123", db_path=db_file)
        assert res1["ok"] is True, f"Registration failed: {res1}"
        alice_id = res1["user_id"]

        res2 = register_user("bob_tester", "bob@example.com", "SecurePass456", db_path=db_file)
        assert res2["ok"] is True
        bob_id = res2["user_id"]

        alice = get_user_by_username("alice_sec", db_path=db_file)
        assert alice is not None and alice["id"] == alice_id
        assert alice["role"] == "user"

        # Insert scan for Alice
        sample_report = {"target": "http://localhost/dvwa", "total_findings": 1}
        scan_id = insert_scan(
            user_id=alice_id,
            target="http://localhost/dvwa",
            started_at=utc_now_iso(),
            duration_sec=1.25,
            risk_score=15,
            grade="B",
            total_findings=1,
            high_count=1,
            medium_count=0,
            low_count=0,
            report_json=json.dumps(sample_report),
            authorized_confirmed=1,
            db_path=db_file,
        )

        # Alice can read her own scan
        alice_scans = list_scans_for_user(alice_id, db_path=db_file)
        assert len(alice_scans) == 1 and alice_scans[0]["id"] == scan_id
        assert get_scan(scan_id, user_id=alice_id, db_path=db_file) is not None

        # Bob CANNOT read or delete Alice's scan
        assert get_scan(scan_id, user_id=bob_id, db_path=db_file) is None
        assert delete_scan(scan_id, user_id=bob_id, db_path=db_file) is False

        # Alice can delete her own scan
        assert delete_scan(scan_id, user_id=alice_id, db_path=db_file) is True
        assert get_scan(scan_id, user_id=alice_id, db_path=db_file) is None

        # Activity log check
        insert_activity("custom_test", user_id=alice_id, username="alice_sec", detail="ok", db_path=db_file)
        events = list_activity(limit=10, db_path=db_file)
        assert any(e["action"] == "custom_test" for e in events)


def test_password_hashing_and_lockout():
    """Verify PBKDF2 hashing and 5-failure account lockout."""
    h1, s1 = hash_password("MyStrongPass99")
    h2, s2 = hash_password("MyStrongPass99")
    assert s1 != s2 and h1 != h2, "Per-user random salt must produce distinct hashes"
    assert verify_password("MyStrongPass99", h1, s1) is True
    assert verify_password("WrongPassword1", h1, s1) is False

    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "lockout.db"
        init_db(db_file)
        register_user("lock_user", "lock@example.com", "CorrectPass123", db_path=db_file)

        # 5 wrong password attempts must lock the account
        for _ in range(5):
            bad = login("lock_user", "WrongPass000", db_path=db_file)
            assert bad["ok"] is False

        user_row = get_user_by_username("lock_user", db_path=db_file)
        assert user_row["failed_logins"] == 5
        assert user_row["locked_until"] is not None

        # Even with the CORRECT password, login must now be refused while locked
        locked_attempt = login("lock_user", "CorrectPass123", db_path=db_file)
        assert locked_attempt["ok"] is False
        assert "locked" in locked_attempt["error"].lower()


def test_admin_permissions_and_safeguards():
    """Verify normal users cannot invoke admin actions and last admin cannot be deleted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "admin_test.db"
        init_db(db_file)

        register_user("normal_u", "normal@example.com", "NormalPass123", db_path=db_file)
        normal_user = get_user_by_username("normal_u", db_path=db_file)

        pwd_hash, salt_hex = hash_password("AdminPass123")
        admin_id = create_user(
            "root_admin", "admin@example.com", pwd_hash, salt_hex, role="admin", db_path=db_file
        )
        admin_user = get_user_by_id(admin_id, db_path=db_file)

        # 1. Normal user must be denied admin functions with PermissionError
        denied = False
        try:
            perform_admin_user_action(normal_user, admin_id, "disable", db_path=db_file)
        except PermissionError:
            denied = True
        assert denied is True, "Normal user must be denied admin operations"

        # 2. Admin cannot disable, demote, or delete themselves
        ok_self, _ = perform_admin_user_action(admin_user, admin_id, "delete", db_path=db_file)
        assert ok_self is False

        # 3. Admin can disable and re-enable normal user
        ok_dis, _ = perform_admin_user_action(
            admin_user, normal_user["id"], "disable", db_path=db_file
        )
        assert ok_dis is True
        assert get_user_by_id(normal_user["id"], db_path=db_file)["is_active"] == 0


def test_target_policy():
    """Verify ALLOW_PRIVATE_TARGETS blocks localhost/127.0.0.1 when false."""
    prev = os.environ.get("ALLOW_PRIVATE_TARGETS")
    try:
        os.environ["ALLOW_PRIVATE_TARGETS"] = "false"
        ok_loop, msg_loop = is_target_allowed("http://127.0.0.1/dvwa")
        assert ok_loop is False and "ALLOW_PRIVATE_TARGETS=false" in (msg_loop or "")

        ok_local, _ = is_target_allowed("http://localhost/dvwa")
        assert ok_local is False

        os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
        ok_allowed, _ = is_target_allowed("http://localhost/dvwa/login.php")
        assert ok_allowed is True
    finally:
        if prev is None:
            os.environ.pop("ALLOW_PRIVATE_TARGETS", None)
        else:
            os.environ["ALLOW_PRIVATE_TARGETS"] = prev


if __name__ == "__main__":
    print("Running ThreatForge database, auth & security hardening tests...\n")
    suite = [
        ("SQLite round-trip + user scan isolation", test_db_roundtrip_and_isolation),
        ("PBKDF2 hashing + 5-failure lockout", test_password_hashing_and_lockout),
        ("Admin role enforcement + self/last-admin guards", test_admin_permissions_and_safeguards),
        ("ALLOW_PRIVATE_TARGETS policy check", test_target_policy),
    ]
    results = [run_test(name, fn) for name, fn in suite]
    print("\n" + "=" * 50)
    if all(results):
        print(f"ALL {len(results)} DB & AUTH CHECKS PASSED")
        sys.exit(0)
    else:
        print("SOME DB & AUTH CHECKS FAILED")
        sys.exit(1)

