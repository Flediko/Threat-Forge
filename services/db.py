"""
Database Layer (WAMP MySQL & SQLite)
=====================================
Provides parameterized database persistence for users, scans, and activity logs.
Defaults to WAMP MySQL (port 3306, user 'root', database 'threatforge') and
supports SQLite fallback for offline unit tests.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3

try:
    import pymysql
    import pymysql.cursors
    HAVE_PYMYSQL = True
except ImportError:
    HAVE_PYMYSQL = False

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "data" / "threatforge.db"

# MySQL / WAMP Configuration
MYSQL_HOST = os.environ.get("TF_MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.environ.get("TF_MYSQL_PORT", 3306))
MYSQL_USER = os.environ.get("TF_MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ.get("TF_MYSQL_PASSWORD", "")
MYSQL_DB = os.environ.get("TF_MYSQL_DB", "threatforge")

# Strictly whitelisted columns allowed in update_user()
_ALLOWED_USER_UPDATE_COLS = {
    "username",
    "email",
    "password_hash",
    "salt",
    "role",
    "is_active",
    "failed_logins",
    "locked_until",
    "last_login_at",
}


def utc_now_iso() -> str:
    """Return the current UTC time formatted as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_MYSQL_AVAILABLE = None


def _probe_mysql() -> bool:
    """Check whether the configured MySQL server is reachable."""
    global _MYSQL_AVAILABLE
    if _MYSQL_AVAILABLE is not None:
        return _MYSQL_AVAILABLE
    if not HAVE_PYMYSQL:
        _MYSQL_AVAILABLE = False
        return False
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            connect_timeout=1,
        )
        conn.close()
        _MYSQL_AVAILABLE = True
    except Exception:
        _MYSQL_AVAILABLE = False
    return _MYSQL_AVAILABLE


def is_using_mysql(db_path: str | Path | None = None) -> bool:
    """Return True if MySQL mode should be used (default when db_path is omitted)."""
    if db_path is not None or os.environ.get("USE_SQLITE") == "1":
        return False
    return _probe_mysql()


def resolve_db_path(db_path: str | Path | None = None) -> Path:
    """Resolve the SQLite database path and ensure its parent folder exists."""
    if db_path is not None:
        target = Path(db_path)
    elif os.environ.get("THREATFORGE_DB_PATH"):
        target = Path(os.environ["THREATFORGE_DB_PATH"])
    else:
        target = DEFAULT_SQLITE_PATH

    target.parent.mkdir(parents=True, exist_ok=True)
    return target


class MySQLConnectionWrapper:
    """Thin wrapper around PyMySQL connection to harmonize with sqlite execute interface."""

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, sql: str, params: tuple | list = ()):
        cur = self._conn.cursor()
        # Translate standard '?' placeholder to MySQL '%s'
        mysql_sql = sql.replace("?", "%s")
        cur.execute(mysql_sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


@contextmanager
def get_conn(db_path: str | Path | None = None):
    """
    Context manager that opens a connection (WAMP MySQL by default, or SQLite
    when db_path is provided), commits on success, and always closes.
    """
    if is_using_mysql(db_path):
        conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
        wrapper = MySQLConnectionWrapper(conn)
        try:
            yield wrapper
            wrapper.commit()
        except Exception:
            wrapper.rollback()
            raise
        finally:
            wrapper.close()
    else:
        path = resolve_db_path(db_path)
        conn = sqlite3.connect(str(path), timeout=20.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db(db_path: str | Path | None = None) -> None:
    """
    Create the database (if MySQL) and the users, scans, and activity_log tables.
    Safe to call repeatedly.
    """
    if is_using_mysql(db_path):
        # 1. Ensure database exists on WAMP MySQL server
        server_conn = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            charset="utf8mb4",
            autocommit=True,
        )
        try:
            with server_conn.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
                )
        finally:
            server_conn.close()

        # 2. Create tables in the threatforge database
        with get_conn(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(64) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'user',
                    is_active INT NOT NULL DEFAULT 1,
                    failed_logins INT NOT NULL DEFAULT 0,
                    locked_until VARCHAR(50),
                    created_at VARCHAR(50) NOT NULL,
                    last_login_at VARCHAR(50)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    target VARCHAR(500) NOT NULL,
                    started_at VARCHAR(50) NOT NULL,
                    duration_sec DOUBLE,
                    risk_score INT,
                    grade VARCHAR(10),
                    total_findings INT,
                    high_count INT,
                    medium_count INT,
                    low_count INT,
                    report_json LONGTEXT NOT NULL,
                    authorized_confirmed INT NOT NULL DEFAULT 0,
                    INDEX idx_scans_user_id (user_id),
                    INDEX idx_scans_started_at (started_at),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    username VARCHAR(100),
                    action VARCHAR(100) NOT NULL,
                    detail TEXT,
                    ip VARCHAR(64),
                    created_at VARCHAR(50) NOT NULL,
                    INDEX idx_activity_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_activity (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    username VARCHAR(100) NOT NULL,
                    target VARCHAR(500) NOT NULL,
                    scan_mode VARCHAR(16) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    progress VARCHAR(255) NOT NULL,
                    started_at VARCHAR(50) NOT NULL,
                    updated_at VARCHAR(50) NOT NULL,
                    finished_at VARCHAR(50),
                    scan_id INT,
                    error TEXT,
                    INDEX idx_scan_activity_status_started (status, started_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """
            )
    else:
        # SQLite mode (for test suites)
        with get_conn(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    failed_logins INTEGER NOT NULL DEFAULT 0,
                    locked_until TEXT,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    duration_sec REAL,
                    risk_score INTEGER,
                    grade TEXT,
                    total_findings INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    report_json TEXT NOT NULL,
                    authorized_confirmed INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    detail TEXT,
                    ip TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    finished_at TEXT,
                    scan_id INTEGER,
                    error TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_activity_created_at ON activity_log(created_at);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_activity_status_started ON scan_activity(status, started_at);"
            )


# ── User Queries ─────────────────────────────────────────────────────────────

def get_user_by_username(
    username: str, db_path: str | Path | None = None
) -> dict | None:
    """Fetch a user row by case-insensitive username."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(username) = LOWER(?);",
            (username.strip(),),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_email(
    email: str, db_path: str | Path | None = None
) -> dict | None:
    """Fetch a user row by case-insensitive email."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(?);",
            (email.strip(),),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(
    user_id: int, db_path: str | Path | None = None
) -> dict | None:
    """Fetch a user row by primary key ID."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?;",
            (int(user_id),),
        ).fetchone()
        return dict(row) if row else None


def create_user(
    username: str,
    email: str,
    password_hash: str,
    salt: str,
    role: str = "user",
    db_path: str | Path | None = None,
) -> int:
    """Insert a new user and return the newly created user ID."""
    now = utc_now_iso()
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO users (
                username, email, password_hash, salt, role,
                is_active, failed_logins, locked_until, created_at, last_login_at
            )
            VALUES (?, ?, ?, ?, ?, 1, 0, NULL, ?, NULL);
            """,
            (username.strip(), email.strip().lower(), password_hash, salt, role, now),
        )
        return int(cur.lastrowid)


def update_user(
    user_id: int, db_path: str | Path | None = None, **fields
) -> bool:
    """
    Update whitelisted fields on a user record using parameterized queries.
    """
    if not fields:
        return False

    invalid = set(fields.keys()) - _ALLOWED_USER_UPDATE_COLS
    if invalid:
        raise ValueError(f"Disallowed user update columns: {invalid}")

    # Static column assignments mapped from strictly validated whitelist
    col_clauses = []
    values = []
    for col in _ALLOWED_USER_UPDATE_COLS:
        if col in fields:
            col_clauses.append(f"{col} = ?")
            values.append(fields[col])

    if not col_clauses:
        return False

    values.append(int(user_id))
    sql = "UPDATE users SET " + ", ".join(col_clauses) + " WHERE id = ?;"
    with get_conn(db_path) as conn:
        cur = conn.execute(sql, tuple(values))
        return cur.rowcount > 0


def delete_user(user_id: int, db_path: str | Path | None = None) -> bool:
    """Delete a user by ID."""
    with get_conn(db_path) as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?;", (int(user_id),))
        return cur.rowcount > 0


def list_users(db_path: str | Path | None = None) -> list[dict]:
    """List all users with their total scan count."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.password_hash, u.salt, u.role, u.is_active,
                   u.failed_logins, u.locked_until, u.created_at, u.last_login_at,
                   COUNT(s.id) AS scan_count
            FROM users u
            LEFT JOIN scans s ON s.user_id = u.id
            GROUP BY u.id, u.username, u.email, u.password_hash, u.salt, u.role, u.is_active,
                     u.failed_logins, u.locked_until, u.created_at, u.last_login_at
            ORDER BY u.created_at DESC;
            """
        ).fetchall()
        return [dict(r) for r in rows]


# ── Scan Queries ─────────────────────────────────────────────────────────────

def insert_scan(
    user_id: int,
    target: str,
    started_at: str,
    duration_sec: float,
    risk_score: int,
    grade: str,
    total_findings: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    report_json: str,
    authorized_confirmed: int = 0,
    db_path: str | Path | None = None,
) -> int:
    """Insert a completed scan record and return its ID."""
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                user_id, target, started_at, duration_sec,
                risk_score, grade, total_findings,
                high_count, medium_count, low_count,
                report_json, authorized_confirmed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                int(user_id),
                target,
                started_at,
                float(duration_sec),
                int(risk_score),
                str(grade),
                int(total_findings),
                int(high_count),
                int(medium_count),
                int(low_count),
                report_json,
                1 if authorized_confirmed else 0,
            ),
        )
        return int(cur.lastrowid)


def list_scans_for_user(
    user_id: int, db_path: str | Path | None = None
) -> list[dict]:
    """Return all scans belonging to *user_id*, newest first."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM scans
            WHERE user_id = ?
            ORDER BY started_at DESC, id DESC;
            """,
            (int(user_id),),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(
    scan_id: int,
    user_id: int | None = None,
    db_path: str | Path | None = None,
) -> dict | None:
    """
    Fetch a single scan by ID. When *user_id* is provided, ownership is
    enforced directly in the SQL query so users cannot read others' scans.
    """
    with get_conn(db_path) as conn:
        if user_id is not None:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ? AND user_id = ?;",
                (int(scan_id), int(user_id)),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT s.*, u.username FROM scans s LEFT JOIN users u ON u.id = s.user_id WHERE s.id = ?;",
                (int(scan_id),),
            ).fetchone()
        return dict(row) if row else None


def delete_scan(
    scan_id: int,
    user_id: int | None = None,
    db_path: str | Path | None = None,
) -> bool:
    """
    Delete a scan by ID. When *user_id* is provided, ownership is enforced
    in the SQL WHERE clause so a user can only delete their own scan.
    """
    with get_conn(db_path) as conn:
        if user_id is not None:
            cur = conn.execute(
                "DELETE FROM scans WHERE id = ? AND user_id = ?;",
                (int(scan_id), int(user_id)),
            )
        else:
            cur = conn.execute(
                "DELETE FROM scans WHERE id = ?;",
                (int(scan_id),),
            )
        return cur.rowcount > 0


def count_recent_scans_for_user(
    user_id: int,
    since_iso: str,
    db_path: str | Path | None = None,
) -> int:
    """Count how many scans *user_id* has started since *since_iso*."""
    with get_conn(db_path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM scans
            WHERE user_id = ? AND started_at >= ?;
            """,
            (int(user_id), since_iso),
        ).fetchone()
        return int(row["cnt"]) if row else 0


def list_all_scans(db_path: str | Path | None = None) -> list[dict]:
    """Return all scans across all users (for admin panel), newest first."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT s.id, s.user_id, s.target, s.started_at, s.duration_sec,
                   s.risk_score, s.grade, s.total_findings, s.high_count,
                   s.medium_count, s.low_count, s.authorized_confirmed, u.username
            FROM scans s
            LEFT JOIN users u ON u.id = s.user_id
            ORDER BY s.started_at DESC, s.id DESC;
            """
        ).fetchall()
        return [dict(r) for r in rows]


def start_scan_activity(
    user_id: int,
    username: str,
    target: str,
    scan_mode: str,
    db_path: str | Path | None = None,
) -> int:
    """Persist a scan's live status so administrators can monitor it."""
    now = utc_now_iso()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_conn(db_path) as conn:
        conn.execute(
            "DELETE FROM scan_activity WHERE status != 'running' AND finished_at < ?;",
            (cutoff,),
        )
        cur = conn.execute(
            """
            INSERT INTO scan_activity (
                user_id, username, target, scan_mode, status, progress,
                started_at, updated_at
            ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?);
            """,
            (int(user_id), username, target[:500], scan_mode, "Starting scan", now, now),
        )
        return int(cur.lastrowid)


def update_scan_activity(
    activity_id: int,
    progress: str,
    db_path: str | Path | None = None,
) -> None:
    """Update the current stage and heartbeat for a running scan."""
    now = utc_now_iso()
    with get_conn(db_path) as conn:
        conn.execute(
            "UPDATE scan_activity SET progress = ?, updated_at = ? WHERE id = ? AND status = 'running';",
            (str(progress)[:255], now, int(activity_id)),
        )


def finish_scan_activity(
    activity_id: int,
    status: str,
    progress: str,
    scan_id: int | None = None,
    error: str | None = None,
    db_path: str | Path | None = None,
) -> None:
    """Mark a monitored scan as complete or failed."""
    now = utc_now_iso()
    with get_conn(db_path) as conn:
        conn.execute(
            """
            UPDATE scan_activity
            SET status = ?, progress = ?, scan_id = ?, error = ?, updated_at = ?, finished_at = ?
            WHERE id = ?;
            """,
            (status, str(progress)[:255], scan_id, str(error)[:1000] if error else None, now, now, int(activity_id)),
        )


def list_scan_activity(
    limit: int = 100,
    db_path: str | Path | None = None,
) -> list[dict]:
    """Return recent live and completed scan runs for the admin portal."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM scan_activity ORDER BY started_at DESC, id DESC LIMIT ?;",
            (int(limit),),
        ).fetchall()
        return [dict(row) for row in rows]


# ── Activity Log Queries ─────────────────────────────────────────────────────

def insert_activity(
    action: str,
    user_id: int | None = None,
    username: str | None = None,
    detail: str | None = None,
    ip: str | None = None,
    db_path: str | Path | None = None,
) -> int:
    """Insert an activity log entry and return its ID."""
    now = utc_now_iso()
    with get_conn(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO activity_log (user_id, username, action, detail, ip, created_at)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (user_id, username, action, detail, ip or "local", now),
        )
        return int(cur.lastrowid)


def list_activity(
    limit: int = 500,
    offset: int = 0,
    db_path: str | Path | None = None,
) -> list[dict]:
    """Return activity log rows ordered newest first."""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM activity_log
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?;
            """,
            (int(limit), int(offset)),
        ).fetchall()
        return [dict(r) for r in rows]
