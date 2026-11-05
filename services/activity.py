"""
Activity Logging Service
========================
 Thin wrapper around ``services.db.insert_activity`` and ``list_activity``
for recording user logins, registrations, scans, PDF exports, and admin actions.
"""

from pathlib import Path
from .db import insert_activity, list_activity


def log_event(
    action: str,
    user_id: int | None = None,
    username: str | None = None,
    detail: str | None = None,
    ip: str | None = None,
    db_path: str | Path | None = None,
) -> int:
    """Record an audit trail event in ``activity_log``."""
    return insert_activity(
        action=action,
        user_id=user_id,
        username=username,
        detail=detail,
        ip=ip,
        db_path=db_path,
    )


def get_activity_events(
    limit: int = 500,
    offset: int = 0,
    db_path: str | Path | None = None,
) -> list[dict]:
    """Fetch recent activity log entries."""
    return list_activity(limit=limit, offset=offset, db_path=db_path)

