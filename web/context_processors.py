"""
Context processors for ThreatForge web views.
"""

from services.db import get_user_by_id


def auth_user_context(request):
    """
    Injects `auth_user` into the template context if logged into ThreatForge.
    """
    user_id = request.session.get("auth_user_id")
    if not user_id:
        return {"auth_user": None}

    user = get_user_by_id(user_id)
    if not user or not user.get("is_active", 1):
        request.session.pop("auth_user_id", None)
        return {"auth_user": None}

    return {
        "auth_user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "is_active": user["is_active"],
            "last_login_at": user.get("last_login_at"),
        }
    }

