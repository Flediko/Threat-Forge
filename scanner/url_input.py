"""
URL Input Module
================
Validates and normalises the target URL provided by the user,
enforcing target policy checks before any network request is made.
"""

from urllib.parse import urlparse, urlunparse
import requests
from services.target_policy import is_target_allowed, sanitize_target_url


def validate_url(
    url: str,
    timeout: int = 30,
    session: requests.Session | None = None,
) -> dict:
    """
    Validate and normalise a URL.

    1. Sanitizes control characters and enforces ``is_target_allowed()``
       (including max URL length 2048 and ``ALLOW_PRIVATE_TARGETS`` policy)
       BEFORE sending any HTTP request.
    2. Treats HTTP 401/403/404 responses as reachable hosts; only structural
       errors, policy blocks, connection errors, timeouts, or 5xx responses
       are marked invalid.

    Returns
    -------
    dict
        {
            "valid": bool,
            "url": str | None,      # normalised URL (with scheme)
            "error": str | None      # human-readable error message
        }
    """
    cleaned = sanitize_target_url(url)
    if not cleaned:
        return {"valid": False, "url": None, "error": "Invalid URL: empty target."}

    # Add scheme if missing
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned

    # Structural validation
    parsed = urlparse(cleaned)
    if not parsed.netloc:
        return {"valid": False, "url": None, "error": "Invalid URL: no domain found."}

    normalised = urlunparse(parsed)

    # Target policy check BEFORE any request is sent
    allowed, policy_error = is_target_allowed(normalised)
    if not allowed:
        return {"valid": False, "url": normalised, "error": policy_error}

    http = session if session is not None else requests

    # Reachability check
    try:
        resp = http.get(normalised, timeout=timeout, allow_redirects=True)
        # HTTP 401/403/404 mean the host is up and reachable
        if resp.status_code >= 500:
            resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        return {
            "valid": False,
            "url": normalised,
            "error": f"Cannot connect to {normalised}. The site may be down or unreachable.",
        }
    except requests.exceptions.Timeout:
        return {
            "valid": False,
            "url": normalised,
            "error": f"Connection to {normalised} timed out after {timeout}s.",
        }
    except requests.exceptions.HTTPError as exc:
        return {"valid": False, "url": normalised, "error": f"HTTP server error: {exc}"}
    except requests.exceptions.RequestException as exc:
        return {"valid": False, "url": normalised, "error": f"Request failed: {exc}"}

    return {"valid": True, "url": normalised, "error": None}
