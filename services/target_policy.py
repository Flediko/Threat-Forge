"""
Target Policy & SSRF / Private-Network Guard
============================================
Enforces URL length limits, strips control characters, and checks whether
scanning loopback or RFC-1918 private network addresses is allowed via the
``ALLOW_PRIVATE_TARGETS`` environment variable (default ``"true"`` for local
WAMP / DVWA / Juice Shop testing).
"""

import ipaddress
import os
import socket
from urllib.parse import urlparse

MAX_URL_LENGTH = 2048


def sanitize_target_url(raw_url: str) -> str:
    """Strip ASCII control characters and surrounding whitespace from *raw_url*."""
    if not raw_url:
        return ""
    cleaned = "".join(ch for ch in raw_url if ord(ch) >= 32 and ord(ch) != 127)
    return cleaned.strip()


def _is_private_or_loopback_ip(ip_str: str) -> bool:
    """
    Return True if *ip_str* falls in loopback (127.0.0.0/8, ::1),
    private (10/8, 172.16/12, 192.168/16), or link-local (169.254/16).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
            or ip_obj.is_reserved
        )
    except ValueError:
        return False


def is_target_allowed(url: str) -> tuple[bool, str | None]:
    """
    Check whether *url* is permitted by the target policy BEFORE any HTTP
    request is sent.

    Controlled by environment variable ``ALLOW_PRIVATE_TARGETS`` (default
    ``"true"`` so local WAMP/DVWA targets at ``http://localhost/dvwa/`` work
    out of the box). When set to ``"false"``, blocks ``localhost``,
    ``127.0.0.0/8``, ``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``,
    ``169.254.0.0/16``, and any hostname resolving to those ranges.

    Returns
    -------
    tuple[bool, str | None]
        ``(allowed, error_message)``
    """
    cleaned = sanitize_target_url(url)
    if not cleaned:
        return False, "Please enter a target URL."

    if len(cleaned) > MAX_URL_LENGTH:
        return (
            False,
            f"Target URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.",
        )

    candidate = cleaned
    if not candidate.startswith(("http://", "https://")):
        candidate = "http://" + candidate

    parsed = urlparse(candidate)
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "Invalid URL: no hostname found."

    allow_private = (
        os.environ.get("ALLOW_PRIVATE_TARGETS", "true").strip().lower()
        in ("true", "1", "yes")
    )
    if allow_private:
        return True, None

    # When ALLOW_PRIVATE_TARGETS=false, block localhost and private IP ranges
    if hostname in ("localhost", "localhost.localdomain") or hostname.endswith(".local"):
        return (
            False,
            "Scanning local or private network targets is disabled (ALLOW_PRIVATE_TARGETS=false).",
        )

    if _is_private_or_loopback_ip(hostname):
        return (
            False,
            f"Scanning private or loopback address '{hostname}' is disabled (ALLOW_PRIVATE_TARGETS=false).",
        )

    # Resolve hostname and verify none of its resolved IPs are private/loopback
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            resolved_ip = entry[4][0]
            if _is_private_or_loopback_ip(resolved_ip):
                return (
                    False,
                    f"Target '{hostname}' resolves to restricted private/loopback address '{resolved_ip}' (ALLOW_PRIVATE_TARGETS=false).",
                )
    except socket.gaierror:
        # DNS resolution failure will be reported cleanly by url_input.validate_url
        pass

    return True, None

