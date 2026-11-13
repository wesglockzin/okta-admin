"""Small request checks: redirect targets, user allow-list, same-origin."""

from __future__ import annotations

from urllib.parse import urlsplit


def safe_next(target: str | None) -> str | None:
    """Return target only if it is a same-site relative path."""
    if not target or not isinstance(target, str):
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    if "\\" in target or any(c in target for c in "\r\n\t"):
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return None
    return target


def is_allowed(email: str | None, allowed: frozenset[str]) -> bool:
    return bool(email) and email.strip().lower() in allowed


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


def origin_ok(origin: str | None, referer: str | None, host_url: str) -> bool:
    """A write request must come from this site (Origin, else Referer)."""
    source = origin or referer
    if not source:
        return False
    return _origin(source) == _origin(host_url)
