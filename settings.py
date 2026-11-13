"""Settings read from environment variables, with explicit validation."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

ORG_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*")


class ConfigError(Exception):
    """A required setting is missing or invalid."""


def _var_key(name: str) -> str:
    return re.sub(r"[^A-Z0-9]", "_", name.upper())


def load_orgs(environ: Mapping[str, str] = os.environ) -> dict[str, dict[str, str]]:
    """Read the list of Okta orgs from OKTA_ADMIN_ORGS (any length).

    For each name, OKTA_ADMIN_<NAME>_URL is the org URL and
    OKTA_ADMIN_<NAME>_API_TOKEN is the name of the token variable.
    """
    raw = environ.get("OKTA_ADMIN_ORGS", "")
    names = [n.strip().lower() for n in raw.split(",") if n.strip()]
    if not names:
        raise ConfigError("OKTA_ADMIN_ORGS is not set (comma-separated org names)")
    orgs: dict[str, dict[str, str]] = {}
    for name in names:
        if not ORG_NAME.fullmatch(name):
            raise ConfigError(f"OKTA_ADMIN_ORGS: invalid org name {name!r}")
        key = _var_key(name)
        url_var = f"OKTA_ADMIN_{key}_URL"
        url = environ.get(url_var, "").strip().rstrip("/")
        if not url:
            raise ConfigError(f"{url_var} is not set")
        if not url.startswith("https://"):
            raise ConfigError(f"{url_var} must start with https://")
        orgs[name] = {"url": url, "token_var": f"OKTA_ADMIN_{key}_API_TOKEN"}
    return orgs


def auth_settings(environ: Mapping[str, str] = os.environ) -> dict:
    """Return sign-in settings, or raise if auth is not configured.

    AUTH_MODE=none turns the gate off and must be set explicitly.
    """
    mode = environ.get("AUTH_MODE", "oidc").strip().lower()
    if mode == "none":
        return {
            "enabled": False,
            "secret_key": environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex(),
            "base_url": environ.get("APP_BASE_URL", "").rstrip("/"),
            "allowed_emails": frozenset(),
        }
    if mode != "oidc":
        raise ConfigError("AUTH_MODE must be 'oidc' or 'none'")
    required = [
        "OIDC_ISSUER",
        "OIDC_CLIENT_ID",
        "OIDC_CLIENT_SECRET",
        "APP_BASE_URL",
        "FLASK_SECRET_KEY",
        "OIDC_ALLOWED_EMAILS",
    ]
    missing = [v for v in required if not environ.get(v, "").strip()]
    if missing:
        raise ConfigError(
            "missing " + ", ".join(missing) + " (or set AUTH_MODE=none for local use)"
        )
    emails = environ["OIDC_ALLOWED_EMAILS"].split(",")
    allowed = frozenset(e.strip().lower() for e in emails if e.strip())
    return {
        "enabled": True,
        "issuer": environ["OIDC_ISSUER"].strip().rstrip("/"),
        "client_id": environ["OIDC_CLIENT_ID"].strip(),
        "client_secret": environ["OIDC_CLIENT_SECRET"].strip(),
        "base_url": environ["APP_BASE_URL"].strip().rstrip("/"),
        "secret_key": environ["FLASK_SECRET_KEY"],
        "allowed_emails": allowed,
    }
