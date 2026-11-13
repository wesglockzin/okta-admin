import os
import subprocess
import sys
from pathlib import Path

import pytest

from settings import ConfigError, auth_settings, load_orgs

ROOT = Path(__file__).resolve().parent.parent

OIDC_ENV = {
    "OIDC_ISSUER": "https://idp.example.test/",
    "OIDC_CLIENT_ID": "id",
    "OIDC_CLIENT_SECRET": "secret",
    "APP_BASE_URL": "https://app.example.test",
    "FLASK_SECRET_KEY": "key",
    "OIDC_ALLOWED_EMAILS": "A@example.test, b@example.test",
}


def test_load_orgs_any_length():
    env = {
        "OKTA_ADMIN_ORGS": "one, two-x ,three,four",
        "OKTA_ADMIN_ONE_URL": "https://one.example.test/",
        "OKTA_ADMIN_TWO_X_URL": "https://two.example.test",
        "OKTA_ADMIN_THREE_URL": "https://three.example.test",
        "OKTA_ADMIN_FOUR_URL": "https://four.example.test",
    }
    orgs = load_orgs(env)
    assert list(orgs) == ["one", "two-x", "three", "four"]
    assert orgs["one"]["url"] == "https://one.example.test"
    assert orgs["two-x"]["token_var"] == "OKTA_ADMIN_TWO_X_API_TOKEN"


def test_load_orgs_requires_list():
    with pytest.raises(ConfigError, match="OKTA_ADMIN_ORGS"):
        load_orgs({})


def test_load_orgs_requires_url_with_name():
    with pytest.raises(ConfigError, match="OKTA_ADMIN_X_URL"):
        load_orgs({"OKTA_ADMIN_ORGS": "x"})


def test_load_orgs_rejects_plain_http():
    env = {"OKTA_ADMIN_ORGS": "x", "OKTA_ADMIN_X_URL": "http://x.example.test"}
    with pytest.raises(ConfigError, match="https"):
        load_orgs(env)


def test_load_orgs_rejects_odd_name():
    with pytest.raises(ConfigError, match="invalid org name"):
        load_orgs({"OKTA_ADMIN_ORGS": "a/b"})


def test_auth_refuses_when_unset():
    with pytest.raises(ConfigError, match="OIDC_ISSUER"):
        auth_settings({})


def test_auth_names_each_missing_setting():
    env = dict(OIDC_ENV)
    del env["FLASK_SECRET_KEY"]
    del env["OIDC_ALLOWED_EMAILS"]
    with pytest.raises(ConfigError) as info:
        auth_settings(env)
    assert "FLASK_SECRET_KEY" in str(info.value)
    assert "OIDC_ALLOWED_EMAILS" in str(info.value)


def test_auth_none_must_be_explicit():
    settings = auth_settings({"AUTH_MODE": "none"})
    assert settings["enabled"] is False


def test_auth_unknown_mode_rejected():
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        auth_settings({"AUTH_MODE": "off"})


def test_auth_oidc_settings():
    settings = auth_settings(OIDC_ENV)
    assert settings["enabled"] is True
    assert settings["issuer"] == "https://idp.example.test"
    assert settings["allowed_emails"] == {"a@example.test", "b@example.test"}


def _import_app(extra):
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ROOT)}
    env.update(extra)
    return subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


ORGS_ENV = {
    "OKTA_ADMIN_ORGS": "alpha",
    "OKTA_ADMIN_ALPHA_URL": "https://alpha.example.test",
}


def test_start_without_settings_exits_nonzero(tmp_path):
    extra = {**ORGS_ENV, "ACTION_LOG_PATH": str(tmp_path / "a.log")}
    result = _import_app(extra)
    assert result.returncode != 0
    assert "OIDC_ISSUER" in result.stdout + result.stderr


def test_start_with_auth_none_succeeds(tmp_path):
    extra = {
        **ORGS_ENV,
        "AUTH_MODE": "none",
        "ACTION_LOG_PATH": str(tmp_path / "a.log"),
    }
    assert _import_app(extra).returncode == 0
