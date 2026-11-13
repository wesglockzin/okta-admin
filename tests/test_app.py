import pytest

import app as app_module

SAME_SITE = {"Origin": "http://localhost"}


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.fixture
def gate_on(monkeypatch):
    monkeypatch.setattr(app_module, "OIDC_ENABLED", True)


class FakeOkta:
    def get_all_apps(self):
        return [
            {"id": "2", "label": "zeta", "signOnMode": "SAML_2_0", "status": "ACTIVE"},
            {"id": "1", "label": "Alpha", "signOnMode": "OPENID_CONNECT"},
        ]

    def get_app_policy_map(self):
        return {"1": {"policy_id": "p1", "policy_name": "Strong"}}

    def get_app_routing_rule_map(self):
        return {}


def test_orgs_come_from_settings():
    assert list(app_module.OKTA_ENVIRONMENTS) == ["alpha", "beta"]
    assert app_module.DEFAULT_ENV == "alpha"


def test_health_needs_no_auth_and_no_okta(client, gate_on):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_index_lists_configured_orgs(client):
    html = client.get("/").get_data(as_text=True)
    assert 'data-env="alpha"' in html
    assert 'data-env="beta"' in html
    assert 'data-env="dev"' not in html


def test_api_requires_sign_in_when_gate_on(client, gate_on):
    resp = client.get("/api/apps")
    assert resp.status_code == 401


def test_page_redirects_to_login_when_gate_on(client, gate_on):
    resp = client.get("/logs")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_signed_in_user_passes_gate(client, gate_on):
    with client.session_transaction() as sess:
        sess["user"] = {"email": "a@example.test"}
    assert client.get("/logs").status_code == 200


def test_login_ignores_offsite_next(client):
    client.get("/login?next=//evil.example.test")
    with client.session_transaction() as sess:
        assert "post_login_redirect" not in sess


def test_login_keeps_relative_next(client):
    client.get("/login?next=/logs")
    with client.session_transaction() as sess:
        assert sess["post_login_redirect"] == "/logs"


def test_write_without_origin_is_rejected(client):
    resp = client.post("/api/toggle-status", json={"action": "activate"})
    assert resp.status_code == 403


def test_write_from_other_site_is_rejected(client):
    headers = {"Origin": "https://evil.example.test"}
    resp = client.post("/api/toggle-status", json={}, headers=headers)
    assert resp.status_code == 403


def test_write_from_same_site_reaches_handler(client):
    body = {"action": "explode", "app_id": "x"}
    resp = client.post("/api/toggle-status", json=body, headers=SAME_SITE)
    assert resp.status_code == 400


def test_unknown_env_is_400(client):
    resp = client.get("/api/apps?env=nope")
    assert resp.status_code == 400


def test_missing_token_is_400(client, monkeypatch):
    monkeypatch.delenv("OKTA_ADMIN_ALPHA_API_TOKEN", raising=False)
    monkeypatch.setattr(app_module, "_keyring", None)
    resp = client.get("/api/apps")
    assert resp.status_code == 400
    assert "OKTA_ADMIN_ALPHA_API_TOKEN" in resp.get_json()["error"]


def test_apps_listing_is_sorted_and_joined(client, monkeypatch):
    monkeypatch.setattr(app_module, "_client", lambda env: (FakeOkta(), None))
    rows = client.get("/api/apps").get_json()
    assert [r["label"] for r in rows] == ["Alpha", "zeta"]
    assert rows[0]["policy_name"] == "Strong"
    assert rows[1]["policy_id"] is None


def test_sp_vendor_detection():
    detect = app_module._detect_sp_vendor
    shib = {"acs_url": "https://x.example.test/Shibboleth.sso/SAML2/POST"}
    assert detect(shib) == "shibboleth"
    assert detect({"entity_id": "urn:amazon:webservices amazonaws.com"}) == "aws"
    assert detect({"acs_url": "https://x.example.test", "is_oin": True}) == "oin"
    assert detect({}) == "generic"
