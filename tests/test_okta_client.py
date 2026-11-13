import time

import pytest
import requests

import okta_client
from okta_client import OktaClient

BASE = "https://org.example.test"


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, content=b""):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.content = content
        self.text = str(body)

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._body

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """Answers requests from a table keyed by (method, url)."""

    def __init__(self, routes):
        self.headers = {}
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        queue = self.routes[(method, url)]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def methods(self):
        return [c[0] for c in self.calls]


def make(routes):
    session = FakeSession(routes)
    return OktaClient(BASE, "token", session), session


def test_auth_header_uses_ssws():
    _, session = make({})
    assert session.headers["Authorization"] == "SSWS token"


def test_next_link_parsed():
    link = f'<{BASE}/a>; rel="self", <{BASE}/b>; rel="next"'
    resp = FakeResponse(headers={"Link": link})
    assert OktaClient._next_link(resp) == f"{BASE}/b"
    assert OktaClient._next_link(FakeResponse()) is None


def test_pagination_follows_next_links():
    page2 = f"{BASE}/api/v1/apps?after=1"
    link = {"Link": f'<{page2}>; rel="next"'}
    first = FakeResponse(body=[{"id": "1"}], headers=link)
    client, _ = make(
        {
            ("GET", f"{BASE}/api/v1/apps"): [first],
            ("GET", page2): [FakeResponse(body=[{"id": "2"}])],
        }
    )
    assert [a["id"] for a in client._get_paginated(f"{BASE}/api/v1/apps")] == ["1", "2"]


def test_get_all_apps_filters_sign_on_modes():
    apps = [
        {"id": "1", "signOnMode": "SAML_2_0"},
        {"id": "2", "signOnMode": "SOMETHING_ELSE"},
        {"id": "3"},
    ]
    client, _ = make({("GET", f"{BASE}/api/v1/apps"): [FakeResponse(body=apps)]})
    assert [a["id"] for a in client.get_all_apps()] == ["1", "3"]


def test_retry_after_429(monkeypatch):
    sleeps = []
    monkeypatch.setattr(okta_client.time, "sleep", sleeps.append)
    reset = str(int(time.time()) + 2)
    limited = FakeResponse(status=429, headers={"X-Rate-Limit-Reset": reset})
    url = f"{BASE}/api/v1/groups/g1"
    client, session = make({("GET", url): [limited, FakeResponse(body={"id": "g1"})]})
    assert client.get_group("g1") == {"id": "g1"}
    assert session.methods() == ["GET", "GET"]
    assert sleeps and sleeps[0] >= 1


def test_catalog_search_http_error_is_logged_and_raised(caplog):
    url = f"{BASE}/api/v1/catalog/apps?q=Example&limit=20"
    client, _ = make({("GET", url): [FakeResponse(status=403)]})
    with caplog.at_level("ERROR", logger="okta_client"):
        with pytest.raises(requests.HTTPError) as info:
            client.search_oin_catalog("Example")
    assert info.value.response.status_code == 403
    assert "OIN catalog search failed" in caplog.text


def test_http_error_keeps_status(monkeypatch):
    monkeypatch.setattr(okta_client.time, "sleep", lambda s: None)
    client, _ = make({("GET", f"{BASE}/api/v1/apps"): [FakeResponse(status=500)]})
    with pytest.raises(requests.HTTPError) as info:
        client.get_all_apps()
    assert info.value.response.status_code == 500


def routing_rule(includes):
    return {"id": "r1", "conditions": {"app": {"include": includes}}}


def test_add_app_to_routing_rule_puts_once():
    url = f"{BASE}/api/v1/policies/p1/rules/r1"
    rule = routing_rule([{"id": "a1", "type": "APP"}])
    client, session = make(
        {("GET", url): [FakeResponse(body=rule)], ("PUT", url): [FakeResponse()]}
    )
    client.add_app_to_routing_rule("p1", "r1", "a2")
    puts = [c for c in session.calls if c[0] == "PUT"]
    assert len(puts) == 1
    ids = [r["id"] for r in puts[0][2]["json"]["conditions"]["app"]["include"]]
    assert ids == ["a1", "a2"]


def test_add_app_already_in_rule_does_not_write():
    url = f"{BASE}/api/v1/policies/p1/rules/r1"
    rule = routing_rule([{"id": "a1", "type": "APP"}])
    client, session = make({("GET", url): [FakeResponse(body=rule)]})
    client.add_app_to_routing_rule("p1", "r1", "a1")
    assert session.methods() == ["GET"]


def test_remove_app_from_routing_rule():
    url = f"{BASE}/api/v1/policies/p1/rules/r1"
    rule = routing_rule([{"id": "a1", "type": "APP"}, {"id": "a2", "type": "APP"}])
    client, session = make(
        {("GET", url): [FakeResponse(body=rule)], ("PUT", url): [FakeResponse()]}
    )
    client.remove_app_from_routing_rule("p1", "r1", "a1")
    sent = next(c for c in session.calls if c[0] == "PUT")[2]["json"]
    assert [r["id"] for r in sent["conditions"]["app"]["include"]] == ["a2"]


def test_safe_id_rejects_path_tricks():
    assert OktaClient._safe_id("0oa1B2c3") == "0oa1B2c3"
    for bad in ["../x", "a/b", "", "a b", None]:
        with pytest.raises(ValueError):
            OktaClient._safe_id(bad)


def test_delete_app_rejects_bad_id_without_calling_okta():
    client, session = make({})
    with pytest.raises(ValueError):
        client.delete_app("../groups")
    assert session.calls == []


def test_delete_user_assignment_reports_http_error():
    url = f"{BASE}/api/v1/apps/a1/users/u1"
    body = {"errorCode": "E0000009"}
    client, _ = make({("DELETE", url): [FakeResponse(status=500, body=body)]})
    assert client.delete_user_app_assignment("a1", "u1") == (False, "HTTP 500 E0000009")


def test_delete_user_assignment_treats_404_as_done():
    url = f"{BASE}/api/v1/apps/a1/users/u1"
    client, _ = make({("DELETE", url): [FakeResponse(status=404)]})
    assert client.delete_user_app_assignment("a1", "u1") == (True, None)


def test_clear_app_assignments_removes_everyone_and_user_scope():
    app = f"{BASE}/api/v1/apps/a1"
    everyone = {"id": "g1", "type": "BUILT_IN", "profile": {"name": "Everyone"}}
    users = [
        {"id": "u1", "scope": "USER"},
        {"id": "u2", "scope": "USER"},
        {"id": "u3", "scope": "GROUP"},
    ]
    client, session = make(
        {
            ("GET", f"{app}/groups"): [FakeResponse(body=[{"id": "g1"}])],
            ("GET", f"{BASE}/api/v1/groups/g1"): [FakeResponse(body=everyone)],
            ("GET", f"{app}/users"): [FakeResponse(body=users)],
            ("DELETE", f"{app}/groups/g1"): [FakeResponse(status=204)],
            ("DELETE", f"{app}/users/u1"): [FakeResponse(status=204)],
            ("DELETE", f"{app}/users/u2"): [FakeResponse(status=403, body={})],
        }
    )
    summary = client.clear_app_assignments("a1")
    assert summary["everyone_removed"] is True
    assert summary["user_scope_deleted"] == 1
    assert summary["user_scope_failed"] == 1
    assert summary["group_scope_will_orphan"] == 1
    deleted = [c[1] for c in session.calls if c[0] == "DELETE"]
    assert f"{app}/users/u3" not in deleted


def test_everyone_decision():
    groups = {
        "g1": {"name": "Everyone", "type": "BUILT_IN"},
        "g2": {"name": "Staff", "type": "OKTA_GROUP"},
    }
    url = f"{BASE}/api/v1/apps/a1/groups"
    client, _ = make({("GET", url): [FakeResponse(body=[{"id": "g1"}])]})
    decision = client.everyone_decision("a1", groups)
    assert decision["everyone_only"] is True
    client, _ = make({("GET", url): [FakeResponse(body=[{"id": "g1"}, {"id": "g2"}])]})
    decision = client.everyone_decision("a1", groups)
    assert decision["has_everyone"] and not decision["everyone_only"]


METADATA = b"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://idp.test/exk1">
 <md:IDPSSODescriptor>
  <md:KeyDescriptor use="signing">
   <ds:KeyInfo><ds:X509Data><ds:X509Certificate>QUJD</ds:X509Certificate>
   </ds:X509Data></ds:KeyInfo>
  </md:KeyDescriptor>
  <md:SingleSignOnService
    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    Location="https://idp.test/sso"/>
 </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def test_metadata_parsed():
    url = f"{BASE}/api/v1/apps/a1/sso/saml/metadata"
    client, _ = make({("GET", url): [FakeResponse(content=METADATA)]})
    meta = client._fetch_and_parse_metadata(url)
    assert meta["error"] == ""
    assert meta["key_id"] == "exk1"
    assert meta["idp_sso_url"] == "https://idp.test/sso"
    assert meta["cert_pem"].startswith("-----BEGIN CERTIFICATE-----\nQUJD")


def test_metadata_off_tenant_is_refused():
    client, session = make({})
    meta = client._fetch_and_parse_metadata("https://other.example.test/meta")
    assert "not the tenant host" in meta["error"]
    assert session.calls == []


def test_metadata_http_error_is_reported():
    url = f"{BASE}/api/v1/apps/a1/sso/saml/metadata"
    client, _ = make({("GET", url): [FakeResponse(status=403)]})
    meta = client._fetch_and_parse_metadata(url)
    assert "HTTPError" in meta["error"] and "403" in meta["error"]
