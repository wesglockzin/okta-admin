"""okta_client.py — Okta API client for the App Admin Dashboard."""
from __future__ import annotations

import time

import requests

OKTA_ENVIRONMENTS = {
    "dev":  {"url": "https://YOUR_DEV_OKTA_DOMAIN.okta-gov.com",  "token_var": "OKTA_ADMIN_DEV_API_TOKEN"},
    "stg":  {"url": "https://YOUR_STG_OKTA_DOMAIN.okta-gov.com",  "token_var": "OKTA_ADMIN_STG_API_TOKEN"},
    "prod": {"url": "https://YOUR_PROD_OKTA_DOMAIN.okta-gov.com", "token_var": "OKTA_ADMIN_PROD_API_TOKEN"},
}

# Only surface these app types
APP_SIGN_ON_MODES = {"SAML_2_0", "OPENID_CONNECT"}


class OktaClient:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"SSWS {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    # ── Internals ──────────────────────────────────────────────────────────

    def _get_paginated(self, url: str, params: dict | None = None) -> list:
        results = []
        while url:
            resp = self._session.get(url, params=params)
            self._rate_limit_guard(resp)
            resp.raise_for_status()
            results.extend(resp.json())
            params = None
            url = self._next_link(resp)
        return results

    def _rate_limit_guard(self, resp: requests.Response, retries: int = 4) -> None:
        for _ in range(retries):
            if resp.status_code != 429:
                return
            reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
            time.sleep(max(reset - int(time.time()), 1) + 1)

    @staticmethod
    def _next_link(resp: requests.Response) -> str | None:
        for part in resp.headers.get("Link", "").split(","):
            part = part.strip()
            if 'rel="next"' in part:
                return part.split(";")[0].strip().strip("<>")
        return None

    # ── App listing ────────────────────────────────────────────────────────

    def get_all_apps(self) -> list[dict]:
        """Return all SAML and OIDC apps (paginated)."""
        all_apps = self._get_paginated(
            f"{self.base_url}/api/v1/apps",
            params={"limit": 200}
        )
        return [a for a in all_apps if a.get("signOnMode") in APP_SIGN_ON_MODES]

    # ── Policy data ────────────────────────────────────────────────────────

    def list_access_policies(self) -> list[dict]:
        return self._get_paginated(
            f"{self.base_url}/api/v1/policies",
            params={"type": "ACCESS_POLICY", "limit": 200}
        )

    def get_app_policy_map(self) -> dict[str, dict]:
        """Return {app_id: {policy_id, policy_name}} by iterating access policies (paginated)."""
        mapping: dict[str, dict] = {}
        for p in self.list_access_policies():
            pid = p["id"]
            try:
                apps = self._get_paginated(
                    f"{self.base_url}/api/v1/policies/{pid}/app",
                    params={"limit": 200}
                )
                for app in apps:
                    mapping[app["id"]] = {"policy_id": pid, "policy_name": p["name"]}
            except Exception:
                pass
        return mapping

    # ── Routing rule data ──────────────────────────────────────────────────

    def list_idp_routing_policies(self) -> list[dict]:
        return self._get_paginated(
            f"{self.base_url}/api/v1/policies",
            params={"type": "IDP_DISCOVERY", "limit": 200}
        )

    def list_routing_rules(self, policy_id: str) -> list[dict]:
        return self._get_paginated(
            f"{self.base_url}/api/v1/policies/{policy_id}/rules",
            params={"limit": 200}
        )

    def get_app_routing_rule_map(self) -> dict[str, dict]:
        """Return {app_id: {rule_id, rule_name, policy_id}} from IDP routing rules."""
        mapping: dict[str, dict] = {}
        for policy in self.list_idp_routing_policies():
            pid = policy["id"]
            for rule in self.list_routing_rules(pid):
                includes = rule.get("conditions", {}).get("app", {}).get("include", [])
                for ref in includes:
                    if ref.get("type") == "APP":
                        mapping[ref["id"]] = {
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "policy_id": pid,
                        }
        return mapping

    # ── Mutations ──────────────────────────────────────────────────────────

    def assign_policy_to_app(self, app_id: str, policy_id: str) -> None:
        resp = self._session.put(
            f"{self.base_url}/api/v1/apps/{app_id}/policies/{policy_id}"
        )
        resp.raise_for_status()

    def _get_rule(self, policy_id: str, rule_id: str) -> dict:
        resp = self._session.get(
            f"{self.base_url}/api/v1/policies/{policy_id}/rules/{rule_id}"
        )
        resp.raise_for_status()
        return resp.json()

    def _put_rule(self, policy_id: str, rule_id: str, rule: dict) -> None:
        resp = self._session.put(
            f"{self.base_url}/api/v1/policies/{policy_id}/rules/{rule_id}",
            json=rule
        )
        resp.raise_for_status()

    def add_app_to_routing_rule(self, policy_id: str, rule_id: str, app_id: str) -> None:
        rule = self._get_rule(policy_id, rule_id)
        includes = rule.setdefault("conditions", {}).setdefault("app", {}).setdefault("include", [])
        if not any(r.get("id") == app_id for r in includes):
            includes.append({"id": app_id, "type": "APP"})
            self._put_rule(policy_id, rule_id, rule)

    def remove_app_from_routing_rule(self, policy_id: str, rule_id: str, app_id: str) -> None:
        rule = self._get_rule(policy_id, rule_id)
        includes = rule.get("conditions", {}).get("app", {}).get("include", [])
        filtered = [r for r in includes if r.get("id") != app_id]
        if len(filtered) != len(includes):
            rule["conditions"]["app"]["include"] = filtered
            self._put_rule(policy_id, rule_id, rule)

    def activate_app(self, app_id: str) -> None:
        resp = self._session.post(
            f"{self.base_url}/api/v1/apps/{app_id}/lifecycle/activate"
        )
        resp.raise_for_status()

    def deactivate_app(self, app_id: str) -> None:
        resp = self._session.post(
            f"{self.base_url}/api/v1/apps/{app_id}/lifecycle/deactivate"
        )
        resp.raise_for_status()
