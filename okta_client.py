"""okta_client.py — Okta API client for the App Admin Dashboard."""
from __future__ import annotations

import re
import textwrap
import time
import urllib.parse
import xml.etree.ElementTree as _ET

import requests

OKTA_ENVIRONMENTS = {
    "dev":  {"url": "https://dev-your-org.okta.com",     "token_var": "OKTA_ADMIN_DEV_API_TOKEN"},
    "stg":  {"url": "https://staging-your-org.okta.com", "token_var": "OKTA_ADMIN_STG_API_TOKEN"},
    "prod": {"url": "https://your-org.okta.com",         "token_var": "OKTA_ADMIN_PROD_API_TOKEN"},
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
        self._sso_domain: str | None = None  # cached custom SSO domain

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

    def _post(self, url: str, json: dict, timeout: int = 15, retries: int = 4) -> requests.Response:
        """POST with automatic 429 retry using Okta's X-Rate-Limit-Reset header."""
        for attempt in range(retries + 1):
            resp = self._session.post(url, json=json, timeout=timeout)
            if resp.status_code != 429:
                return resp
            reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
            wait  = max(reset - int(time.time()), 1) + 1
            if attempt < retries:
                time.sleep(wait)
        return resp  # return final 429 if all retries exhausted

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
        return [a for a in all_apps if a.get("signOnMode") in APP_SIGN_ON_MODES or a.get("signOnMode") is None]

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

    def get_app_assignments(self, app_id: str) -> dict:
        """
        Return the effective assignments for an app.
        Prefers groups — if none are assigned, falls back to direct user assignments.
        Returns: {"type": "groups"|"users", "ids": [...]}
        """
        groups = self._get_paginated(f"{self.base_url}/api/v1/apps/{app_id}/groups")
        if groups:
            return {"type": "groups", "ids": [g["id"] for g in groups]}
        users = self._get_paginated(f"{self.base_url}/api/v1/apps/{app_id}/users")
        return {"type": "users", "ids": [u["id"] for u in users]}

    def copy_assignments(self, src_app_id: str, dst_app_id: str) -> dict:
        """
        Copy group or user assignments from src to dst app.
        Returns the assignments dict from get_app_assignments.
        """
        assignments = self.get_app_assignments(src_app_id)
        if assignments["type"] == "groups":
            for gid in assignments["ids"]:
                r = self._session.put(f"{self.base_url}/api/v1/apps/{dst_app_id}/groups/{gid}", json={})
                r.raise_for_status()
        else:
            for uid in assignments["ids"]:
                r = self._session.post(
                    f"{self.base_url}/api/v1/apps/{dst_app_id}/users/{uid}",
                    json={"id": uid, "scope": "USER"},
                )
                r.raise_for_status()
        return assignments

    def create_oin_instance(self, oin_key: str, label: str, legacy_app_settings: dict | None = None) -> dict:
        """Create a new OIN app instance from a catalog template key.

        If the template requires app-level fields (e.g. subdomain) that the legacy
        generic SAML app doesn't have, we auto-derive them from the legacy signOn config
        and retry once.
        """
        from urllib.parse import urlparse

        app_settings: dict = {}
        if legacy_app_settings and legacy_app_settings.get("app"):
            app_settings = dict(legacy_app_settings["app"])

        payload = {
            "name": oin_key,
            "label": label,
            "signOnMode": "SAML_2_0",
            "settings": {"app": app_settings, "signOn": {}},
        }
        resp = self._post(f"{self.base_url}/api/v1/apps", json=payload, timeout=15)

        # If required app-level fields are blank, try to derive them from SAML URLs and retry once
        # Retry on 400 or 403 with "cannot be left blank" — derive missing fields from legacy SAML config
        if resp.status_code in (400, 403) and legacy_app_settings:
            err = resp.json()
            missing = [
                c["errorSummary"].split(":")[0].strip()
                for c in err.get("errorCauses", [])
                if "cannot be left blank" in c.get("errorSummary", "")
            ]
            if missing:
                sso = legacy_app_settings.get("signOn", {})
                acs_url   = sso.get("ssoAcsUrl", "") or sso.get("ssoAcsUrlOverride", "") or ""
                audience  = sso.get("audience", "") or sso.get("audienceOverride", "") or ""
                login_url = sso.get("loginUrl", "") or acs_url

                def _hostname_first(url: str) -> str:
                    h = urlparse(url).hostname or ""
                    return h.split(".")[0] if h else ""

                subdomain = _hostname_first(acs_url) or _hostname_first(audience)
                base_url  = f"{urlparse(acs_url).scheme}://{urlparse(acs_url).hostname}" if acs_url else ""

                derived: dict[str, str] = {
                    # ACS URL — every casing/naming variant seen in OIN templates
                    "acsUrl":              acs_url,
                    "acsURL":              acs_url,
                    "acs_url":             acs_url,
                    "ssoUrl":              acs_url,
                    "ssoAcsUrl":           acs_url,
                    "url":                 acs_url,
                    # Audience / Entity ID variants
                    "audience":            audience,
                    "audUri":              audience,
                    "audienceRestriction": audience,
                    "audience_uri":        audience,
                    "entityId":            audience,
                    "spEntityID":          audience,
                    "spEntityId":          audience,
                    "sp_entity_id":        audience,
                    "issuer":              audience,
                    # Subdomain variants
                    "subdomain":           subdomain,
                    "subDomain":           subdomain,
                    "orgName":             subdomain,
                    "siteName":            subdomain,
                    "environment":         subdomain,
                    "accountName":         subdomain,
                    "companyName":         subdomain,
                    # Login / base URL variants
                    "loginUrl":            login_url,
                    "loginURL":            login_url,
                    "baseUrl":             base_url,
                    "baseURL":             base_url,
                    "siteURL":             audience or acs_url,
                }
                filled: list[str] = []
                for field in missing:
                    if field in derived and derived[field]:
                        payload["settings"]["app"][field] = derived[field]
                        filled.append(f"{field}={derived[field]!r}")

                if filled:
                    resp = self._post(f"{self.base_url}/api/v1/apps", json=payload, timeout=15)

        if not resp.ok:
            raise RuntimeError(
                f"create_oin_instance failed {resp.status_code}: {resp.text[:400]}"
            )
        return resp.json()

    def copy_saml_config(self, legacy_id: str, oin_id: str) -> dict:
        """
        Copy SAML sign-on config from legacy custom app to OIN instance.
        Uses override fields (OIN templates). Silently skips fields the
        template locks (403) — some OIN apps (e.g. Box) manage config SP-side.
        Returns {"copied": [...], "skipped": [...], "locked": bool}
        """
        legacy_sso = self.get_app(legacy_id).get("settings", {}).get("signOn", {})
        oin        = self.get_app(oin_id)
        oin_sso    = oin.setdefault("settings", {}).setdefault("signOn", {})

        oin_sso["ssoAcsUrlOverride"]   = legacy_sso.get("ssoAcsUrl")
        oin_sso["audienceOverride"]    = legacy_sso.get("audience")
        oin_sso["recipientOverride"]   = legacy_sso.get("recipient")
        oin_sso["destinationOverride"] = legacy_sso.get("destination")
        oin_sso["attributeStatements"] = legacy_sso.get("attributeStatements", [])

        resp = self._session.put(f"{self.base_url}/api/v1/apps/{oin_id}", json=oin, timeout=15)
        if resp.status_code in (400, 403):
            # Template locked or doesn't accept overrides — SP manages config
            return {"locked": True, "copied": [], "skipped": ["ssoAcsUrl", "audience", "recipient", "destination", "attributeStatements"]}
        resp.raise_for_status()
        return {"locked": False, "copied": ["ssoAcsUrl", "audience", "recipient", "destination", "attributeStatements"], "skipped": []}

    def copy_policy(self, legacy_id: str, oin_id: str, policy_map: dict) -> str | None:
        """Assign the same auth policy from legacy app to OIN instance. Returns policy name or None."""
        pol = policy_map.get(legacy_id)
        if not pol:
            return None
        resp = self._session.put(f"{self.base_url}/api/v1/apps/{oin_id}/policies/{pol['policy_id']}")
        resp.raise_for_status()
        return pol["policy_name"]

    def copy_routing_rule(self, legacy_id: str, oin_id: str, routing_map: dict) -> str | None:
        """Add OIN instance to the same routing rule as the legacy app. Returns rule name or None."""
        rt = routing_map.get(legacy_id)
        if not rt:
            return None
        self.add_app_to_routing_rule(rt["policy_id"], rt["rule_id"], oin_id)
        return rt["rule_name"]

    # ── Rename ────────────────────────────────────────────────────────────────

    def get_app(self, app_id: str) -> dict:
        resp = self._session.get(f"{self.base_url}/api/v1/apps/{app_id}")
        resp.raise_for_status()
        return resp.json()

    def rename_app(self, app_id: str, new_label: str) -> dict:
        """Rename an app label (GET full object + PUT back with new label)."""
        app_data = self.get_app(app_id)
        app_data["label"] = new_label
        resp = self._session.put(
            f"{self.base_url}/api/v1/apps/{app_id}",
            json=app_data,
        )
        resp.raise_for_status()
        return resp.json()

    def deactivate_app(self, app_id: str) -> None:
        resp = self._session.post(f"{self.base_url}/api/v1/apps/{app_id}/lifecycle/deactivate")
        resp.raise_for_status()

    def delete_app(self, app_id: str) -> None:
        resp = self._session.delete(f"{self.base_url}/api/v1/apps/{app_id}")
        resp.raise_for_status()

    # ── Notes ────────────────────────────────────────────────────────────────

    def get_app_note(self, app_id: str) -> str:
        """Return the admin notes string for an app, or empty string."""
        app_data = self.get_app(app_id)
        return (app_data.get("notes") or {}).get("admin") or ""

    def set_app_note(self, app_id: str, note: str) -> dict:
        """Write admin note to the app. Empty string clears it."""
        app_data = self.get_app(app_id)
        if "notes" not in app_data or app_data["notes"] is None:
            app_data["notes"] = {}
        app_data["notes"]["admin"] = note or None
        resp = self._session.put(f"{self.base_url}/api/v1/apps/{app_id}", json=app_data)
        resp.raise_for_status()
        return resp.json()

    # ── Dashboard visibility ──────────────────────────────────────────────────

    def set_app_visibility(self, app_id: str, hide: bool) -> dict:
        """Show or hide the app tile in the Okta user dashboard.
        hide=True  → app NOT shown on dashboard
        hide=False → app shown on dashboard
        """
        app_data = self.get_app(app_id)
        vis = app_data.setdefault("visibility", {})
        vis.setdefault("hide", {})["web"] = hide
        vis["hide"]["iOS"] = hide
        resp = self._session.put(f"{self.base_url}/api/v1/apps/{app_id}", json=app_data)
        if not resp.ok:
            try:
                detail = resp.json().get("errorSummary") or resp.text[:200]
            except Exception:
                detail = resp.text[:200]
            raise RuntimeError(f"{resp.status_code} {detail}")
        return resp.json()

    # ── SP Config ─────────────────────────────────────────────────────────────

    def _get_sso_domain(self) -> str:
        """Return the custom SSO domain (e.g. login-dev.example.gov). Cached per instance."""
        if self._sso_domain is not None:
            return self._sso_domain
        try:
            resp = self._session.get(f"{self.base_url}/api/v1/domains", timeout=10)
            resp.raise_for_status()
            domains = resp.json().get("domains", [])
            # Use the first non-default custom domain
            custom = next((d["domain"] for d in domains if d.get("id") != "default"), None)
            self._sso_domain = f"https://{custom}" if custom else self.base_url
        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).warning("domains fetch failed: %s", e)
            self._sso_domain = self.base_url
        return self._sso_domain

    def _fetch_and_parse_metadata(self, api_metadata_url: str) -> dict:
        """Fetch IDP metadata XML (authenticated) and parse out IDP values in Python.
        Returns dict with idp_entity_id, idp_sso_url, cert_pem, key_id. Empty strings on failure."""
        _NS = {
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
        }
        empty = {'idp_entity_id': '', 'idp_sso_url': '', 'cert_pem': '', 'key_id': ''}
        try:
            resp = self._session.get(api_metadata_url, timeout=15,
                                     headers={"Accept": "application/xml", "Content-Type": None})
            resp.raise_for_status()
            root = _ET.fromstring(resp.content)

            idp_entity_id = root.get('entityID', '')
            key_id = idp_entity_id.rsplit('/', 1)[-1] if idp_entity_id else ''

            idp_sso_url = ''
            for sso in root.findall('.//md:SingleSignOnService', _NS):
                binding = sso.get('Binding', '')
                loc     = sso.get('Location', '')
                if 'HTTP-POST' in binding:
                    idp_sso_url = loc
                    break
                if 'HTTP-Redirect' in binding and not idp_sso_url:
                    idp_sso_url = loc

            cert_pem = ''
            for kd in root.findall('.//md:KeyDescriptor', _NS):
                if kd.get('use', 'signing') == 'signing':
                    x509 = kd.find('.//ds:X509Certificate', _NS)
                    if x509 is not None and x509.text:
                        b64 = x509.text.replace('\n', '').replace('\r', '').strip()
                        wrapped = '\n'.join(textwrap.wrap(b64, 64))
                        cert_pem = f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"
                        break

            return {'idp_entity_id': idp_entity_id, 'idp_sso_url': idp_sso_url,
                    'cert_pem': cert_pem, 'key_id': key_id}
        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).warning("metadata fetch/parse failed for %s: %s", api_metadata_url, e)
            return empty

    def get_saml_config(self, app_id: str) -> dict:
        """Return SP configuration data for a SAML app, with IDP values parsed from metadata XML."""
        app_data = self.get_app(app_id)
        name     = app_data.get("name", "")
        label    = app_data.get("label", "")
        status   = app_data.get("status", "ACTIVE")
        sign_on  = (app_data.get("settings") or {}).get("signOn") or {}

        is_oin = not name.startswith("template_")

        # Fetch and parse metadata once via authenticated API URL
        api_metadata_url = ((app_data.get("_links") or {}).get("metadata") or {}).get("href") or ""
        meta = self._fetch_and_parse_metadata(api_metadata_url) if api_metadata_url else \
               {'idp_entity_id': '', 'idp_sso_url': '', 'cert_pem': '', 'key_id': ''}

        # Build public metadata URL: prefer exk key_id path, fall back to name/id path.
        # Always use the custom SSO domain (not self.base_url which is the admin API domain).
        sso_domain = self._get_sso_domain()
        if meta['key_id']:
            metadata_url = f"{sso_domain}/app/{meta['key_id']}/sso/saml/metadata"
        else:
            metadata_url = f"{sso_domain}/app/{name}/{app_id}/sso/saml/metadata"

        acs_url = (sign_on.get("ssoAcsUrlOverride") or sign_on.get("ssoAcsUrl") or "")
        entity_id    = (sign_on.get("audienceOverride") or sign_on.get("audience") or "")
        nameid_format = sign_on.get("subjectNameIdFormat", "")
        attr_stmts   = sign_on.get("attributeStatements") or []

        return {
            "app_id":        app_id,
            "label":         label,
            "name":          name,
            "status":        status,
            "is_oin":        is_oin,
            "metadata_url":  metadata_url,
            "acs_url":       acs_url,
            "entity_id":     entity_id,
            "nameid_format": nameid_format,
            "attr_stmts":    attr_stmts,
            "idp_entity_id": meta['idp_entity_id'],
            "idp_sso_url":   meta['idp_sso_url'],
            "cert_pem":      meta['cert_pem'],
        }

    # ── OIN catalog ───────────────────────────────────────────────────────────

    # SSO sign-on modes that indicate an OIN app supports federated login
    _SSO_MODES = {"SAML_2_0", "OPENID_CONNECT", "AUTO_LOGIN", "SECURE_PASSWORD_STORE"}
    # Strict federation modes — SAML and OIDC only; used for sso_signal and
    # keeping unverified apps that explicitly declare federation capability.
    _FEDERATION_MODES = {"SAML_2_0", "OPENID_CONNECT"}
    # Fallback keywords if signOnModes is absent from the catalog response
    _SSO_KEYWORDS = {"saml", "sso", "single sign-on", "openid", "oidc"}

    def _oin_has_sso(self, item: dict) -> bool:
        """Return True if the catalog item supports SSO (SAML or OIDC).

        The Okta catalog list API frequently returns signOnModes=[] even for apps
        that fully support SAML/OIDC (e.g. OpenAI). Only reject when signOnModes
        is populated AND contains no SSO modes — provisioning-only apps with empty
        modes are caught downstream by _PROVISIONING_PATTERNS.
        """
        modes = set(item.get("signOnModes") or [])
        if not modes:
            return True  # empty = unknown; don't filter — let provisioning pattern catch SCIM-only
        return bool(modes & self._SSO_MODES)

    # Provisioning-only connectors to exclude (not SSO migration targets)
    _PROVISIONING_PATTERNS = re.compile(
        r'provisioning connector|by aquera', re.IGNORECASE
    )
    # Gov/Fed variants are always kept as valid candidates
    _GOV_PATTERNS = re.compile(
        r'\b(gov(ernment)?|fed(eral)?)\b', re.IGNORECASE
    )

    # Label-to-search-term overrides for known acronyms and label mismatches.
    # Keys are lowercased first-word of the app label (after stripping [LEGACY]).
    # Values are the search term to use instead.
    _LABEL_SEARCH_MAP: dict[str, str] = {
        "csod":          "Cornerstone OnDemand",
        "csodfed":       "Cornerstone OnDemand",   # CSODFed-TAM etc.
        "litmos":        "Litmos",
        "stackoverflow": "Stack Overflow for Teams",
        "stackoverflows": "Stack Overflow for Teams",
        "lexis":         "LexisNexis",
        "westlaw":       "WestLaw",
        "westlawnext":   "WestLaw",
        "symplicity":    "Symplicity",
        "sympliciy":     "Symplicity",              # typo in actual Okta label
        "sans":          "Litmos",                  # SANS Training runs on Litmos
        "gcp":           "Google Cloud Platform",
        "lfts2":         "Kiteworks",               # LFTS2 (Kiteworks)
        "ucc-cisco-expressway": "Cisco Expressway",
        "ucc-cuc":       "Cisco Unity Connection",  # UCC-CUC-A/B/C/D
        "ucc-cucm":      "Cisco Unified Communications Manager",
        "ucc-cisco-ucce": "Cisco Unified Contact Center Enterprise",
        "onestream":     "OneStream",
        "keycloak":      "Vyopta",                  # KeyCloak Vyopta SSO — underlying app is Vyopta
        "open":          "OpenAI",                  # "Open AI" (space) → search OpenAI specifically; OIN app is SCIM-only → no_match
    }

    def search_oin_catalog(self, name: str, limit: int = 20) -> list[dict]:
        """
        Search the Okta Integration Network catalog for matching apps.
        Filters applied:
          1. SSO only — SAML or OIDC capable (no pure provisioning/SCIM)
          2. Word boundary — search term must appear as a whole word in the
             OIN display name (e.g. "Keeper" won't match "Gatekeeper")
          3. No Aquera/provisioning connectors
          4. When an exact + verified match exists, drop non-exact others
             UNLESS they contain Gov/Fed (government variants are always kept)
        Returns [] on error or no results.
        """
        # Normalize via override map before extracting first word.
        # Strip hyphens from the first token so "CSOD-Pilot" → key "csod",
        # and "UCC-Vyopta" → key "ucc-vyopta" (hyphenated keys kept as-is).
        name_stripped = name.strip()
        raw_first = name_stripped.split()[0].lower() if name_stripped else ""
        # Try exact first-token match first (e.g. "ucc-vyopta"), then
        # split on hyphen for acronym-prefixed labels (e.g. "csod-pilot" → "csod").
        first_word_lower = raw_first if raw_first in self._LABEL_SEARCH_MAP \
            else raw_first.split('-')[0]
        if first_word_lower in self._LABEL_SEARCH_MAP:
            name_stripped = self._LABEL_SEARCH_MAP[first_word_lower]

        # Search and boundary-check on the first word — "Box Enterprise Plus"
        # should search for "Box" and match the OIN app "Box", not require
        # the full phrase in the display name or the catalog search.
        first_word = name_stripped.split()[0] if name_stripped else name_stripped
        q = urllib.parse.quote(first_word)
        word_re = re.compile(r'\b' + re.escape(first_word) + r'\b', re.IGNORECASE)
        try:
            resp = self._session.get(
                f"{self.base_url}/api/v1/catalog/apps?q={q}&limit={limit}",
                timeout=10,
            )
            resp.raise_for_status()
            items = resp.json() or []
            name_lower = name_stripped.lower()
            results = []
            _sso_kw_re = re.compile(r'\b(saml|oidc|sso|single sign.?on|openid)\b', re.IGNORECASE)
            for item in items:
                if not self._oin_has_sso(item):
                    continue
                display = item.get("displayName", "")
                if not word_re.search(display):
                    continue
                if self._PROVISIONING_PATTERNS.search(display):
                    continue
                base_name  = name_lower.split(' - ')[0].strip()
                modes      = set(item.get("signOnModes") or [])
                desc       = item.get("description") or ""
                # federation: explicitly declares SAML_2_0 or OPENID_CONNECT
                federation = bool(modes & self._FEDERATION_MODES)
                # sso_signal: federation mode, SSO keyword in name, or SSO keyword in description
                sso_signal = (
                    federation
                    or bool(_sso_kw_re.search(display))
                    or bool(_sso_kw_re.search(desc))
                )
                # primary: display name starts with the search term's first word —
                # filters out apps where the vendor name appears only as an integration
                # target (e.g. "Five9 Plus Adapter for ServiceNow" is not a ServiceNow app)
                primary = display.lower().startswith(first_word.lower())
                results.append({
                    "name":        item.get("name", ""),
                    "displayName": display,
                    "category":    item.get("category", ""),
                    "verified":    item.get("verificationStatus") == "OKTA_VERIFIED",
                    "exact":       display.lower() == name_lower or display.lower() == base_name,
                    "gov":         bool(self._GOV_PATTERNS.search(display)),
                    "sso_named":   sso_signal,
                    "federation":  federation,
                    "primary":     primary,
                })

            # If any candidate is both federation AND primary (display starts with the
            # search term), prefer those — eliminates integration adapters like
            # "Five9 Plus Adapter for ServiceNow" where the vendor name is incidental.
            if any(r["federation"] and r["primary"] for r in results):
                results = [r for r in results if r["federation"] and r["primary"]]
            elif any(r["federation"] for r in results):
                results = [r for r in results if r["federation"]]
            elif any(r["sso_named"] for r in results):
                results = [r for r in results if r["sso_named"]]

            # Drop unverified non-exact results, UNLESS the app explicitly declares
            # SAML/OIDC — an unverified app with federation in signOnModes is still
            # a valid migration target.
            results = [r for r in results if r["verified"] or r["exact"] or r["federation"]]

            # When an exact + verified match exists, drop non-exact results
            # unless they are a Gov/Fed variant
            has_exact_verified = any(r["exact"] and r["verified"] for r in results)
            if has_exact_verified:
                results = [r for r in results if r["exact"] or r["gov"]]

            return results
        except Exception:
            return []
