from __future__ import annotations

import logging
import re
import textwrap
import time
import urllib.parse
import xml.etree.ElementTree as _ET

import requests

log = logging.getLogger(__name__)

APP_SIGN_ON_MODES = {
    "SAML_2_0", "SAML_1_1", "OPENID_CONNECT",
    "BROWSER_PLUGIN", "AUTO_LOGIN", "SECURE_PASSWORD_STORE", "BOOKMARK",
    "WS_FEDERATION", "RADIUS_FOR_GENERIC_APP",
}


class OktaClient:
    def __init__(self, base_url: str, api_token: str, session: requests.Session):
        self.base_url = base_url.rstrip("/")
        self._session = session
        self._session.headers["Authorization"] = f"SSWS {api_token}"
        self._session.headers["Content-Type"] = "application/json"
        self._sso_domain: str | None = None


    def _get_paginated(self, url: str, params: dict | None = None) -> list:
        results = []
        while url:
            resp = self._request_with_retry("GET", url, params=params)
            resp.raise_for_status()
            results.extend(resp.json())
            params = None
            url = self._next_link(resp)
        return results

    def _request_with_retry(self, method: str, url: str, *, retries: int = 4,
                            **kwargs) -> requests.Response:
        resp = None
        for attempt in range(retries + 1):
            resp = self._session.request(method, url, **kwargs)
            if resp.status_code != 429:
                break
            reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
            wait = max(reset - int(time.time()), 1) + 1
            if attempt < retries:
                time.sleep(wait)
        try:
            remaining = int(resp.headers.get("X-Rate-Limit-Remaining", "999"))
        except (TypeError, ValueError):
            remaining = 999
        if remaining <= 5:
            reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 2))
            time.sleep(max(reset - int(time.time()), 0) + 1)
        return resp

    def _post(self, url: str, json: dict, timeout: int = 15, retries: int = 4) -> requests.Response:
        return self._request_with_retry("POST", url, json=json, timeout=timeout, retries=retries)

    @staticmethod
    def _next_link(resp: requests.Response) -> str | None:
        for part in resp.headers.get("Link", "").split(","):
            part = part.strip()
            if 'rel="next"' in part:
                return part.split(";")[0].strip().strip("<>")
        return None


    def get_all_apps(self) -> list[dict]:
        all_apps = self._get_paginated(
            f"{self.base_url}/api/v1/apps",
            params={"limit": 200}
        )
        return [a for a in all_apps if a.get("signOnMode") in APP_SIGN_ON_MODES or a.get("signOnMode") is None]


    def list_access_policies(self) -> list[dict]:
        return self._get_paginated(
            f"{self.base_url}/api/v1/policies",
            params={"type": "ACCESS_POLICY", "limit": 200}
        )

    def get_app_policy_map(self) -> dict[str, dict]:
        import logging as _log
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
            except Exception as e:
                _log.getLogger(__name__).warning(
                    "policy->app fetch failed for policy %s (%s); its apps are "
                    "OMITTED from the policy map", pid, e)
        return mapping


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

    def get_app_assignments(self, app_id: str) -> dict:
        groups = self._get_paginated(f"{self.base_url}/api/v1/apps/{app_id}/groups")
        if groups:
            return {"type": "groups", "ids": [g["id"] for g in groups]}
        users = self._get_paginated(f"{self.base_url}/api/v1/apps/{app_id}/users")
        return {"type": "users", "ids": [u["id"] for u in users]}

    def copy_assignments(self, src_app_id: str, dst_app_id: str) -> dict:
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


    def get_group(self, group_id: str) -> dict:
        resp = self._request_with_retry("GET", f"{self.base_url}/api/v1/groups/{group_id}")
        resp.raise_for_status()
        return resp.json()

    def list_app_groups(self, app_id: str) -> list[dict]:
        return self._get_paginated(
            f"{self.base_url}/api/v1/apps/{app_id}/groups",
            params={"limit": 200},
        )

    def list_app_user_assignments(self, app_id: str) -> list[dict]:
        return self._get_paginated(
            f"{self.base_url}/api/v1/apps/{app_id}/users",
            params={"limit": 500},
        )

    def first_page_user_assignments(self, app_id: str) -> tuple[list[dict], bool]:
        resp = self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/apps/{app_id}/users",
            params={"limit": 500},
        )
        resp.raise_for_status()
        items = resp.json()
        if not isinstance(items, list):
            items = []
        return items, bool(self._next_link(resp))

    def recent_membership_remove_count(self, app_id: str, minutes: int = 5) -> int:
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        filt = (
            f'target.id eq "{app_id}" and '
            f'eventType eq "application.user_membership.remove"'
        )
        resp = self._request_with_retry(
            "GET",
            f"{self.base_url}/api/v1/logs",
            params={"since": since, "filter": filt, "limit": 1},
        )
        resp.raise_for_status()
        items = resp.json() if isinstance(resp.json(), list) else []
        return len(items) + (1 if self._next_link(resp) else 0)

    def get_groups_id_name_map(self) -> dict[str, dict]:
        groups = self._get_paginated(
            f"{self.base_url}/api/v1/groups",
            params={"limit": 200},
        )
        out: dict[str, dict] = {}
        for g in groups:
            gid = g.get("id")
            if not gid:
                continue
            out[gid] = {
                "name": (g.get("profile") or {}).get("name") or "?",
                "type": g.get("type") or "?",
            }
        return out

    def everyone_decision(self, app_id: str, group_map: dict[str, dict]) -> dict:
        assigned = self.list_app_groups(app_id)
        names: list[str] = []
        other: list[str] = []
        has_everyone = False
        for ag in assigned:
            gid = ag.get("id")
            if not gid:
                continue
            meta = group_map.get(gid) or {}
            name = meta.get("name") or "?"
            gtype = meta.get("type") or "?"
            names.append(name)
            if name == "Everyone" and gtype == "BUILT_IN":
                has_everyone = True
            else:
                other.append(name)
        return {
            "has_everyone": has_everyone,
            "groups": names,
            "other_groups": other,
            "everyone_only": has_everyone and not other,
        }

    def find_everyone_group_on_app(self, app_id: str) -> dict | None:
        for ag in self.list_app_groups(app_id):
            gid = ag.get("id")
            if not gid:
                continue
            try:
                g = self.get_group(gid)
            except Exception:  # noqa: BLE001 - one bad group must not stop the scan
                log.warning("could not read group %s; skipping it", gid, exc_info=True)
                continue
            name = (g.get("profile") or {}).get("name") or ""
            gtype = g.get("type") or ""
            if name == "Everyone" and gtype == "BUILT_IN":
                return g
        return None

    def remove_group_from_app(self, app_id: str, group_id: str) -> bool:
        resp = self._request_with_retry("DELETE", f"{self.base_url}/api/v1/apps/{app_id}/groups/{group_id}")
        if resp.status_code in (204, 200, 404):
            return True
        resp.raise_for_status()
        return False

    def delete_user_app_assignment(self, app_id: str, user_id: str) -> tuple[bool, str | None]:
        resp = self._request_with_retry("DELETE", f"{self.base_url}/api/v1/apps/{app_id}/users/{user_id}")
        if resp.status_code in (204, 200, 404):
            return True, None
        try:
            err = (resp.json() or {}).get("errorCode") or "?"
        except Exception:
            err = "?"
        return False, f"HTTP {resp.status_code} {err}"

    def clear_app_assignments(self, app_id: str) -> dict:
        everyone = self.find_everyone_group_on_app(app_id)
        first_page, more_pages = self.first_page_user_assignments(app_id)
        user_scope = [u for u in first_page if u.get("scope") == "USER"]
        group_scope_count = sum(1 for u in first_page if u.get("scope") == "GROUP")

        everyone_removed = False
        if everyone:
            everyone_removed = self.remove_group_from_app(app_id, everyone["id"])

        user_deleted = 0
        user_failed = 0
        fail_codes: dict[str, int] = {}
        for u in user_scope:
            uid = u.get("id")
            if not uid:
                continue
            ok, err = self.delete_user_app_assignment(app_id, uid)
            if ok:
                user_deleted += 1
            else:
                user_failed += 1
                fail_codes[err or "?"] = fail_codes.get(err or "?", 0) + 1

        return {
            "everyone_was_assigned": everyone is not None,
            "everyone_removed": everyone_removed,
            "user_scope_total": len(user_scope),
            "user_scope_deleted": user_deleted,
            "user_scope_failed": user_failed,
            "user_scope_fail_codes": fail_codes,
            "group_scope_will_orphan": group_scope_count,
            "more_records_after_first_page": more_pages,
        }

    def create_oin_instance(self, oin_key: str, label: str, legacy_app_settings: dict | None = None) -> dict:
        from urllib.parse import urlparse

        app_settings: dict = {}
        if legacy_app_settings and legacy_app_settings.get("app"):
            app_settings = dict(legacy_app_settings["app"])

        try:
            existing = self._get_paginated(
                f"{self.base_url}/api/v1/apps",
                params={"q": label, "limit": 20},
            )
            for a in existing:
                if a.get("name") == oin_key and a.get("label") == label:
                    return a
        except Exception:
            import logging as _log
            _log.getLogger(__name__).warning(
                "create_oin_instance preflight lookup failed for %r; proceeding to create", label)

        payload = {
            "name": oin_key,
            "label": label,
            "signOnMode": "SAML_2_0",
            "settings": {"app": app_settings, "signOn": {}},
        }
        resp = self._post(f"{self.base_url}/api/v1/apps", json=payload, timeout=15)

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
                    "acsUrl":              acs_url,
                    "acsURL":              acs_url,
                    "acs_url":             acs_url,
                    "ssoUrl":              acs_url,
                    "ssoAcsUrl":           acs_url,
                    "url":                 acs_url,
                    "audience":            audience,
                    "audUri":              audience,
                    "audienceRestriction": audience,
                    "audience_uri":        audience,
                    "entityId":            audience,
                    "spEntityID":          audience,
                    "spEntityId":          audience,
                    "sp_entity_id":        audience,
                    "issuer":              audience,
                    "subdomain":           subdomain,
                    "subDomain":           subdomain,
                    "orgName":             subdomain,
                    "siteName":            subdomain,
                    "environment":         subdomain,
                    "accountName":         subdomain,
                    "companyName":         subdomain,
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
        legacy_sso = self.get_app(legacy_id).get("settings", {}).get("signOn", {})
        oin        = self.get_app(oin_id)
        oin_sso    = oin.setdefault("settings", {}).setdefault("signOn", {})

        oin_sso["ssoAcsUrlOverride"]   = legacy_sso.get("ssoAcsUrl")
        oin_sso["audienceOverride"]    = legacy_sso.get("audience")
        oin_sso["recipientOverride"]   = legacy_sso.get("recipient")
        oin_sso["destinationOverride"] = legacy_sso.get("destination")
        oin_sso["attributeStatements"] = legacy_sso.get("attributeStatements", [])

        fields = ["ssoAcsUrl", "audience", "recipient", "destination", "attributeStatements"]
        resp = self._session.put(f"{self.base_url}/api/v1/apps/{oin_id}", json=oin, timeout=15)
        if resp.status_code in (400, 403):
            try:
                err = resp.json() or {}
            except Exception:
                err = {}
            code = err.get("errorCode", "")
            if code in ("E0000006", "E0000015") or resp.status_code == 401:
                raise PermissionError(
                    f"copy_saml_config denied for {oin_id}: HTTP {resp.status_code} {code} "
                    f"{err.get('errorSummary', '')}".strip())
            return {"locked": True, "copied": [], "skipped": fields,
                    "reason": f"HTTP {resp.status_code} {code} {err.get('errorSummary', '')}".strip()}
        resp.raise_for_status()
        return {"locked": False, "copied": fields, "skipped": []}

    def copy_policy(self, legacy_id: str, oin_id: str, policy_map: dict) -> str | None:
        pol = policy_map.get(legacy_id)
        if not pol:
            return None
        resp = self._session.put(f"{self.base_url}/api/v1/apps/{oin_id}/policies/{pol['policy_id']}")
        resp.raise_for_status()
        return pol["policy_name"]

    def copy_routing_rule(self, legacy_id: str, oin_id: str, routing_map: dict) -> str | None:
        rt = routing_map.get(legacy_id)
        if not rt:
            return None
        self.add_app_to_routing_rule(rt["policy_id"], rt["rule_id"], oin_id)
        return rt["rule_name"]


    def get_app(self, app_id: str) -> dict:
        resp = self._session.get(f"{self.base_url}/api/v1/apps/{app_id}")
        resp.raise_for_status()
        return resp.json()

    def rename_app(self, app_id: str, new_label: str) -> dict:
        app_data = self.get_app(app_id)
        app_data["label"] = new_label
        resp = self._session.put(
            f"{self.base_url}/api/v1/apps/{app_id}",
            json=app_data,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _safe_id(value: str) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9]+", value):
            raise ValueError(f"invalid Okta id: {value!r}")
        return value

    def deactivate_app(self, app_id: str) -> None:
        app_id = self._safe_id(app_id)
        resp = self._session.post(f"{self.base_url}/api/v1/apps/{app_id}/lifecycle/deactivate")
        resp.raise_for_status()

    def delete_app(self, app_id: str) -> None:
        app_id = self._safe_id(app_id)
        resp = self._session.delete(f"{self.base_url}/api/v1/apps/{app_id}")
        resp.raise_for_status()


    def get_app_note(self, app_id: str) -> str:
        app_data = self.get_app(app_id)
        return (app_data.get("notes") or {}).get("admin") or ""

    def set_app_note(self, app_id: str, note: str) -> dict:
        app_data = self.get_app(app_id)
        if "notes" not in app_data or app_data["notes"] is None:
            app_data["notes"] = {}
        app_data["notes"]["admin"] = note or None
        resp = self._session.put(f"{self.base_url}/api/v1/apps/{app_id}", json=app_data)
        resp.raise_for_status()
        return resp.json()


    def set_app_visibility(self, app_id: str, hide: bool) -> dict:
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


    def _get_sso_domain(self) -> str:
        if self._sso_domain is not None:
            return self._sso_domain
        try:
            resp = self._session.get(f"{self.base_url}/api/v1/domains", timeout=10)
            resp.raise_for_status()
            domains = resp.json().get("domains", [])
            custom = next((d["domain"] for d in domains if d.get("id") != "default"), None)
            self._sso_domain = f"https://{custom}" if custom else self.base_url
        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).warning("domains fetch failed: %s", e)
            self._sso_domain = self.base_url
        return self._sso_domain

    def _fetch_and_parse_metadata(self, api_metadata_url: str) -> dict:
        _NS = {
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
        }
        empty = {'idp_entity_id': '', 'idp_sso_url': '', 'cert_pem': '', 'key_id': '', 'error': ''}
        meta_host = urllib.parse.urlparse(api_metadata_url).hostname
        tenant_host = urllib.parse.urlparse(self.base_url).hostname
        if meta_host != tenant_host:
            import logging as _log
            _log.getLogger(__name__).warning(
                "refusing to fetch metadata off-tenant: %s (tenant %s)", meta_host, tenant_host)
            return {**empty, 'error': f"metadata host {meta_host} is not the tenant host"}
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
                    'cert_pem': cert_pem, 'key_id': key_id, 'error': ''}
        except Exception as e:
            import logging as _log
            _log.getLogger(__name__).warning("metadata fetch/parse failed for %s: %s", api_metadata_url, e)
            return {**empty, 'error': f"{type(e).__name__}: {e}"}

    def get_saml_config(self, app_id: str) -> dict:
        app_data = self.get_app(app_id)
        name     = app_data.get("name", "")
        label    = app_data.get("label", "")
        status   = app_data.get("status", "ACTIVE")
        sign_on  = (app_data.get("settings") or {}).get("signOn") or {}

        is_oin = not name.startswith("template_")

        api_metadata_url = ((app_data.get("_links") or {}).get("metadata") or {}).get("href") or ""
        meta = self._fetch_and_parse_metadata(api_metadata_url) if api_metadata_url else \
               {'idp_entity_id': '', 'idp_sso_url': '', 'cert_pem': '', 'key_id': '',
                'error': 'no metadata href on app'}

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
            "idp_metadata_error": meta.get('error', ''),
        }


    _SSO_MODES = {"SAML_2_0", "OPENID_CONNECT", "AUTO_LOGIN", "SECURE_PASSWORD_STORE"}
    _FEDERATION_MODES = {"SAML_2_0", "OPENID_CONNECT"}
    _SSO_KEYWORDS = {"saml", "sso", "single sign-on", "openid", "oidc"}

    def _oin_has_sso(self, item: dict) -> bool:
        modes = set(item.get("signOnModes") or [])
        if not modes:
            return True
        return bool(modes & self._SSO_MODES)

    _PROVISIONING_PATTERNS = re.compile(
        r'provisioning connector|by aquera', re.IGNORECASE
    )
    _GOV_PATTERNS = re.compile(
        r'\b(gov(ernment)?|fed(eral)?)\b', re.IGNORECASE
    )

    _LABEL_SEARCH_MAP: dict[str, str] = {}

    def search_oin_catalog(self, name: str, limit: int = 20) -> list[dict]:
        name_stripped = name.strip()
        raw_first = name_stripped.split()[0].lower() if name_stripped else ""
        first_word_lower = raw_first if raw_first in self._LABEL_SEARCH_MAP \
            else raw_first.split('-')[0]
        if first_word_lower in self._LABEL_SEARCH_MAP:
            name_stripped = self._LABEL_SEARCH_MAP[first_word_lower]

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
                federation = bool(modes & self._FEDERATION_MODES)
                sso_signal = (
                    federation
                    or bool(_sso_kw_re.search(display))
                    or bool(_sso_kw_re.search(desc))
                )
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

            if any(r["federation"] and r["primary"] for r in results):
                results = [r for r in results if r["federation"] and r["primary"]]
            elif any(r["federation"] for r in results):
                results = [r for r in results if r["federation"]]
            elif any(r["sso_named"] for r in results):
                results = [r for r in results if r["sso_named"]]

            results = [r for r in results if r["verified"] or r["exact"] or r["federation"]]

            has_exact_verified = any(r["exact"] and r["verified"] for r in results)
            if has_exact_verified:
                results = [r for r in results if r["exact"] or r["gov"]]

            return results
        except Exception:
            return []
