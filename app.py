"""
app.py — Okta Admin

Local run:    .venv/bin/python app.py     # http://localhost:5002
ACA URL:      https://okta-admin.your-env.eastus.azurecontainerapps.io

Auth posture (v2.0.0+):
  PROD Okta OIDC gate via the shared "Okta Admin Tools" app. Authlib
  drives the OAuth flow and validates the id_token. If any of the OIDC
  env vars is missing the gate disables itself (open posture) so the
  tool stays usable when running locally without OIDC.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("okta-admin")

# ── Action logger — file (in-container, ephemeral on restart) + stdout (Azure
# Container App logs capture this for durable audit history). ────────────────
_alog = logging.getLogger("okta.admin.actions")
_alog.setLevel(logging.INFO)
_alog.propagate = False
_ah = logging.FileHandler(Path(__file__).parent / "okta-admin-actions.log", encoding="utf-8")
_ah.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
_alog.addHandler(_ah)
_as = logging.StreamHandler(sys.stdout)
_as.setFormatter(logging.Formatter("ACTION | %(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
_alog.addHandler(_as)

def _log_action(env: str, action: str, label: str, outcome: str, detail: str = "") -> None:
    _alog.info("%-5s| %-12s| %-40s| %-10s| %s",
               env.upper()[:5], action[:12], label[:40], outcome[:10], detail)

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import (
    Flask, jsonify, redirect, render_template, render_template_string,
    request, Response, session, stream_with_context, url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import keyring as _keyring
    KEYRING_SERVICE = "okta-app-admin"
except ImportError:
    _keyring = None  # type: ignore
    KEYRING_SERVICE = ""

load_dotenv(Path(__file__).parent / ".env")

sys.path.insert(0, str(Path(__file__).parent))
from okta_client import OKTA_ENVIRONMENTS, OktaClient
from wes_tools_http import make_session
from wes_tools_docs import register_howto

APP_VERSION = "2.1.6"

# ── Auth-count source: the Okta Migration Realtime tool's persisted unit_index
#    in Azure Tables (table `oktamigrationunits`, PartitionKey = env). Lazy
#    init so the app stays usable if storage is unreachable / not configured.
AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", "").strip()
TABLE_UNITS = os.environ.get("TABLE_UNITS", "oktamigrationunits")
_units_table = None
if AZURE_STORAGE_CONNECTION_STRING:
    try:
        import urllib3 as _urllib3
        _urllib3.disable_warnings()
        from azure.data.tables import TableServiceClient
        from azure.core.pipeline.transport import RequestsTransport
        # verify=False to dodge AnyConnect TLS inspection when running locally
        # behind VPN; inside ACA this is a no-op.
        _transport = RequestsTransport(connection_verify=False)
        _tbl_svc = TableServiceClient.from_connection_string(
            AZURE_STORAGE_CONNECTION_STRING, transport=_transport)
        _units_table = _tbl_svc.get_table_client(TABLE_UNITS)
        log.info("Auth-count source: enabled (table %s)", TABLE_UNITS)
    except Exception:
        log.exception("Failed to init Azure Tables client; auth counts will be 0")
        _units_table = None
else:
    log.info("Auth-count source: disabled (AZURE_STORAGE_CONNECTION_STRING unset)")


def _get_auth_counts(env: str) -> tuple[dict[str, int], dict[str, int]]:
    """Read the Realtime tool's unit_index for `env` and return two maps:
    by_client_id (for OIDC, summing across redirect URIs for a given client)
    and by_label (for SAML, keyed on AppInstance displayName).

    Returns ({}, {}) on any error so the page still renders."""
    if _units_table is None:
        return {}, {}
    by_client: dict[str, int] = {}
    by_label: dict[str, int] = {}
    try:
        for ent in _units_table.query_entities(query_filter=f"PartitionKey eq '{env}'"):
            try:
                count = int(ent.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            if count <= 0:
                continue
            sso_type = (ent.get("sso_type") or "").upper()
            client_id = (ent.get("client_id") or "").strip()
            unit = (ent.get("unit") or "").strip()
            if sso_type == "OIDC" and client_id:
                # Multiple redirect URIs may share one client_id — sum them
                by_client[client_id] = by_client.get(client_id, 0) + count
            elif unit:
                # SAML — Realtime stores the AppInstance displayName as `unit`
                by_label[unit] = by_label.get(unit, 0) + count
    except Exception:
        log.exception("[%s] auth-count fetch failed", env)
    return by_client, by_label

# ── OIDC config (PROD Okta via "Okta Admin Tools" app) ───────────────────────
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5002").rstrip("/")
OIDC_SCOPES = "openid email profile"
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

if not OIDC_ENABLED:
    log.warning("OIDC is NOT configured — auth gate disabled, app is open. "
                "Set OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET to enable.")

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
# ACA puts a load balancer in front; trust X-Forwarded-* so url_for(_external=True)
# builds the correct https URL matching the redirect URI registered with Okta.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_BASE_URL.startswith("https://")
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = OAuth(app)
if OIDC_ENABLED:
    oauth.register(
        name="okta",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {
    "/health", "/login", "/oidc/login", "/oidc/callback", "/logout", "/favicon.ico",
}


@app.before_request
def _auth_gate():
    if not OIDC_ENABLED:
        return
    if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized — session expired"), 401
        return redirect(url_for("login", next=request.path))


def get_token(var_name: str) -> str:
    """Keyring first, env-var fallback. Linux ACA containers have no keyring
    backend, so swallow NoKeyringError and any other keyring failure."""
    if _keyring:
        try:
            val = _keyring.get_password(KEYRING_SERVICE, var_name)
            if val:
                return val.strip()
        except Exception:
            pass
    return os.environ.get(var_name, "").strip()


def _client(env: str):
    """Return (OktaClient, None) or (None, error_response)."""
    if env not in OKTA_ENVIRONMENTS:
        return None, (jsonify({"error": f"Unknown environment: {env}"}), 400)
    env_cfg = OKTA_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return None, (jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400)
    return OktaClient(env_cfg["url"], token, make_session("OktaAdmin", APP_VERSION)), None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# In-tool documentation (/howto), rendered from HOWTO.md via the shared module.
register_howto(app, tool_name="Okta Admin")


@app.route("/")
def index():
    resp = app.make_response(render_template("index.html", version=APP_VERSION,
                                              user=session.get("user")))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/health")
def health():
    return jsonify(status="ok", version=APP_VERSION), 200


# ── OIDC routes ──────────────────────────────────────────────────────────────
LOGIN_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Okta Admin — Sign in</title>
<style>
 body{margin:0;background:#0f172a;color:#e2e8f0;font:14px -apple-system,Segoe UI,Roboto,ExampleApp-serif;display:grid;place-items:center;min-height:100vh}
 .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:420px;width:90%;text-align:center}
 h1{margin:0 0 8px;font-size:20px}
 p{color:#94a3b8;margin:0 0 28px;font-size:13px}
 a.btn{display:inline-block;background:#22c55e;color:#0f172a;text-decoration:none;padding:10px 22px;border-radius:8px;font-weight:600}
 a.btn:hover{background:#16a34a;color:#fff}
 .err{color:#fca5a5;font-size:12px;margin-top:16px}
 .vpn{background:#1f2937;border:1px solid #f59e0b;color:#fbbf24;font-size:13px;margin-top:20px;padding:12px 14px;border-radius:8px;text-align:left;line-height:1.5}
 .vpn b{color:#fde68a}
 .vpn .raw{display:block;color:#94a3b8;font-size:11px;margin-top:8px;font-family:ui-monospace,Menlo,monospace;word-break:break-word}
 footer{position:fixed;bottom:16px;left:0;right:0;text-align:center;font-size:11px;color:#475569}
</style></head><body>
<div class="card">
 <h1>Okta Admin</h1>
 <p>Sign in with your work email to continue.</p>
 <a class="btn" href="/oidc/login">Sign in</a>
 {% if error %}
   {% if 'access_denied' in error %}
   <div class="vpn"><b>VPN required.</b> This app is restricted to the internal network. Connect to AnyConnect, then click Sign in again.<span class="raw">{{ error }}</span></div>
   {% else %}<div class="err">{{ error }}</div>{% endif %}
 {% endif %}
</div>
<footer>Okta Admin v{{ version }}</footer>
</body></html>"""


@app.get("/login")
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    nxt = request.args.get("next")
    if nxt:
        session["post_login_redirect"] = nxt
    err = session.pop("login_error", None)
    return render_template_string(LOGIN_HTML, error=err, version=APP_VERSION)


@app.get("/oidc/login")
def oidc_login():
    if not OIDC_ENABLED:
        session["login_error"] = "OIDC not configured"
        return redirect(url_for("login"))
    redirect_uri = url_for("oidc_callback", _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)


@app.get("/oidc/callback")
def oidc_callback():
    if request.args.get("error"):
        session["login_error"] = f"{request.args.get('error')}: {request.args.get('error_description', '')}"
        return redirect(url_for("login"))
    try:
        token = oauth.okta.authorize_access_token()
    except Exception as e:
        log.exception("OIDC token exchange failed")
        session["login_error"] = f"token exchange failed: {e}"
        return redirect(url_for("login"))
    claims = token.get("userinfo") or {}
    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        session["login_error"] = "Email claim missing in id_token."
        return redirect(url_for("login"))
    session["user"] = {
        "email": email,
        "name": claims.get("name"),
        "login_time": datetime.now(timezone.utc).isoformat(),
    }
    redirect_to = session.pop("post_login_redirect", None) or url_for("index")
    return redirect(redirect_to)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/api/apps")
def api_apps():
    """Fetch all SAML + OIDC apps with policy and routing rule data merged."""
    env = request.args.get("env", "dev")
    client, err = _client(env)
    if err:
        return err
    try:
        apps = client.get_all_apps()
        policy_map = client.get_app_policy_map()
        routing_map = client.get_app_routing_rule_map()
        # Auth event counts from the Realtime tool's unit_index (Azure Tables).
        # OIDC matches by client_id (= Okta app id, summed across redirect URIs);
        # SAML matches by AppInstance displayName (= app label).
        auth_by_client, auth_by_label = _get_auth_counts(env)

        result = []
        for a in apps:
            aid = a["id"]
            pm = policy_map.get(aid, {})
            rm = routing_map.get(aid, {})
            hide = (a.get("visibility") or {}).get("hide") or {}
            sign_on_mode = a.get("signOnMode", "")
            label = a.get("label", "")
            if sign_on_mode == "OPENID_CONNECT":
                auth_count = auth_by_client.get(aid, 0)
            elif sign_on_mode == "SAML_2_0":
                auth_count = auth_by_label.get(label, 0)
            else:
                auth_count = 0
            result.append({
                "id": aid,
                "label": label,
                "sign_on_mode": sign_on_mode,
                "status": a.get("status", ""),
                "policy_id": pm.get("policy_id"),
                "policy_name": pm.get("policy_name"),
                "routing_rule_id": rm.get("rule_id"),
                "routing_rule_name": rm.get("rule_name"),
                "routing_policy_id": rm.get("policy_id"),
                "dashboard_hidden": bool(hide.get("web")),
                "note": (a.get("notes") or {}).get("admin") or "",
                "auth_count": auth_count,
            })
        result.sort(key=lambda x: x["label"].lower())
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/policies")
def api_policies():
    env = request.args.get("env", "dev")
    client, err = _client(env)
    if err:
        return err
    try:
        return jsonify(client.list_access_policies())
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/routing-rules")
def api_routing_rules():
    env = request.args.get("env", "dev")
    client, err = _client(env)
    if err:
        return err
    try:
        rules = []
        for policy in client.list_idp_routing_policies():
            for rule in client.list_routing_rules(policy["id"]):
                rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "policy_id": policy["id"],
                })
        return jsonify(rules)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/toggle-status", methods=["POST"])
def api_toggle_status():
    data = request.get_json()
    env = data.get("env", "dev")
    app_id = data.get("app_id", "").strip()
    action = data.get("action", "")

    if action not in ("activate", "deactivate"):
        return jsonify({"error": "action must be 'activate' or 'deactivate'"}), 400

    client, err = _client(env)
    if err:
        return err
    try:
        if action == "activate":
            client.activate_app(app_id)
        else:
            client.deactivate_app(app_id)
        _log_action(env, action.upper(), app_id, "ok")
        return jsonify({"status": "ACTIVE" if action == "activate" else "INACTIVE"})
    except Exception as e:
        _log_action(env, action.upper(), app_id, "FAILED", str(e))
        return jsonify({"error": str(e)}), 502


@app.route("/api/assign-policy", methods=["POST"])
def api_assign_policy():
    data = request.get_json()
    env = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    policy_id = data.get("policy_id", "").strip()

    if not app_ids or not policy_id:
        return jsonify({"error": "app_ids and policy_id required"}), 400

    client, err = _client(env)
    if err:
        return err
    results = {}
    for aid in app_ids:
        try:
            client.assign_policy_to_app(aid, policy_id)
            results[aid] = "ok"
            _log_action(env, "POLICY", aid, "ok", f"policy={policy_id}")
        except Exception as e:
            results[aid] = str(e)
            _log_action(env, "POLICY", aid, "FAILED", str(e))
    return jsonify(results)


@app.route("/api/assign-routing-rule", methods=["POST"])
def api_assign_routing_rule():
    data = request.get_json()
    env = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    rule_id = data.get("rule_id", "").strip()
    rule_policy_id = data.get("rule_policy_id", "").strip()
    action = data.get("action", "add")

    if not app_ids or not rule_id or not rule_policy_id:
        return jsonify({"error": "app_ids, rule_id, rule_policy_id required"}), 400

    client, err = _client(env)
    if err:
        return err
    results = {}
    for aid in app_ids:
        try:
            if action == "remove":
                client.remove_app_from_routing_rule(rule_policy_id, rule_id, aid)
            else:
                client.add_app_to_routing_rule(rule_policy_id, rule_id, aid)
            results[aid] = "ok"
            _log_action(env, f"ROUTING-{action.upper()}", aid, "ok", f"rule={rule_id}")
        except Exception as e:
            results[aid] = str(e)
            _log_action(env, f"ROUTING-{action.upper()}", aid, "FAILED", str(e))
    return jsonify(results)


@app.route("/api/rename", methods=["POST"])
def api_rename():
    data = request.get_json()
    env = data.get("env", "dev")
    app_id = data.get("app_id", "").strip()
    new_label = data.get("label", "").strip()
    if not app_id or not new_label:
        return jsonify({"error": "app_id and label required"}), 400
    client, err = _client(env)
    if err:
        return err
    try:
        client.rename_app(app_id, new_label)
        _log_action(env, "RENAME", new_label, "ok", f"id={app_id}")
        return jsonify({"ok": True, "label": new_label})
    except Exception as e:
        _log_action(env, "RENAME", app_id, "FAILED", str(e))
        return jsonify({"error": str(e)}), 502


@app.route("/api/note", methods=["POST"])
def api_note():
    data = request.get_json()
    env = data.get("env", "dev")
    app_id = data.get("app_id", "").strip()
    note = data.get("note", "")
    if not app_id:
        return jsonify({"error": "app_id required"}), 400
    client, err = _client(env)
    if err:
        return err
    try:
        client.set_app_note(app_id, note)
        _log_action(env, "NOTE", app_id, "ok", f'"{note[:60]}"' if note else "(cleared)")
        return jsonify({"ok": True, "note": note})
    except Exception as e:
        _log_action(env, "NOTE", app_id, "FAILED", str(e))
        return jsonify({"error": str(e)}), 502


@app.route("/api/visibility", methods=["POST"])
def api_visibility():
    data = request.get_json()
    env = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    hide = data.get("hide")
    if not app_ids or hide is None:
        return jsonify({"error": "app_ids and hide (bool) required"}), 400
    client, err = _client(env)
    if err:
        return err
    results = {}
    for aid in app_ids:
        try:
            client.set_app_visibility(aid, bool(hide))
            results[aid] = "ok"
            _log_action(env, "VISIBILITY", aid, "ok", "hidden" if hide else "visible")
        except Exception as e:
            results[aid] = str(e)
            _log_action(env, "VISIBILITY", aid, "FAILED", str(e))
    return jsonify(results)


# ---------------------------------------------------------------------------
# SP Config — Claude-generated vendor instructions (ZIP download)
# ---------------------------------------------------------------------------

import csv
import io
import os
import re as _re
import secrets
import string
import subprocess
import tempfile
def _safe_filename(label: str) -> str:
    """Convert app label to a safe filename slug."""
    slug = _re.sub(r'[^\w\s-]', '', label).strip()
    slug = _re.sub(r'[\s]+', '-', slug)
    return slug[:60] or "app"


# ---------------------------------------------------------------------------
# SP Config — deterministic template rendering (no LLM dependency).
# Vendor-specific "What to do" snippets are selected by inspecting SP-side
# URLs and the OIN flag. The output format matches what the previous
# LLM-generated text produced — plain-text, no markdown, no greeting.
# ---------------------------------------------------------------------------

_SP_VENDOR_SHIBBOLETH = """\
What to do (Shibboleth SP)

1. In shibboleth2.xml, update the <MetadataProvider> entry to point at the Metadata URL above. Set a sensible reloadInterval (e.g. 7200) and a backingFile name.

2. Update the <SSO entityID="..."> element to reference the IDP Entity ID listed above.

3. In attribute-map.xml, confirm the attribute names listed under Attribute Statements map to the local attribute names the application expects.

4. Validate the config with shibd -t and restart the service: service shibd restart.

5. Test a login from a fresh browser. If decryption fails, confirm the SP private key file is still readable by the shibd process.
"""

_SP_VENDOR_AWS = """\
What to do (AWS SSO / IAM Identity Center)

1. In the AWS admin console (IAM Identity Center -> Settings -> Identity source), select "External identity provider" if not already set.

2. Upload or paste the Metadata URL above. AWS will pull the IDP SSO URL, Entity ID, and signing certificate automatically.

3. Confirm the ACS URL and Audience URI on the AWS side match the values listed above. AWS auto-generates these; they should already match if the Okta app was created from the AWS metadata.

4. Run a test sign-in with a user assigned to this Okta app. If AWS rejects the assertion, verify the NameID format — AWS typically expects emailAddress.
"""

_SP_VENDOR_MICROSOFT = """\
What to do (Microsoft / Azure / Entra)

1. In the Microsoft Entra admin center (Enterprise applications -> this app -> Single sign-on), choose SAML.

2. Use the Metadata URL above to import the IdP configuration if the tenant supports metadata import. Otherwise paste the IDP SSO URL, Entity ID, and upload the signing certificate manually.

3. Verify the Reply URL (ACS) and Identifier (Entity ID) on the Microsoft side match the values listed above.

4. Confirm the NameID format and attribute mappings. Microsoft typically expects the nameidentifier claim to carry the email value.

5. Test sign-in. Microsoft sign-in errors include a correlation ID — check Azure AD sign-in logs for the full failure reason if the test fails.
"""

_SP_VENDOR_GOOGLE = """\
What to do (Google Workspace)

1. In Google Admin (admin.google.com -> Security -> SSO with third-party IdP), add or update the SAML SSO profile for this domain.

2. Upload the IdP metadata (download the XML from the Metadata URL above) or manually enter the IDP SSO URL, Entity ID, and upload the signing certificate PEM.

3. Confirm the ACS URL and Entity ID on the Google side match the values listed above. The Google ACS URL is unique per customer ID and must match exactly.

4. Verify the NameID format is emailAddress and that email is being released as the NameID — Google uses email as the primary identifier.

5. Test sign-in. If Google reports "the SAML response is invalid", confirm the user's email in Google matches the email being sent in the assertion.
"""

_SP_VENDOR_SALESFORCE = """\
What to do (Salesforce)

1. In Salesforce Setup (Identity -> Single Sign-On Settings), edit or create the SAML SSO configuration for this Okta integration.

2. Upload the metadata file (from the Metadata URL above) or manually enter the IDP SSO URL, Entity ID, and upload the signing certificate.

3. Confirm the Entity ID (Issuer) and ACS URL on the Salesforce side match the values listed above.

4. Set the SAML Identity Type (Username or Federation ID) to match what NameID will contain.

5. Test sign-in. If Salesforce rejects, use the SAML Assertion Validator in Salesforce Setup — it shows exactly which field failed validation.
"""

_SP_VENDOR_OIN = """\
What to do

1. In the application admin console, locate the SAML / SSO identity provider configuration section.

2. Import the IdP metadata using the Metadata URL above. The platform should auto-populate the IDP SSO URL, IDP Entity ID, and signing certificate.

3. Confirm the ACS URL and Entity ID / Audience URI on the SP side match the values listed above. These are the SP-side values Okta is already configured to send to.

4. Verify the NameID format and that the listed attributes are being released as the application expects.

5. Save the configuration and run a test login. If the test fails, confirm the user is assigned to the Okta app and that the expected attributes are being released.
"""

_SP_VENDOR_GENERIC = """\
What to do

The configuration path varies by platform — use whichever your platform supports:

1. Metadata URL import (preferred if supported): paste the Metadata URL above and let the platform auto-populate IDP SSO URL, Entity ID, and signing certificate.

2. Raw metadata XML upload: download the XML from the Metadata URL above and upload the file.

3. Manual entry: copy IDP SSO URL, IDP Entity ID, and the signing certificate PEM into the SP-side configuration fields individually.

After configuring, verify the ACS URL and Entity ID / Audience URI on the SP side match the values listed above. Save and run a test login. If the test fails, confirm the user is assigned to the Okta app and that the expected attributes are being released.
"""


def _detect_sp_vendor(cfg: dict) -> str:
    """Pick the best-fit vendor snippet by inspecting SP-side URLs.

    Returns one of: "shibboleth" | "aws" | "microsoft" | "google" |
    "salesforce" | "oin" | "generic". First match wins; falls back to the
    OIN snippet if the app is OIN-sourced, else the generic three-path
    instructions for custom SAML apps.
    """
    acs = (cfg.get("acs_url") or "").lower()
    entity = (cfg.get("entity_id") or "").lower()
    haystack = acs + " " + entity
    if "/shibboleth.sso/" in haystack:
        return "shibboleth"
    if "amazonaws.com" in haystack or "signin.aws.amazon.com" in haystack:
        return "aws"
    if "microsoftonline.com" in haystack or "microsoft.com" in haystack:
        return "microsoft"
    if "google.com" in haystack or "googleapis" in haystack:
        return "google"
    if "salesforce.com" in haystack or ".force.com" in haystack:
        return "salesforce"
    return "oin" if cfg.get("is_oin") else "generic"


_SP_VENDOR_SNIPPETS = {
    "shibboleth": _SP_VENDOR_SHIBBOLETH,
    "aws":        _SP_VENDOR_AWS,
    "microsoft":  _SP_VENDOR_MICROSOFT,
    "google":     _SP_VENDOR_GOOGLE,
    "salesforce": _SP_VENDOR_SALESFORCE,
    "oin":        _SP_VENDOR_OIN,
    "generic":    _SP_VENDOR_GENERIC,
}


def _render_sp_config_text(cfg: dict, env: str) -> str:
    """Render the SP config text deterministically — no LLM call.

    Output format matches what the previous Claude-generated text produced:
    plain text, header fields, signing cert PEM, SP-side values, attribute
    statements, and a vendor-specific "What to do" section selected from
    `_SP_VENDOR_SNIPPETS`.
    """
    # Attribute statements block (omit entirely if no attributes defined)
    attr_block = ""
    if cfg.get("attr_stmts"):
        lines = []
        for a in cfg["attr_stmts"]:
            name = a.get("name", "")
            values = a.get("values") or a.get("value") or ""
            if isinstance(values, list):
                values = values[0] if len(values) == 1 else ", ".join(values)
            lines.append(f"{name} -> {values}")
        attr_block = "\n\nAttribute Statements:\n" + "\n".join(lines)

    # OIN apps get the auto-config disclaimer; custom apps don't.
    oin_note = ""
    if cfg.get("is_oin"):
        oin_note = (
            "\n\nNote: Most modern SAML service providers can auto-configure "
            "from the metadata URL alone. The values below are provided for "
            "reference or for vendors that require manual entry."
        )

    vendor_key = _detect_sp_vendor(cfg)
    what_to_do = _SP_VENDOR_SNIPPETS[vendor_key]

    return (
        f"Application: {cfg['label']}\n"
        f"Environment: {env.upper()}\n"
        f"\n"
        f"Metadata URL: {cfg['metadata_url']}"
        f"{oin_note}\n"
        f"\n"
        f"IDP SSO URL: {cfg.get('idp_sso_url') or ''}\n"
        f"IDP Entity ID: {cfg.get('idp_entity_id') or ''}\n"
        f"\n"
        f"Signing Certificate (PEM):\n"
        f"{cfg.get('cert_pem') or ''}\n"
        f"\n"
        f"ACS URL (Reply URL): {cfg.get('acs_url') or ''}\n"
        f"Entity ID / Audience URI: {cfg.get('entity_id') or ''}\n"
        f"NameID Format: {cfg.get('nameid_format') or ''}"
        f"{attr_block}\n"
        f"\n"
        f"{what_to_do}"
    )


@app.route("/api/sp-config", methods=["POST"])
def api_sp_config():
    """Return one app's SP config as a plain .txt download.
    Frontend iterates selected apps and calls this endpoint per-app.
    No encryption, no bundling — corporate proxies block password-protected
    zips; SAML SP metadata isn't sensitive enough to fight that, and the
    Okta admin auth gate already covers in-tool access."""
    from flask import send_file
    data    = request.get_json() or {}
    env     = data.get("env", "dev")
    app_id  = data.get("app_id")
    if not app_id:
        return jsonify({"error": "app_id required"}), 400

    client, err = _client(env)
    if err:
        return err

    try:
        cfg = client.get_saml_config(app_id)
        if cfg.get("status") != "ACTIVE":
            _log_action(env, "SP_CONFIG", app_id, "skipped", "inactive")
            return jsonify({"error": f"{cfg.get('label', app_id)}: skipped (INACTIVE)"}), 400
        text = _render_sp_config_text(cfg, env)
        slug = _safe_filename(cfg['label'])
        _log_action(env, "SP_CONFIG", cfg['label'], "ok")
    except Exception as e:
        log.warning("sp-config failed for %s: %s", app_id, e)
        _log_action(env, "SP_CONFIG", app_id, "FAILED", str(e))
        return jsonify({"error": str(e)}), 500

    buf = io.BytesIO(text.encode("utf-8"))
    return send_file(
        buf,
        mimetype="text/plain; charset=utf-8",
        as_attachment=True,
        download_name=f"{slug}-sp-config.txt",
    )


@app.route("/logs")
def logs_page():
    log_file = Path(__file__).parent / "okta-admin-actions.log"
    lines = []
    if log_file.exists():
        with open(log_file, encoding="utf-8") as f:
            lines = f.readlines()
    return render_template("logs.html", lines=lines[-500:])


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    print(f"\n  Okta Admin v{APP_VERSION}")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=True, threaded=True)
