"""
app.py — Okta Admin (local Flask UI)
Run: .venv/bin/python app.py
Then open: http://localhost:5002
"""
from __future__ import annotations

import glob
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("okta-admin")

# ── Action logger — persistent, human-readable, one line per action ──────────
_alog = logging.getLogger("okta.admin.actions")
_alog.setLevel(logging.INFO)
_alog.propagate = False
_ah = logging.FileHandler(Path(__file__).parent / "okta-admin-actions.log", encoding="utf-8")
_ah.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
_alog.addHandler(_ah)

def _log_action(env: str, action: str, label: str, outcome: str, detail: str = "") -> None:
    _alog.info("%-5s| %-12s| %-40s| %-10s| %s",
               env.upper()[:5], action[:12], label[:40], outcome[:10], detail)

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, Response, stream_with_context

try:
    import keyring as _keyring
    KEYRING_SERVICE = "okta-app-admin"
except ImportError:
    _keyring = None  # type: ignore
    KEYRING_SERVICE = ""

load_dotenv(Path(__file__).parent / ".env")

sys.path.insert(0, str(Path(__file__).parent))
from okta_client import OKTA_ENVIRONMENTS, OktaClient

APP_VERSION = "1.5.0"

app = Flask(__name__)


def get_token(var_name: str) -> str:
    """Keyring first, .env fallback."""
    if _keyring:
        val = _keyring.get_password(KEYRING_SERVICE, var_name)
        if val:
            return val.strip()
    return os.environ.get(var_name, "").strip()


def _client(env: str):
    """Return (OktaClient, None) or (None, error_response)."""
    if env not in OKTA_ENVIRONMENTS:
        return None, (jsonify({"error": f"Unknown environment: {env}"}), 400)
    env_cfg = OKTA_ENVIRONMENTS[env]
    token = get_token(env_cfg["token_var"])
    if not token:
        return None, (jsonify({"error": f"{env_cfg['token_var']} is not set"}), 400)
    return OktaClient(env_cfg["url"], token), None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    resp = app.make_response(render_template("index.html", version=APP_VERSION))
    resp.headers["Cache-Control"] = "no-store"
    return resp


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

        result = []
        for a in apps:
            aid = a["id"]
            pm = policy_map.get(aid, {})
            rm = routing_map.get(aid, {})
            hide = (a.get("visibility") or {}).get("hide") or {}
            result.append({
                "id": aid,
                "label": a.get("label", ""),
                "sign_on_mode": a.get("signOnMode", ""),
                "status": a.get("status", ""),
                "policy_id": pm.get("policy_id"),
                "policy_name": pm.get("policy_name"),
                "routing_rule_id": rm.get("rule_id"),
                "routing_rule_name": rm.get("rule_name"),
                "routing_policy_id": rm.get("policy_id"),
                "dashboard_hidden": bool(hide.get("web")),
                "note": (a.get("notes") or {}).get("admin") or "",
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

import io
import re as _re
import zipfile

_CLAUDE_TIMEOUT = 120
_CLAUDE_ENV_ALLOWLIST = {"PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL",
                         "TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR",
                         "CLAUDE_CONFIG_DIR", "NODE_EXTRA_CA_CERTS",
                         "NODE_TLS_REJECT_UNAUTHORIZED"}


def _find_claude() -> str:
    candidates = sorted(glob.glob(
        os.path.expanduser("~/.vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude")
    ))
    return candidates[-1] if candidates else "claude"


def _safe_filename(label: str) -> str:
    """Convert app label to a safe filename slug."""
    slug = _re.sub(r'[^\w\s-]', '', label).strip()
    slug = _re.sub(r'[\s]+', '-', slug)
    return slug[:60] or "app"


_SP_CONFIG_PROMPT = """\
You are an Okta SSO administrator preparing SP (Service Provider) configuration instructions for a vendor or SP administrator.

Write plain configuration instructions — no greeting, no closing, no email framing. Just the instructions.

The configuration values are already extracted and provided below. Present them clearly and write a "What to do" section tailored to this specific application.

Rules:
- Lead with the Metadata URL
- Present all provided values with clear labels
- No markdown, no bullet symbols — plain text with line breaks
- No sign-off, no signature

If is_oin=true:
  Add this note after the Metadata URL: "Note: Most modern SAML service providers can auto-configure from the metadata URL alone. The values below are provided for reference or for vendors that require manual entry."
  Write a "What to do" section with 3-5 steps focused on importing the metadata URL.

If is_oin=false:
  This is a custom (non-OIN) SAML application. The SP admin's platform may not support automatic metadata import. Write a "What to do" section that covers all three common configuration paths and tells the admin to use whichever their platform supports:
  1. Metadata URL import (if their platform supports it — paste the URL and let it auto-populate)
  2. Raw metadata XML upload (download from the metadata URL and upload the XML file)
  3. Manual entry (copy IDP SSO URL, IDP Entity ID, and download the signing certificate PEM for upload)
  Keep the steps practical and platform-agnostic — do not assume any specific vendor portal layout.

App configuration:
{details}
"""


def _call_claude(prompt: str, safe_env: dict) -> str:
    """Call Claude CLI, return the full text response."""
    claude = _find_claude()
    proc = subprocess.Popen(
        [claude, "-p", prompt,
         "--output-format", "stream-json",
         "--verbose",
         "--include-partial-messages",
         "--permission-mode", "bypassPermissions",
         "--no-session-persistence"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=safe_env, start_new_session=True,
    )
    chunks = []
    try:
        for raw in proc.stdout:
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "stream_event":
                ev = event.get("event", {})
                if ev.get("type") == "content_block_delta":
                    delta = ev.get("delta", {})
                    if delta.get("type") == "text_delta":
                        chunks.append(delta.get("text", ""))
            elif event.get("type") == "result" and event.get("is_error"):
                raise RuntimeError(event.get("result", "claude error"))
        try:
            proc.wait(timeout=_CLAUDE_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
            raise RuntimeError(f"Claude timed out after {_CLAUDE_TIMEOUT}s")
    except Exception:
        if proc.poll() is None:
            proc.kill(); proc.wait()
        raise
    return "".join(chunks).strip()


def _build_details(cfg: dict, env: str) -> str:
    attr_lines = ""
    if cfg.get("attr_stmts"):
        attr_lines = "\nAttribute Statements:\n" + "\n".join(
            f"  {a.get('name','')}: {a.get('values', a.get('value',''))}"
            for a in cfg["attr_stmts"]
        )
    return (
        f"App Name: {cfg['label']}\n"
        f"Environment: {env.upper()}\n"
        f"OIN App (is_oin): {'true' if cfg['is_oin'] else 'false'}\n"
        f"\nMetadata URL: {cfg['metadata_url']}\n"
        f"\nIDP SSO URL: {cfg.get('idp_sso_url') or ''}\n"
        f"IDP Entity ID: {cfg.get('idp_entity_id') or ''}\n"
        f"Signing Certificate (PEM):\n{cfg.get('cert_pem') or ''}\n"
        f"\nACS URL (Reply URL): {cfg.get('acs_url') or ''}\n"
        f"Entity ID / Audience URI: {cfg.get('entity_id') or ''}\n"
        f"NameID Format: {cfg.get('nameid_format') or ''}"
        f"{attr_lines}"
    )


@app.route("/api/sp-config-zip", methods=["POST"])
def api_sp_config_zip():
    from flask import send_file
    data    = request.get_json()
    env     = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    if not app_ids:
        return jsonify({"error": "app_ids required"}), 400

    client, err = _client(env)
    if err:
        return err

    safe_env = {k: v for k, v in os.environ.items() if k in _CLAUDE_ENV_ALLOWLIST}
    zip_buf = io.BytesIO()
    errors = []

    first_label = None
    success_count = 0
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for app_id in app_ids:
            try:
                cfg  = client.get_saml_config(app_id)
                slug = _safe_filename(cfg['label'])
                if cfg.get("status") != "ACTIVE":
                    errors.append(f"{cfg['label']}: skipped (INACTIVE)")
                    log.info("sp-config skipped inactive app %s (%s)", cfg['label'], app_id)
                    continue
                details = _build_details(cfg, env)
                prompt  = _SP_CONFIG_PROMPT.format(details=details)
                text    = _call_claude(prompt, safe_env)
                fname   = f"{slug}-sp-config.txt"
                zf.writestr(fname, text)
                if first_label is None:
                    first_label = cfg['label']
                success_count += 1
                _log_action(env, "SP_CONFIG", cfg['label'], "ok")
            except Exception as e:
                errors.append(f"{app_id}: {e}")
                log.warning("sp-config failed for %s: %s", app_id, e)
                _log_action(env, "SP_CONFIG", app_id, "FAILED", str(e))

    if success_count == 0:
        return jsonify({"error": "; ".join(errors) or "No configs generated"}), 502

    zip_buf.seek(0)
    env_label = env.upper()
    zip_name  = (
        f"sp-configs-{env_label}.zip" if len(app_ids) > 1
        else f"{_safe_filename(first_label or 'app')}-sp-config.zip"
    )
    return send_file(
        zip_buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_name,
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
