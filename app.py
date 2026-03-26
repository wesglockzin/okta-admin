"""
app.py — Okta App Admin Dashboard (local Flask UI)
Run: .venv/bin/python app.py
Then open: http://localhost:5002
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

try:
    import keyring as _keyring
    KEYRING_SERVICE = "okta-app-admin"
except ImportError:
    _keyring = None  # type: ignore
    KEYRING_SERVICE = ""

load_dotenv(Path(__file__).parent / ".env")

sys.path.insert(0, str(Path(__file__).parent))
from okta_client import OKTA_ENVIRONMENTS, OktaClient

APP_VERSION = "1.0.0"

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
    return render_template("index.html", version=APP_VERSION)


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
        return jsonify({"status": "ACTIVE" if action == "activate" else "INACTIVE"})
    except Exception as e:
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
        except Exception as e:
            results[aid] = str(e)
    return jsonify(results)


@app.route("/api/assign-routing-rule", methods=["POST"])
def api_assign_routing_rule():
    data = request.get_json()
    env = data.get("env", "dev")
    app_ids = data.get("app_ids", [])
    rule_id = data.get("rule_id", "").strip()
    rule_policy_id = data.get("rule_policy_id", "").strip()
    action = data.get("action", "add")  # "add" | "remove"

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
        except Exception as e:
            results[aid] = str(e)
    return jsonify(results)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    print(f"\n  Okta App Admin Dashboard v{APP_VERSION}")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
