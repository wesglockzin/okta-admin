# Okta Admin

**Type: service** (Flask web app). A small web UI for everyday Okta application
administration across several Okta orgs, without clicking through the Admin Console.

## What it does
- **App inventory** — SAML, OIDC, WS-Fed, SWA and RADIUS apps across each org, with status at a glance.
- **Bulk actions** — activate / deactivate, assign an authentication policy, add or remove an IdP routing rule.
- **Clear assignments** — remove the built-in *Everyone* group from apps and track Okta's background clean-up with a live progress page.
- **Per-app edits** — rename, admin notes, dashboard visibility.
- **Action log** — every write is logged locally.

Bulk operations pre-filter to ACTIVE apps — Okta rejects policy, routing and visibility
changes on inactive apps, which reads as a misleading failure in a batch.

## Run
```bash
cp .env.example .env     # fill in the required settings below
docker compose up        # http://localhost:8080
```
Without Docker: `pip install -e ".[keyring]"` then `okta-admin` (http://127.0.0.1:5002).
To keep API tokens in the OS keyring instead of the environment, run `okta-admin-setup-tokens`.

Tests and lint: `pip install -e ".[dev]"`, then `pytest`, `ruff check .`, `ruff format --check .`.

## Settings
All settings are environment variables (or a `.env` file). `.env.example` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `OKTA_ADMIN_ORGS` | required | Comma-separated org names (any number). The first is the default. |
| `OKTA_ADMIN_<NAME>_URL` | required per org | `https://` URL of that org. |
| `OKTA_ADMIN_<NAME>_API_TOKEN` | required per org | API token. The OS keyring is checked first, if installed. |
| `AUTH_MODE` | `oidc` | `none` turns sign-in off (local use only). |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | required with `oidc` | OIDC sign-in. |
| `APP_BASE_URL` | required with `oidc` | Public URL of this app. |
| `FLASK_SECRET_KEY` | required with `oidc` | Session key; keep it stable across workers and restarts. |
| `OIDC_ALLOWED_EMAILS` | required with `oidc` | Comma-separated emails allowed to sign in. |
| `ACCESS_DENIED_NOTICE` | generic text | Shown when the identity provider denies access. |
| `HOST` / `PORT` | `127.0.0.1` / `5002` | Local bind address. The container binds `0.0.0.0` and reads `PORT` (8080). |
| `ACTION_LOG_PATH` | `okta-admin-actions.log` beside `app.py` | Action log file. |
| `KEYRING_SERVICE` | `okta-app-admin` | OS keyring service name. |
| `AZURE_STORAGE_CONNECTION_STRING` | unset (off) | Optional auth-count overlay from Azure Tables. |
| `TABLE_UNITS` | `appauthcounts` | Table name for that overlay. |
| `AZURE_TLS_VERIFY` | `true` | Set `false` only behind a TLS-inspecting proxy. |

The app exits at start-up, naming the setting, if the org list, sign-in settings or
session key are missing and `AUTH_MODE=none` is not set.

## Notes
This tool **writes** to Okta when you click an action. Use a token scoped to what you
need, and try changes against a non-production org first.

## Known limitations
- **It writes to Okta.** Every action button changes the org immediately — there is no
  dry-run mode and no undo. The action log records what was done, not how to reverse it.
- **Everyone allowed in can write to every org.** Authorization is an email allow-list;
  there are no roles. API tokens carry whatever rights they were issued with.
- **CSRF protection is an Origin/Referer check** on every write request.
- **Dependencies are range-pinned but there is no lockfile yet.**
- **The action log is a local file** and is not shared between containers.
- **Many error messages still return raw upstream error text to the browser.**
