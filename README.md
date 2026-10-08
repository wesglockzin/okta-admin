# Okta Admin

A small Flask web UI for everyday Okta application administration across multiple
Okta orgs (e.g. DEV / STG / PROD), without clicking through the Admin Console.

## What it does
- **App inventory** — SAML, OIDC, WS-Fed, SWA and RADIUS apps across each org, with status at a glance.
- **Bulk actions** — activate / deactivate, assign an authentication policy, add or remove an IdP routing rule.
- **Clear assignments** — remove the built-in *Everyone* group from apps and track Okta's background clean-up with a live progress page.
- **Per-app edits** — rename, admin notes, dashboard visibility.
- **Action log** — every write is logged locally.

Bulk operations pre-filter to ACTIVE apps — Okta rejects policy, routing and visibility
changes on inactive apps, which reads as a misleading failure in a batch.

## Run locally
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python setup_tokens.py     # one-time: store an API token per org in the OS keyring
.venv/bin/python app.py              # http://127.0.0.1:5002
```

## Configuration
- Org base URLs live in `okta_client.py` (`OKTA_ENVIRONMENTS`) — set them to your orgs.
- API tokens: OS keyring first, environment variables as fallback (`OKTA_ADMIN_{DEV,STG,PROD}_API_TOKEN`).
- Optional OIDC sign-in gate: set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
  `APP_BASE_URL` and `FLASK_SECRET_KEY`. When they are absent the gate is off — intended for
  local development only.

## Container
A `Dockerfile` is included (gunicorn on port 8080, runs as a non-root arbitrary UID).

## Notes
This tool **writes** to Okta when you click an action. Use a token scoped to what you
need, and try changes against a non-production org first.

## Known limitations
- **It writes to Okta.** Every action button changes the org immediately — there is no
  dry-run mode and no undo. The action log records what was done, not how to reverse it.
- **The sign-in gate is off when OIDC isn't configured.** With the `OIDC_*` variables
  unset, anyone who can reach the port can use the tool. Never deploy it that way.
- **TLS verification is disabled for the optional auth-count data source** (Azure Tables),
  to work behind a TLS-inspecting proxy. Okta API calls verify certificates normally.
- **One API token per org, with whatever rights that token has.** There is no per-user
  authorization inside the tool.
- **No automated tests.**
