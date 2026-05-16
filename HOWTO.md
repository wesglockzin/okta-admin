# Okta Admin

## TL;DR

A bulk app-management dashboard for Okta. Inventory of every SAML/OIDC app across DEV / STG / PROD, with one-click controls for visibility (hide/show from dashboard), assignments, sign-on policy assignment, routing rule assignment, and bulk SP configuration export.

Built for the IAM admin team. Replaces "click into 50 apps one at a time in the Okta admin console" with a sortable, filterable, action-able grid.

## What this tool is — and what it isn't

**It is:**
- A full inventory view of every SAML/OIDC/SWA/WS-Fed app per env
- Bulk-action surface for visibility, policy assignment, routing rule assignment
- SP Config generator — produces password-protected zips of vendor-facing SAML metadata + setup instructions
- Live "Auth Events" column showing recent auth volume per app (sourced from Migration Realtime's Azure Tables)
- Multi-environment (DEV / STG / PROD)

**It isn't:**
- **Not Live Tail** — that's per-event, this is per-app aggregated
- **Not Change Auditor** — that watches config changes; this is the surface that *makes* them
- **Not OIN Migration** — that's app-replacement (custom SAML → OIN); this manages existing apps in place
- **Not Federated Claims Analyzer** — that's interactive SSO testing; this is config management

## Quick start — 30 seconds

1. Sign in (work email; on VPN)
2. Pick environment (DEV / STG / PROD)
3. App grid loads — every SAML/OIDC/SWA/WS-Fed app, with status, sign-on mode, dashboard visibility, assignments count, last-modified, auth event count
4. Click a row to see details + per-app actions
5. Use checkboxes for multi-select + bulk actions

## How to use it

### The app grid

| Column | What it shows |
|---|---|
| **Status** | ACTIVE / INACTIVE — color-coded |
| **Label** | The app's display name in Okta |
| **Sign-on Mode** | SAML 2.0 / OIDC / SWA / WS-Fed |
| **Visibility** | Whether the app tile appears on the user dashboard (hide.web flag) |
| **Auth Events** | Auth events recorded by Migration Realtime since the cutover anchor — "is this app in active use?" at a glance |
| **Last Modified** | When the app config was last touched |

### Filtering + sorting

- **Search box** filters by name / id / sign-on mode
- **Column headers** sort
- **Status filter** (ACTIVE / INACTIVE / ALL) narrows

### Per-app actions

Click a row to see:
- **Toggle visibility** — show or hide the app tile on user dashboards
- **Assignments** — view/edit groups and users
- **Sign-on policy** — assign or change the authentication policy
- **Routing rule** — add/remove this app from IdP Discovery routing rules
- **Open in Okta admin console** — direct link

### Bulk actions

Multi-select with checkboxes, then:
- **Hide visibility** (or show) for the selection
- **Generate SP configs** — produces a downloadable zip with one password-protected zip per app (each containing the vendor-facing SAML metadata + "what to do" instructions); a `passwords.csv` inside lists each app and its zip password

## Common workflows

### "Hide 30 OIN apps from end-user dashboards"
- Filter by sign-on mode SAML / Status ACTIVE
- Multi-select the 30 apps
- Bulk action → Hide visibility
- The app instances stay assignable to users for SP-initiated flows but disappear from the dashboard tile

### "Generate SP config zips for vendor handoff"
- Filter or multi-select the apps you want to hand off
- Bulk action → Generate SP configs
- Download the resulting zip
- Inside: per-app `*-sp-config.zip` (password-protected, ZipCrypto for Windows Explorer compatibility) + `passwords.csv` with the password for each
- Send the per-app zip to each vendor along with their password

### "Which apps are seeing real auth traffic?"
- Sort by Auth Events column descending
- Top of the list = actively used; bottom = candidates for review/deprecation

### "Add an app to a routing rule"
- Click the app row
- Routing rule section shows which rules the app is in (or not)
- Add/remove via the toggle

---

## Deep dive — how it actually works

### Architecture

```
Browser ── /api/* ──▶ Flask app (ACA)
                        │
                        │  uses OktaClient (okta_client.py)
                        │
                        ├──▶ Okta /api/v1/apps  + /api/v1/apps/{id}/groups, /users, /policies
                        │
                        └──▶ Azure Tables (oktamigrationunits) ──── Auth Events column
                                                                      (shared with Migration Realtime)
```

### Visibility toggle

To hide an app from end-user dashboards, the tool reads the full app config (`GET /api/v1/apps/{id}`), sets `visibility.hide.web=true` and `visibility.hide.iOS=true`, and PUTs the whole object back (`PUT /api/v1/apps/{id}`). The full-PUT pattern is required because Okta's API doesn't support PATCH on apps — you submit the full object.

Implication: there's a known issue where OIDC apps' `settings.signOn` carries fields that fail validation on re-submit (the `mode` error you may have seen). When this fires, the visibility change doesn't apply. The tool surfaces the error in the UI.

### SP Config generator

For each selected app:
1. Pull the full app config + SAML metadata via Okta API
2. Build a vendor-facing text file with: metadata URL, IdP entity ID, IdP SSO URL, signing certificate PEM, ACS URL, audience, NameID format, attribute statements, and a "What to do" section with vendor-specific guidance (Shibboleth / AWS / Microsoft / Google / Salesforce / OIN / generic)
3. Generate a 20-char random password
4. Wrap the text file in a ZipCrypto-encrypted zip (`zip -P` — Windows Explorer can extract without third-party tools)
5. Bundle every app's encrypted zip plus a `passwords.csv` into the outer download

Vendor detection: the tool inspects the ACS URL and entity ID for known patterns (e.g. `/Shibboleth.sso/` → Shibboleth) and selects the right "What to do" snippet from a built-in library. **No LLM** — fully deterministic since v2.1.2.

### Auth Events column

Reads from the Azure Tables `oktamigrationunits` table that Migration Realtime writes to. Each row holds `{partition=env, rowkey=sha1("env:unit"), event_count, first_seen, last_seen}`. Okta Admin queries this table by env and joins to the app list by canonical app name.

If Migration Realtime hasn't synced or the table is unreachable, the Auth Events column shows `—` (Migration Realtime is the source of truth — Okta Admin is read-only on this data).

### Identity
Calls Okta as **`OktaAdmin/<version> (wes-tools)`** via the shared `wes_tools_http.make_session()` helper.

## Common questions

### "Why did my visibility change fail for an OIDC app?"
The full-PUT roundtrip on OIDC apps trips an Okta validation error (`Api validation failed: mode`) for reasons the API docs don't document well. We've seen it for any OIDC app where `settings.signOn` carries a `mode` enum that's read-only. Known limitation — workaround is to set visibility from the Okta admin console directly for those apps.

### "Auth Events column is empty"
Migration Realtime hasn't recorded auth events for that app since the cutover anchor (default 2026-01-01). Either:
- The app legitimately hasn't been used since then
- The app emits a `target.displayName` that doesn't match the canonical name (alias mismatch)

### "Bulk SP Config download timed out"
Generating SP configs is fast (no LLM since v2.1.2), but the zip can be large for 50+ apps. If the download times out, generate in smaller batches.

### "How do I know which app a routing rule covers?"
Click the app row → Routing Rules section lists every rule that includes this app. Or use the **Look in routing rules** quick filter at the top of the grid.

---

## Architecture (for the nerds)

- **Stack:** Flask + gunicorn, deployed to Azure Container Apps in `your-resource-group`
- **Auth:** OIDC via the shared "Okta Admin Tools" app (Authlib + ProxyFix); `before_request` enforcer covers all non-public routes
- **Okta API:** `OktaClient` in `okta_client.py` — wraps Apps, Groups, Users, Policies, IdP Discovery, OIN catalog endpoints
- **SP Config generation:** `_render_sp_config_text()` in app.py — deterministic template render based on vendor detection from ACS URL / Audience patterns. Zero LLM dependency since v2.1.2.
- **Zip encryption:** `zip -P <password>` via subprocess — ZipCrypto for Windows Explorer native extract; deliberately not AES-256 because mainstream Windows tooling doesn't decrypt AES zips without third-party software
- **Azure Tables read:** `azure-data-tables` SDK, query partition=env, row key prefix optional
- **Identity:** `OktaAdmin/<APP_VERSION> (wes-tools)` UA via `wes_tools_http.make_session()`
- **In-tool docs:** this page renders from `HOWTO.md` next to `app.py`, via `wes_tools_docs.register_howto()`
- **Source:** `~/Projects/wes-tools/OKTA/Okta Admin/`

## What's not here yet

- Inline app config editing (today: redirect to Okta admin console)
- App-creation wizard (today: create in Okta admin console, then this tool inventories)
- Diff-style change preview before bulk actions
- Schedule recurring SP config exports

Speak up if any of these would help.
