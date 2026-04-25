# Okta Admin

A local Flask web UI for managing Okta SAML and OIDC applications across DEV / STG / PROD environments — without touching the Okta Admin Console.

## Overview

The Okta Admin Console is comprehensive but slow for bulk operations and offers limited visibility into config drift across environments. This tool gives Identity Engineers a fast, scriptable surface for everyday application-management tasks: bulk activate/deactivate, policy assignment, IDP routing rule assignment, and inventory comparison across environments.

## Features

* **App inventory** across DEV, STG, PROD with at-a-glance status
* **Authentication policy assignment** — bulk apply / change policy per app
* **IDP routing rule assignment** — wire apps to the right routing rules
* **Activate / deactivate** — toggle app status without console clicks
* **Action logging** — every API mutation appended to `okta-admin-actions.log`
* **Per-edit backups** — `backups/<filename>.bak` written before every file edit, by convention

## Technical Stack

* **Backend:** Python 3, Flask
* **Frontend:** Jinja2 templates + minimal CSS
* **Okta integration:** Direct REST API calls via `okta_client.py`
* **Token storage:** OS keyring (macOS Keychain / Windows Credential Manager) under service `okta-app-admin`

## Configuration

Tokens are stored in the OS keyring per environment. Run setup once per machine:

```bash
python setup_tokens.py
```

This prompts for and stores:

* `OKTA_ADMIN_DEV_API_TOKEN`
* `OKTA_ADMIN_STG_API_TOKEN`
* `OKTA_ADMIN_PROD_API_TOKEN`

The application's `get_token(var)` helper reads the keyring first and falls back to a `.env` file if the keyring entry is missing.

## Security Conventions

* **Never hardcode tokens.** Token values are kept in OS keyring; `.env` is a fallback for development only.
* **Pre-filter by app status.** Bulk operations always pre-filter to active apps — Okta's API rejects visibility, policy, and routing changes against deactivated apps with a 403, which is misleading for batch flows.
* **Backup before edit.** Every file mutation creates `backups/<filename>.bak` first.

## Running

```bash
python app.py
```

Default port: see `app.py` for the Flask binding (typically `5000`).
