# Okta App Admin Dashboard

## The Problem

During a large-scale ADFS → Okta migration with 200+ applications, the Okta Admin Console becomes a bottleneck. Policy assignment, routing rule configuration, and app activation/deactivation are one-at-a-time operations in the UI. There's no bulk view that shows app inventory, current policy assignments, and routing rules in one place — making it impossible to verify migration state at a glance or make bulk changes efficiently.

## What It Does

A local web UI for Okta app management, built on top of the Okta API:

- View full SAML + OIDC app inventory across environments (DEV/STG/PROD)
- Assign authentication policies and routing rules to apps
- Activate and deactivate apps
- Bulk operations across multiple apps
- Secure token storage via OS Keyring — no credentials in config files

## Why It's Built This Way

- **OS Keyring**: API tokens stored in platform keyring (macOS/Windows/Linux) via `setup_tokens.py`. Never stored on disk or in environment files.
- **Multi-environment**: DEV/STG/PROD environments selectable at runtime — same UI, different Okta orgs.
- **Local-only**: Runs on `localhost:5002`. No external access, no auth gate needed — this is a local admin tool.

## Tech Stack

- Python 3.11+ / Flask (port 5002)
- Okta API client library
- OS Keyring (macOS/Windows/Linux) for credential storage

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure tokens (stores in OS keyring — you'll need Okta API tokens for each environment):
   ```bash
   python setup_tokens.py
   ```

3. Run:
   ```bash
   python app.py
   ```
   Open http://localhost:5002

## Environment Variables

See `.env.example`. All actual tokens must be stored via `setup_tokens.py` — do not put real tokens in `.env`.

## Status

Production — v1.0.0. Used alongside `adfs-okta-migration-tool` for the full ADFS → Okta migration workflow.

## Related

- [adfs-okta-migration-tool](../adfs-okta-migration-tool) — ADFS → Okta migration tooling; use alongside this dashboard for the full migration workflow.
