"""
setup_tokens.py — Store Okta API tokens in the OS credential store.

Run once per machine (or whenever a token changes):
    python setup_tokens.py

Tokens are saved to:
  macOS  → Keychain
  Windows → Credential Manager
  Linux  → Secret Service (GNOME Keyring / KWallet)
"""
from __future__ import annotations

import getpass
import sys

try:
    import keyring
except ImportError:
    print("ERROR: 'keyring' package not installed.")
    print("Run:  pip install keyring")
    sys.exit(1)

KEYRING_SERVICE = "okta-app-admin"

TOKENS = [
    ("OKTA_ADMIN_DEV_API_TOKEN",  "DEV  (https://dev-your-org.okta.com)"),
    ("OKTA_ADMIN_STG_API_TOKEN",  "STG  (https://staging-your-org.okta.com)"),
    ("OKTA_ADMIN_PROD_API_TOKEN", "PROD (https://your-org.okta.com)"),
]


def main() -> None:
    print("\nOkta App Admin Dashboard — Token Setup")
    print("=" * 42)
    print("Tokens will be stored in your OS credential store.")
    print("Press Enter to keep an existing token unchanged.\n")

    changed = 0
    for var, label in TOKENS:
        existing = keyring.get_password(KEYRING_SERVICE, var)
        hint = " [already set]" if existing else " [not set]"
        value = getpass.getpass(f"{label}{hint}\n  Enter token (Enter to skip): ")
        if value.strip():
            keyring.set_password(KEYRING_SERVICE, var, value.strip())
            print(f"  ✓ {var} saved.\n")
            changed += 1
        else:
            print(f"  – {var} unchanged.\n")

    print(f"Done. {changed} token(s) updated.")
    if changed:
        print("Restart the app to pick up the new tokens.\n")


if __name__ == "__main__":
    main()
