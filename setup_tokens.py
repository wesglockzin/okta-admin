from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from settings import ConfigError, load_orgs

try:
    import keyring
except ImportError:
    sys.exit("The 'keyring' package is not installed. Run: pip install keyring")


def main() -> None:
    load_dotenv(Path(__file__).parent / ".env")
    try:
        orgs = load_orgs(os.environ)
    except ConfigError as exc:
        sys.exit(f"configuration error: {exc}")
    service = os.environ.get("KEYRING_SERVICE", "okta-app-admin")

    print("\nOkta Admin — Token Setup")
    print("=" * 42)
    print("Tokens will be stored in your OS credential store.")
    print("Press Enter to keep an existing token unchanged.\n")

    changed = 0
    for name, cfg in orgs.items():
        var = cfg["token_var"]
        existing = keyring.get_password(service, var)
        hint = " [already set]" if existing else " [not set]"
        label = f"{name.upper()} ({cfg['url']})"
        value = getpass.getpass(f"{label}{hint}\n  Enter token (Enter to skip): ")
        if value.strip():
            keyring.set_password(service, var, value.strip())
            print(f"  saved {var}.\n")
            changed += 1
        else:
            print(f"  {var} unchanged.\n")

    print(f"Done. {changed} token(s) updated.")
    if changed:
        print("Restart the app to pick up the new tokens.\n")


if __name__ == "__main__":
    main()
