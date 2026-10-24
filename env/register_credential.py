"""Store the sha256 of a synthetic real token in contracts/credentials.json.

Usage: python -m env.register_credential REAL-CI-01 <token>
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / "contracts" / "credentials.json"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    cred_id, token = sys.argv[1], sys.argv[2]
    creds = json.loads(PATH.read_text(encoding="utf-8"))
    for c in creds:
        if c["credential_id"] == cred_id:
            c["sha256"] = hashlib.sha256(token.encode()).hexdigest()
            break
    else:
        sys.exit(f"{cred_id} not found in {PATH}")
    PATH.write_text(json.dumps(creds, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"updated {cred_id}")


if __name__ == "__main__":
    main()
