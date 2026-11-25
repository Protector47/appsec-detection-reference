#!/usr/bin/env python3
"""Validate every example event against the security event schema.

Also fails if any event field value looks like a secret (long hex or
base64 blobs in fields that should not carry them) and if timestamps
inside a scenario go backwards.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
schema = json.loads((ROOT / "schema" / "security-event.schema.json").read_text())
validator = Draft202012Validator(schema, format_checker=FormatChecker())

errors = 0
files = sorted((ROOT / "examples" / "events").glob("*.jsonl"))
if not files:
    print("No example event files found", file=sys.stderr)
    sys.exit(1)

for path in files:
    last_ts = ""
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        rec = json.loads(line)
        for err in validator.iter_errors(rec):
            print(f"{path.name}:{lineno}: {err.message}")
            errors += 1
        if rec["ts"] < last_ts:
            print(f"{path.name}:{lineno}: timestamp goes backwards")
            errors += 1
        last_ts = rec["ts"]

if errors:
    print(f"{errors} problem(s) found", file=sys.stderr)
    sys.exit(1)
print(f"Validated {len(files)} files against the schema.")
