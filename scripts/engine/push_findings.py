#!/usr/bin/env python3
"""Push a JSON file of finding payloads through the engine ingest contract.

Usage:
    SITE=https://<deployment>.convex.site ENGINE_API_KEY=<key> \
        python3 push_findings.py <findings.json>

Honesty: refuses payloads without id/attackSteps (same rule as the server),
so a half-formed finding can never be pushed.
"""

from __future__ import annotations

import json
import sys

from orchestrator import api, log


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    with open(path, encoding="utf-8") as fh:
        payloads = json.load(fh)
    if isinstance(payloads, dict):
        payloads = [payloads]
    pushed = 0
    for payload in payloads:
        if "id" not in payload or not payload.get("attackSteps"):
            log(f"SKIP {payload.get('id', '<no-id>')}: missing id/attackSteps")
            continue
        result = api("/api/ingest_finding", method="POST", body=payload)
        log(f"pushed {payload['id']} -> {result}")
        pushed += 1
    log(f"done: {pushed}/{len(payloads)} payload(s) pushed")


if __name__ == "__main__":
    main()
