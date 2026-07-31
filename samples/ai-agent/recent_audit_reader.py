#!/usr/bin/env python3
"""Read recent CaumeDSE AuditJSON lines from a local service log."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Iterable


PREFIX = "CaumeDSE AuditJSON: "
SECRET_MARKERS = ("Authorization:", "Bearer ")


def iter_audit_events(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if PREFIX not in line:
                continue
            payload = line.split(PREFIX, 1)[1].strip()
            if not payload.startswith("{"):
                continue
            try:
                event, _ = json.JSONDecoder().raw_decode(payload)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("auditSchemaVersion") == 1 and event.get("safeForAgent") is True:
                yield event


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize recent CaumeDSE structured audit events.")
    parser.add_argument("log", type=Path, help="CaumeDSE service log containing AuditJSON lines.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum events to return.")
    args = parser.parse_args()

    events = list(iter_audit_events(args.log))[-max(1, args.limit):]
    combined = json.dumps(events, sort_keys=True)
    if any(marker in combined for marker in SECRET_MARKERS):
        raise SystemExit("refusing to print audit events that appear to contain credential markers")

    categories = Counter(str(event.get("category", "unknown")) for event in events)
    print(json.dumps(
        {
            "source": str(args.log),
            "returnedEvents": len(events),
            "categories": dict(sorted(categories.items())),
            "events": events,
        },
        indent=2,
        sort_keys=True,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
