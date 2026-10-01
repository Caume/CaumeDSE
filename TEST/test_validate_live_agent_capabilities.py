#!/usr/bin/env python3
"""Fixture tests for the live agent capability validator."""

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT_DIR / "TEST" / "validate_live_agent_capabilities.py"
FIXTURES_DIR = ROOT_DIR / "TEST" / "testfiles" / "live-agent-capabilities"
SOURCE = ROOT_DIR / "TEST" / "testfiles" / "agent-capabilities-manifest" / "valid.c"
OPENAPI = ROOT_DIR / "TEST" / "testfiles" / "agent-capabilities-manifest" / "valid.yaml"


def run_case(name: str, manifest: str, expected_success: bool, expected: str) -> int:
    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest",
            str(FIXTURES_DIR / manifest),
            "--source",
            str(SOURCE),
            "--openapi",
            str(OPENAPI),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    success = result.returncode == 0
    if success != expected_success or expected not in output:
        print(f"FAIL {name}:\n{output}", file=sys.stderr)
        return 1
    print(f"PASS {name}")
    return 0


def main() -> int:
    failures = 0
    failures += run_case("matching manifest", "valid.json", True, "1 route(s)")
    failures += run_case("missing method", "missing-method.json", False, "route mismatch: direct")
    failures += run_case("unexpected route", "unexpected-route.json", False, "unexpected route: extra")
    failures += run_case("invalid JSON", "invalid.json", False, "invalid live manifest")
    if failures:
        print(f"Live agent capability fixture tests failed: {failures} issue(s)", file=sys.stderr)
        return 1
    print("Live agent capability fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
