#!/usr/bin/env python3
"""Fixture tests for the agent capability manifest validator."""

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT_DIR / "TEST" / "validate_agent_capabilities_manifest.py"
FIXTURES_DIR = ROOT_DIR / "TEST" / "testfiles" / "agent-capabilities-manifest"


def run_case(name: str, source: str, openapi: str, expected_success: bool, expected: str) -> int:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--source", str(FIXTURES_DIR / source), "--openapi", str(FIXTURES_DIR / openapi)],
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
    failures += run_case("documented direct route", "valid.c", "valid.yaml", True, "1 route(s)")
    failures += run_case("missing advertised method", "missing-method.c", "valid.yaml", False, "undocumented method: POST /direct")
    failures += run_case("missing advertised path", "missing-path.c", "valid.yaml", False, "undocumented path: /missing")
    if failures:
        print(f"Agent capability manifest fixture tests failed: {failures} issue(s)", file=sys.stderr)
        return 1
    print("Agent capability manifest fixture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
