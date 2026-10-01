#!/usr/bin/env python3
"""Verify a live agent capability response against source and OpenAPI."""

import argparse
import json
import sys
from pathlib import Path

from validate_agent_capabilities_manifest import (
    METHOD_RE,
    ROUTE_RE,
    load_openapi_methods,
    normalize_path,
)


def load_expected_routes(source: Path) -> dict[str, tuple[str, frozenset[str]]]:
    routes = {}
    for route in ROUTE_RE.finditer(source.read_text(encoding="utf-8")):
        name = route.group("name")
        if name in routes:
            raise ValueError(f"duplicate source route name: {name}")
        routes[name] = (
            normalize_path(route.group("path")),
            frozenset(method.lower() for method in METHOD_RE.findall(route.group("methods"))),
        )
    if not routes:
        raise ValueError(f"no agent capability routes found in {source}")
    return routes


def load_live_routes(manifest: Path) -> dict[str, tuple[str, frozenset[str]]]:
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid live manifest {manifest}: {error}") from error

    routes = document.get("routes") if isinstance(document, dict) else None
    if not isinstance(routes, list):
        raise ValueError("live manifest routes must be an array")

    result = {}
    for route in routes:
        if not isinstance(route, dict):
            raise ValueError("live manifest route must be an object")
        name = route.get("name")
        path = route.get("path")
        methods = route.get("methods")
        if not isinstance(name, str) or not isinstance(path, str):
            raise ValueError("live manifest route requires string name and path")
        if not isinstance(methods, list) or not all(isinstance(method, str) for method in methods):
            raise ValueError(f"live manifest route {name} requires a string methods array")
        method_set = frozenset(method.lower() for method in methods)
        if len(method_set) != len(methods):
            raise ValueError(f"live manifest route {name} has duplicate methods")
        if name in result:
            raise ValueError(f"duplicate live route name: {name}")
        result[name] = (normalize_path(path), method_set)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--openapi", type=Path, required=True)
    args = parser.parse_args()

    try:
        expected = load_expected_routes(args.source)
        live = load_live_routes(args.manifest)
    except ValueError as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1

    failures = 0
    for name in sorted(expected):
        if name not in live:
            print(f"FAIL live manifest missing route: {name}", file=sys.stderr)
            failures += 1
        elif live[name] != expected[name]:
            print(f"FAIL live manifest route mismatch: {name}", file=sys.stderr)
            failures += 1
    for name in sorted(set(live) - set(expected)):
        print(f"FAIL live manifest has unexpected route: {name}", file=sys.stderr)
        failures += 1

    openapi_methods = load_openapi_methods(args.openapi)
    for name, (path, methods) in expected.items():
        documented_methods = openapi_methods.get(path, set())
        for method in methods:
            if method not in documented_methods:
                print(
                    f"FAIL expected route is undocumented by OpenAPI: {name} {method.upper()} {path}",
                    file=sys.stderr,
                )
                failures += 1

    if failures:
        print(f"Live agent capability validation failed: {failures} issue(s)", file=sys.stderr)
        return 1
    print(f"Live agent capability validation passed: {len(expected)} route(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
