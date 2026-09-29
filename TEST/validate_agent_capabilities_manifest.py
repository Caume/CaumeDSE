#!/usr/bin/env python3
"""Verify that agent capability routes are documented by OpenAPI."""

import argparse
import re
import sys
from pathlib import Path

ROUTE_RE = re.compile(
    r'\{\\"name\\":\\"(?P<name>[^"\\]+)\\",\\"path\\":\\"'
    r'(?P<path>[^"\\]+)\\",\\"methods\\":\[(?P<methods>.*?)\],'
    r'\\"authRequired\\":(?:true|false)\}'
)
METHOD_RE = re.compile(r'\\"(?P<method>[A-Z]+)\\"')
PATH_RE = re.compile(r'^  (?P<path>/\S+):\s*$')
OPENAPI_METHOD_RE = re.compile(r'^    (?P<method>get|post|put|delete|head|options):')
PLACEHOLDER_NAMES = {
    "org": "organization",
    "type": "documentType",
    "db": "dbName",
    "table": "dbTable",
    "row": "contentRow",
    "column": "contentColumn",
    "script": "parserScript",
}


def normalize_path(path: str) -> str:
    return re.sub(
        r'\{([^}]+)\}',
        lambda match: "{" + PLACEHOLDER_NAMES.get(match.group(1), match.group(1)) + "}",
        path,
    )


def load_openapi_methods(spec: Path) -> dict[str, set[str]]:
    paths: dict[str, set[str]] = {}
    current_path: str | None = None
    for line in spec.read_text(encoding="utf-8").splitlines():
        path_match = PATH_RE.match(line)
        if path_match:
            current_path = path_match.group("path")
            paths.setdefault(current_path, set())
            continue
        method_match = OPENAPI_METHOD_RE.match(line)
        if current_path and method_match:
            paths[current_path].add(method_match.group("method"))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--openapi", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.read_text(encoding="utf-8")
    openapi_methods = load_openapi_methods(args.openapi)
    routes = list(ROUTE_RE.finditer(source))
    if not routes:
        print(f"FAIL no agent capability routes found in {args.source}", file=sys.stderr)
        return 1

    failures = 0
    for route in routes:
        name = route.group("name")
        path = normalize_path(route.group("path"))
        documented_methods = openapi_methods.get(path)
        if documented_methods is None:
            print(f"FAIL {name} advertises undocumented path: {path}", file=sys.stderr)
            failures += 1
            continue
        for method in METHOD_RE.findall(route.group("methods")):
            if method.lower() not in documented_methods:
                print(
                    f"FAIL {name} advertises undocumented method: {method} {path}",
                    file=sys.stderr,
                )
                failures += 1

    if failures:
        print(f"Agent capability manifest validation failed: {failures} issue(s)", file=sys.stderr)
        return 1

    print(f"Agent capability manifest validation passed: {len(routes)} route(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
