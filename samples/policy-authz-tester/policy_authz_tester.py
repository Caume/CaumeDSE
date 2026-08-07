#!/usr/bin/env python3
"""
CaumeDSE policy-as-code authorization tester sample.

Validates a small JSON policy format, renders the intended role/filter setup
plan, and compares observed HTTP probe results against expected allow/deny
outcomes. Uses only Python's standard library.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY = SAMPLE_DIR / "policy.example.json"
SENSITIVE_KEYS = {
    "orgKey",
    "newOrgKey",
    "authorization",
    "accessPassword",
    "oauthConsumerSecret",
    "certificate",
    "privateKey",
}
SECRET_PATTERNS = [
    (re.compile(r"(?i)(orgKey|newOrgKey|accessPassword|oauthConsumerSecret)=([^&\s\"]+)"), r"\1=<redacted>"),
    (re.compile(r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9._~-]+"), "Authorization: Bearer <redacted>"),
]
SUPPORTED_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}
SUPPORTED_DECISIONS = {"allow", "deny"}
METHOD_FIELDS = {
    "GET": "*_get",
    "POST": "*_post",
    "PUT": "*_put",
    "DELETE": "*_delete",
    "HEAD": "*_head",
    "OPTIONS": "*_options",
}


class PolicyError(Exception):
    pass


def load_json(path):
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise PolicyError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Invalid JSON in {path}: {exc}") from exc


def redact_value(value):
    if isinstance(value, dict):
        return {key: ("<redacted>" if key in SENSITIVE_KEYS else redact_value(val)) for key, val in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if not isinstance(value, str):
        return value
    text = value
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def require_string(container, name, context):
    value = container.get(name)
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{context} must define non-empty string field: {name}")
    return value


def require_int(container, name, context):
    value = container.get(name)
    if not isinstance(value, int):
        raise PolicyError(f"{context} must define integer field: {name}")
    return value


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise PolicyError("Policy must be a JSON object.")
    if policy.get("policySchemaVersion") != 1:
        raise PolicyError("policySchemaVersion must be 1.")
    subject = policy.get("subject")
    if not isinstance(subject, dict):
        raise PolicyError("Policy must define subject object.")
    for field in ("organization", "user"):
        require_string(subject, field, "subject")
    resources = policy.get("resources", {})
    if not isinstance(resources, dict):
        raise PolicyError("resources must be an object.")
    for field in ("storage", "document"):
        require_string(resources, field, "resources")
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PolicyError("Policy must define at least one rule.")
    seen = set()
    for index, rule in enumerate(rules):
        context = f"rules[{index}]"
        if not isinstance(rule, dict):
            raise PolicyError(f"{context} must be an object.")
        name = require_string(rule, "name", context)
        if name in seen:
            raise PolicyError(f"Duplicate rule name: {name}")
        seen.add(name)
        method = require_string(rule, "method", context).upper()
        if method not in SUPPORTED_METHODS:
            raise PolicyError(f"{context}.method is unsupported: {method}")
        decision = require_string(rule, "decision", context).lower()
        if decision not in SUPPORTED_DECISIONS:
            raise PolicyError(f"{context}.decision must be allow or deny.")
        status = require_int(rule, "expectedStatus", context)
        if decision == "allow" and status >= 400:
            raise PolicyError(f"{context} allow rule must expect a non-error status.")
        if decision == "deny" and status < 400:
            raise PolicyError(f"{context} deny rule must expect an error status.")
        require_string(rule, "route", context)
    return policy


def method_map(allowed_methods):
    allowed = {str(method).upper() for method in allowed_methods}
    unknown = allowed - SUPPORTED_METHODS
    if unknown:
        raise PolicyError(f"Unsupported methods in setup plan: {', '.join(sorted(unknown))}")
    return {field: ("1" if method in allowed else "0") for method, field in METHOD_FIELDS.items()}


def setup_plan(policy):
    subject = policy["subject"]
    resources = policy["resources"]
    org = subject["organization"]
    user = subject["user"]
    route_base = f"/organizations/{org}/users/{user}"
    roles = policy.get("roles", [])
    whitelist = policy.get("filterWhitelist", [])
    blacklist = policy.get("filterBlacklist", [])
    plan = []
    for role in roles:
        table = require_string(role, "resource", "roles[]")
        plan.append({
            "kind": "roleTable",
            "method": "POST",
            "path": f"{route_base}/roleTables/{table}",
            "fields": method_map(role.get("allowMethods", [])),
        })
    for entry in whitelist:
        filter_user = entry.get("user", user)
        plan.append({
            "kind": "filterWhitelist",
            "method": "POST",
            "path": f"{route_base}/filterWhitelist/{filter_user}",
            "fields": method_map(entry.get("allowMethods", [])),
            "resourcePattern": entry.get("resourcePattern", resources["document"]),
        })
    for entry in blacklist:
        filter_user = entry.get("user", user)
        plan.append({
            "kind": "filterBlacklist",
            "method": "POST",
            "path": f"{route_base}/filterBlacklist/{filter_user}",
            "fields": method_map(entry.get("denyMethods", [])),
            "resourcePattern": entry.get("resourcePattern", resources["document"]),
        })
    return plan


def observation_map(observations):
    if not isinstance(observations, list):
        raise PolicyError("observations must be a JSON array.")
    mapped = {}
    for item in observations:
        if not isinstance(item, dict):
            raise PolicyError("each observation must be an object.")
        name = require_string(item, "rule", "observation")
        if name in mapped:
            raise PolicyError(f"duplicate observation for rule: {name}")
        mapped[name] = item
    return mapped


def evaluate(policy, observations):
    observed = observation_map(observations)
    results = []
    for rule in policy["rules"]:
        item = observed.get(rule["name"])
        actual = item.get("status") if item else None
        passed = actual == rule["expectedStatus"]
        results.append({
            "rule": rule["name"],
            "decision": rule["decision"],
            "method": rule["method"].upper(),
            "route": rule["route"],
            "expectedStatus": rule["expectedStatus"],
            "actualStatus": actual,
            "requestId": item.get("requestId") if item else None,
            "auditCategory": item.get("auditCategory") if item else None,
            "passed": passed,
        })
    counts = Counter("passed" if item["passed"] else "failed" for item in results)
    return {
        "safeForAgent": True,
        "policy": {
            "name": policy.get("name", "unnamed"),
            "subject": policy["subject"],
            "resources": policy["resources"],
            "ruleCount": len(policy["rules"]),
        },
        "setupPlan": setup_plan(policy),
        "summary": {"passed": counts["passed"], "failed": counts["failed"]},
        "results": results,
    }


def validate_command(args):
    policy = validate_policy(load_json(args.policy))
    print(json.dumps(redact_value({"safeForAgent": True, "policy": policy, "setupPlan": setup_plan(policy)}), indent=2, sort_keys=True))


def report_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    print(json.dumps(redact_value(evaluate(policy, observations)), indent=2, sort_keys=True))


def self_test():
    policy = validate_policy(load_json(DEFAULT_POLICY))
    observations = [
        {"rule": "allow_document_schema", "status": 200, "requestId": "authz-fixture-1", "auditCategory": "request"},
        {"rule": "deny_document_delete", "status": 403, "requestId": "authz-fixture-2", "auditCategory": "authorization"},
        {"rule": "deny_blacklisted_post", "status": 403, "requestId": "authz-fixture-3", "auditCategory": "authorization"},
    ]
    report = redact_value(evaluate(policy, observations))
    if report["summary"] != {"passed": 3, "failed": 0}:
        raise PolicyError("self-test expected all fixture observations to pass.")
    failed = evaluate(policy, [{"rule": "allow_document_schema", "status": 403}])
    if failed["summary"]["failed"] == 0:
        raise PolicyError("self-test failed to detect a mismatched observation.")
    secret_report = redact_value({"route": "/x?orgKey=abc&newOrgKey=def", "authorization": "Bearer secret"})
    if "abc" in json.dumps(secret_report) or "secret" in json.dumps(secret_report):
        raise PolicyError("self-test report redaction leaked a secret marker.")
    print("PASS policy authz tester self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Validate CaumeDSE authorization policy-as-code files.")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="Validate a policy JSON file and render setup intent.")
    validate.add_argument("--policy", default=str(DEFAULT_POLICY))
    report = sub.add_parser("report", help="Compare observed probe results to policy expectations.")
    report.add_argument("--policy", default=str(DEFAULT_POLICY))
    report.add_argument("--observations", required=True)
    sub.add_parser("self-test", help="Run offline validation, evaluation, and redaction checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "validate":
            validate_command(args)
        elif args.command == "report":
            report_command(args)
        elif args.command == "self-test":
            self_test()
    except PolicyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
