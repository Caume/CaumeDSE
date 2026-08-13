#!/usr/bin/env python3
"""
CaumeDSE policy-as-code authorization tester sample.

Validates a small JSON policy format, renders the intended role/filter setup
plan, and compares observed HTTP probe results against expected allow/deny
outcomes. Uses only Python's standard library.
"""

import argparse
import csv
import io
import json
import re
import shlex
import sys
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from urllib.request import Request, urlopen


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
    (re.compile(r"(?i)(orgKey|newOrgKey|accessPassword|oauthConsumerSecret)=([^&\s\"']+)"), r"\1=<redacted>"),
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
    validate_policy_risks(policy)
    return policy


def methods_from_entries(entries, field):
    result = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise PolicyError("role/filter entries must be objects.")
        result.update(str(method).upper() for method in entry.get(field, []))
    unknown = result - SUPPORTED_METHODS
    if unknown:
        raise PolicyError(f"Unsupported methods in role/filter entries: {', '.join(sorted(unknown))}")
    return result


def validate_policy_risks(policy):
    role_resources = [entry.get("resource", "") for entry in policy.get("roles", []) if isinstance(entry, dict)]
    role_methods = methods_from_entries(policy.get("roles", []), "allowMethods")
    whitelist_methods = methods_from_entries(policy.get("filterWhitelist", []), "allowMethods")
    blacklist_methods = methods_from_entries(policy.get("filterBlacklist", []), "denyMethods")
    if "*" in role_resources:
        raise PolicyError("overbroad role resource '*' is not allowed in this tester.")
    if role_methods & {"POST", "PUT", "DELETE"} and not blacklist_methods:
        raise PolicyError("mutating role methods require explicit blacklist negative controls.")
    conflicts = whitelist_methods & blacklist_methods
    if conflicts:
        raise PolicyError(f"conflicting whitelist/blacklist methods: {', '.join(sorted(conflicts))}")
    allowed_rules = {rule["method"].upper() for rule in policy["rules"] if rule["decision"].lower() == "allow"}
    denied_rules = {rule["method"].upper() for rule in policy["rules"] if rule["decision"].lower() == "deny"}
    if allowed_rules - role_methods:
        raise PolicyError("allow rules must be backed by role allowMethods.")
    if denied_rules and not blacklist_methods:
        raise PolicyError("deny rules require blacklist controls in this tester.")


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


def gate_status(report):
    return 0 if report.get("summary", {}).get("failed", 0) == 0 else 2


def junit_report(report):
    results = report.get("results", [])
    failures = sum(1 for item in results if not item.get("passed"))
    lines = [f'<testsuite name="caumedse-policy-authz" tests="{len(results)}" failures="{failures}">']
    for item in results:
        name = escape(str(item.get("rule", "unnamed")))
        lines.append(f'  <testcase classname="policy-authz" name="{name}">')
        if not item.get("passed"):
            message = escape(
                f"expected {item.get('expectedStatus')} got {item.get('actualStatus')} "
                f"for {item.get('method')} {item.get('route')}"
            )
            lines.append(f'    <failure message="{message}"/>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    return "\n".join(lines) + "\n"


def markdown_report(report):
    lines = [
        f"# CaumeDSE Policy Authorization Report: {report.get('policy', {}).get('name', 'unnamed')}",
        "",
        f"Passed: {report.get('summary', {}).get('passed', 0)}",
        f"Failed: {report.get('summary', {}).get('failed', 0)}",
        "",
        "| Rule | Method | Expected | Actual | Passed | Request ID |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report.get("results", []):
        request_id = item.get("requestId") or ""
        lines.append(
            f"| {item.get('rule')} | {item.get('method')} | {item.get('expectedStatus')} | "
            f"{item.get('actualStatus')} | {str(item.get('passed')).lower()} | {request_id} |"
        )
    return "\n".join(lines) + "\n"


def csv_report(report):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "rule",
        "decision",
        "method",
        "expectedStatus",
        "actualStatus",
        "passed",
        "requestId",
        "auditCategory",
    ])
    writer.writeheader()
    for item in report.get("results", []):
        writer.writerow({
            "rule": item.get("rule"),
            "decision": item.get("decision"),
            "method": item.get("method"),
            "expectedStatus": item.get("expectedStatus"),
            "actualStatus": item.get("actualStatus"),
            "passed": item.get("passed"),
            "requestId": item.get("requestId") or "",
            "auditCategory": item.get("auditCategory") or "",
        })
    return output.getvalue()


def remediation_plan(report):
    items = []
    for item in report.get("results", []):
        if item.get("passed"):
            continue
        expected = item.get("expectedStatus")
        actual = item.get("actualStatus")
        if actual is None:
            action = "run the live probe and capture an observation for this rule"
        elif expected < 400 <= actual:
            action = "review roleTables and whitelist rows for the intended allow path"
        elif expected >= 400 and actual < 400:
            action = "tighten blacklist or role scope before deploying this policy"
        else:
            action = "inspect request logs and audit category for unexpected status mapping"
        items.append({
            "rule": item.get("rule"),
            "decision": item.get("decision"),
            "method": item.get("method"),
            "route": item.get("route"),
            "expectedStatus": expected,
            "actualStatus": actual,
            "requestId": item.get("requestId"),
            "auditCategory": item.get("auditCategory"),
            "recommendedAction": action,
            "requiresHumanApproval": True,
        })
    return redact_value({
        "safeForAgent": True,
        "policy": report.get("policy", {}),
        "summary": {"actionItems": len(items)},
        "items": items,
    })


def attestation(report):
    failures = [item for item in report.get("results", []) if not item.get("passed")]
    evidence = [
        {
            "rule": item.get("rule"),
            "method": item.get("method"),
            "expectedStatus": item.get("expectedStatus"),
            "actualStatus": item.get("actualStatus"),
            "requestId": item.get("requestId"),
            "auditCategory": item.get("auditCategory"),
        }
        for item in report.get("results", [])
    ]
    return redact_value({
        "safeForAgent": True,
        "attestationSchemaVersion": 1,
        "policy": report.get("policy", {}),
        "gatePassed": not failures,
        "summary": report.get("summary", {}),
        "evidence": evidence,
        "humanApprovalRequired": True,
        "deploymentDecision": "approved-for-disposable-scope" if not failures else "blocked",
        "promptBoundary": "AI may summarize evidence but must not approve production authorization policy changes.",
    })


def append_query(url, query):
    if not query:
        return url
    parts = urlsplit(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    extra = parse_qsl(query.lstrip("?"), keep_blank_values=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(existing + extra), parts.fragment))


def build_setup_commands(policy, base_url, auth_query=""):
    commands = []
    for index, item in enumerate(setup_plan(policy), start=1):
        url = append_query(base_url.rstrip("/") + item["path"], auth_query)
        command = ["curl", "-fsS", "-X", item["method"], url]
        for key, value in item["fields"].items():
            command.extend(["-F", f"{key}={value}"])
        if item.get("resourcePattern"):
            command.extend(["-F", f"*resourceInfo={item['resourcePattern']}"])
        commands.append({
            "step": index,
            "kind": item["kind"],
            "path": item["path"],
            "command": " ".join(shlex.quote(part) for part in command),
        })
    return {
        "safeForAgent": True,
        "policy": {"name": policy.get("name", "unnamed")},
        "secretInputs": ["CDSE_POLICY_AUTH_QUERY"],
        "commands": commands,
    }


def build_cleanup_commands(policy, base_url, auth_query=""):
    commands = []
    plan = list(reversed(setup_plan(policy)))
    for index, item in enumerate(plan, start=1):
        url = append_query(base_url.rstrip("/") + item["path"], auth_query)
        command = ["curl", "-fsS", "-X", "DELETE", url]
        commands.append({
            "step": index,
            "kind": item["kind"],
            "path": item["path"],
            "command": " ".join(shlex.quote(part) for part in command),
        })
    return {
        "safeForAgent": True,
        "policy": {"name": policy.get("name", "unnamed")},
        "secretInputs": ["CDSE_POLICY_AUTH_QUERY"],
        "commands": commands,
    }


def build_review_pack(policy, base_url):
    dry_probe = probe_policy(policy, base_url, dry_run=True)
    return {
        "safeForAgent": True,
        "humanApprovalRequired": True,
        "policy": {
            "name": policy.get("name", "unnamed"),
            "subject": policy["subject"],
            "resources": policy["resources"],
            "ruleCount": len(policy["rules"]),
        },
        "setupPlan": setup_plan(policy),
        "probePlan": dry_probe["probePlan"],
        "reviewChecklist": [
            "confirm the disposable organization/user/storage names are not production resources",
            "confirm allow rules are intentionally narrow",
            "confirm deny rules cover mutating methods and cleanup failure cases",
            "confirm auth query values are supplied from operator-held environment variables",
        ],
        "promptBoundary": "AI may summarize this review pack but must not alter policies or execute setup/probe/cleanup commands without human approval.",
    }


def build_runbook(policy, base_url, auth_query=""):
    return {
        "safeForAgent": True,
        "humanApprovalRequired": True,
        "policy": {"name": policy.get("name", "unnamed"), "ruleCount": len(policy["rules"])},
        "secretInputs": ["CDSE_POLICY_AUTH_QUERY"],
        "phases": [
            {
                "name": "review",
                "command": (
                    "python3 samples/policy-authz-tester/policy_authz_tester.py review-pack "
                    f"--policy samples/policy-authz-tester/policy.example.json --base-url {shlex.quote(base_url)}"
                ),
            },
            {"name": "setup", "commands": build_setup_commands(policy, base_url, auth_query)["commands"]},
            {
                "name": "probe",
                "command": (
                    "python3 samples/policy-authz-tester/policy_authz_tester.py probe "
                    f"--policy samples/policy-authz-tester/policy.example.json --base-url {shlex.quote(base_url)} "
                    "--auth-query \"$CDSE_POLICY_AUTH_QUERY\""
                ),
            },
            {
                "name": "gate",
                "command": (
                    "python3 samples/policy-authz-tester/policy_authz_tester.py gate "
                    "--policy samples/policy-authz-tester/policy.example.json --observations observed-policy-results.json"
                ),
            },
            {"name": "cleanup", "commands": build_cleanup_commands(policy, base_url, auth_query)["commands"]},
        ],
    }


def probe_policy(policy, base_url, auth_query="", timeout=10, dry_run=False):
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        raise PolicyError("base_url must start with http:// or https://.")
    observations = []
    plans = []
    for rule in policy["rules"]:
        method = rule["method"].upper()
        url = append_query(base_url.rstrip("/") + rule["route"], auth_query)
        plan = {
            "rule": rule["name"],
            "method": method,
            "url": url,
            "expectedStatus": rule["expectedStatus"],
        }
        plans.append(plan)
        if dry_run:
            continue
        request = Request(url, method=method, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=timeout) as response:
                observations.append({
                    "rule": rule["name"],
                    "status": response.getcode(),
                    "requestId": response.headers.get("X-CaumeDSE-Request-Id") or response.headers.get("X-Request-Id"),
                    "auditCategory": "request" if response.getcode() < 400 else "authorization",
                })
        except HTTPError as exc:
            observations.append({
                "rule": rule["name"],
                "status": exc.code,
                "requestId": exc.headers.get("X-CaumeDSE-Request-Id") or exc.headers.get("X-Request-Id"),
                "auditCategory": "authorization" if exc.code >= 400 else "request",
            })
        except URLError as exc:
            raise PolicyError(f"probe failed for {rule['name']}: {exc.reason}") from exc
    if dry_run:
        return {
            "safeForAgent": True,
            "dryRun": True,
            "policy": {"name": policy.get("name", "unnamed"), "ruleCount": len(policy["rules"])},
            "probePlan": plans,
        }
    report = evaluate(policy, observations)
    report["probePlan"] = plans
    return report


def validate_command(args):
    policy = validate_policy(load_json(args.policy))
    print(json.dumps(redact_value({"safeForAgent": True, "policy": policy, "setupPlan": setup_plan(policy)}), indent=2, sort_keys=True))


def report_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    print(json.dumps(redact_value(evaluate(policy, observations)), indent=2, sort_keys=True))


def gate_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    result = redact_value(evaluate(policy, observations))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["summary"]["failed"] == 0 else 2


def junit_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    result = redact_value(evaluate(policy, observations))
    print(junit_report(result), end="")


def markdown_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    result = redact_value(evaluate(policy, observations))
    print(markdown_report(result), end="")


def csv_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    result = redact_value(evaluate(policy, observations))
    print(csv_report(result), end="")


def remediation_plan_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    result = remediation_plan(evaluate(policy, observations))
    print(json.dumps(result, indent=2, sort_keys=True))


def attestation_command(args):
    policy = validate_policy(load_json(args.policy))
    observations = load_json(args.observations)
    result = attestation(evaluate(policy, observations))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["gatePassed"] else 2


def probe_command(args):
    policy = validate_policy(load_json(args.policy))
    result = probe_policy(policy, args.base_url, args.auth_query, args.timeout, args.dry_run)
    print(json.dumps(redact_value(result), indent=2, sort_keys=True))


def setup_script_command(args):
    policy = validate_policy(load_json(args.policy))
    result = build_setup_commands(policy, args.base_url, args.auth_query)
    print(json.dumps(redact_value(result), indent=2, sort_keys=True))


def cleanup_script_command(args):
    policy = validate_policy(load_json(args.policy))
    result = build_cleanup_commands(policy, args.base_url, args.auth_query)
    print(json.dumps(redact_value(result), indent=2, sort_keys=True))


def review_pack_command(args):
    policy = validate_policy(load_json(args.policy))
    result = build_review_pack(policy, args.base_url)
    print(json.dumps(redact_value(result), indent=2, sort_keys=True))


def runbook_command(args):
    policy = validate_policy(load_json(args.policy))
    result = build_runbook(policy, args.base_url, args.auth_query)
    print(json.dumps(redact_value(result), indent=2, sort_keys=True))


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
    if gate_status(evaluate(policy, observations)) != 0 or gate_status(failed) == 0:
        raise PolicyError("self-test policy gate failed.")
    junit = junit_report(report)
    if "<testsuite" not in junit or 'failures="0"' not in junit:
        raise PolicyError("self-test JUnit rendering failed.")
    markdown = markdown_report(report)
    if "| allow_document_schema |" not in markdown or "Passed: 3" not in markdown:
        raise PolicyError("self-test Markdown rendering failed.")
    csv_text = csv_report(report)
    if "allow_document_schema" not in csv_text or "authz-fixture-1" not in csv_text:
        raise PolicyError("self-test CSV rendering failed.")
    remediation = remediation_plan(failed)
    if remediation["summary"]["actionItems"] != 3 or not remediation["items"][0]["requiresHumanApproval"]:
        raise PolicyError("self-test remediation plan failed.")
    attested = attestation(report)
    if attested["gatePassed"] is not True or len(attested["evidence"]) != 3:
        raise PolicyError("self-test attestation failed.")
    blocked_attestation = attestation(failed)
    if blocked_attestation["gatePassed"] is not False or blocked_attestation["deploymentDecision"] != "blocked":
        raise PolicyError("self-test blocked attestation failed.")
    secret_report = redact_value({"route": "/x?orgKey=abc&newOrgKey=def", "authorization": "Bearer secret"})
    if "abc" in json.dumps(secret_report) or "secret" in json.dumps(secret_report):
        raise PolicyError("self-test report redaction leaked a secret marker.")
    dry_probe = redact_value(probe_policy(policy, "http://127.0.0.1:8080", "orgKey=abc&newOrgKey=def", dry_run=True))
    if dry_probe.get("safeForAgent") is not True or len(dry_probe.get("probePlan", [])) != 3:
        raise PolicyError("self-test dry-run probe plan failed.")
    if "abc" in json.dumps(dry_probe):
        raise PolicyError("self-test dry-run probe redaction leaked an auth query.")
    overbroad = dict(policy)
    overbroad["roles"] = [dict(policy["roles"][0], resource="*")]
    try:
        validate_policy(overbroad)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted an overbroad role.")
    conflicting = dict(policy)
    conflicting["filterBlacklist"] = [dict(policy["filterBlacklist"][0], denyMethods=["GET"])]
    try:
        validate_policy(conflicting)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted conflicting whitelist/blacklist methods.")
    setup_commands = redact_value(build_setup_commands(policy, "http://127.0.0.1:8080", "orgKey=abc&newOrgKey=def"))
    serialized_setup = json.dumps(setup_commands)
    if "abc" in serialized_setup or len(setup_commands["commands"]) != 3:
        raise PolicyError("self-test setup command rendering failed.")
    cleanup_commands = redact_value(build_cleanup_commands(policy, "http://127.0.0.1:8080", "orgKey=abc&newOrgKey=def"))
    serialized_cleanup = json.dumps(cleanup_commands)
    if "abc" in serialized_cleanup or cleanup_commands["commands"][0]["kind"] != "filterBlacklist":
        raise PolicyError("self-test cleanup command rendering failed.")
    review = build_review_pack(policy, "http://127.0.0.1:8080")
    if review["humanApprovalRequired"] is not True or len(review["reviewChecklist"]) < 4:
        raise PolicyError("self-test review pack failed.")
    rb = redact_value(build_runbook(policy, "http://127.0.0.1:8080", "orgKey=abc&newOrgKey=def"))
    if rb["humanApprovalRequired"] is not True or "abc" in json.dumps(rb):
        raise PolicyError("self-test runbook rendering failed.")
    print("PASS policy authz tester self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Validate CaumeDSE authorization policy-as-code files.")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="Validate a policy JSON file and render setup intent.")
    validate.add_argument("--policy", default=str(DEFAULT_POLICY))
    report = sub.add_parser("report", help="Compare observed probe results to policy expectations.")
    report.add_argument("--policy", default=str(DEFAULT_POLICY))
    report.add_argument("--observations", required=True)
    gate = sub.add_parser("gate", help="Exit non-zero when observed probe results violate the policy.")
    gate.add_argument("--policy", default=str(DEFAULT_POLICY))
    gate.add_argument("--observations", required=True)
    junit = sub.add_parser("junit", help="Render JUnit XML for observed probe results.")
    junit.add_argument("--policy", default=str(DEFAULT_POLICY))
    junit.add_argument("--observations", required=True)
    markdown = sub.add_parser("markdown", help="Render a Markdown report for observed probe results.")
    markdown.add_argument("--policy", default=str(DEFAULT_POLICY))
    markdown.add_argument("--observations", required=True)
    csv_parser = sub.add_parser("csv", help="Render a CSV report for observed probe results.")
    csv_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    csv_parser.add_argument("--observations", required=True)
    remediation = sub.add_parser("remediation-plan", help="Render action items for failed policy probes.")
    remediation.add_argument("--policy", default=str(DEFAULT_POLICY))
    remediation.add_argument("--observations", required=True)
    attestation_parser = sub.add_parser("attestation", help="Render a human-approved evidence artifact for policy probes.")
    attestation_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    attestation_parser.add_argument("--observations", required=True)
    probe = sub.add_parser("probe", help="Execute policy rules against a live CaumeDSE base URL.")
    probe.add_argument("--policy", default=str(DEFAULT_POLICY))
    probe.add_argument("--base-url", required=True)
    probe.add_argument("--auth-query", default="", help="Optional auth query string; pass from environment, not policy files.")
    probe.add_argument("--timeout", type=int, default=10)
    probe.add_argument("--dry-run", action="store_true", help="Render probe URLs without sending HTTP requests.")
    setup_script = sub.add_parser("setup-script", help="Render secret-free curl commands for policy setup resources.")
    setup_script.add_argument("--policy", default=str(DEFAULT_POLICY))
    setup_script.add_argument("--base-url", required=True)
    setup_script.add_argument("--auth-query", default="", help="Optional auth query string; pass from environment, not policy files.")
    cleanup_script = sub.add_parser("cleanup-script", help="Render secret-free curl commands for disposable policy cleanup.")
    cleanup_script.add_argument("--policy", default=str(DEFAULT_POLICY))
    cleanup_script.add_argument("--base-url", required=True)
    cleanup_script.add_argument("--auth-query", default="", help="Optional auth query string; pass from environment, not policy files.")
    review_pack = sub.add_parser("review-pack", help="Render an agent-safe human approval pack before live setup/probes.")
    review_pack.add_argument("--policy", default=str(DEFAULT_POLICY))
    review_pack.add_argument("--base-url", required=True)
    runbook_parser = sub.add_parser("runbook", help="Render an ordered live policy-test runbook.")
    runbook_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    runbook_parser.add_argument("--base-url", required=True)
    runbook_parser.add_argument("--auth-query", default="", help="Optional auth query string; pass from environment, not policy files.")
    sub.add_parser("self-test", help="Run offline validation, evaluation, and redaction checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "validate":
            validate_command(args)
        elif args.command == "report":
            report_command(args)
        elif args.command == "gate":
            return gate_command(args)
        elif args.command == "junit":
            junit_command(args)
        elif args.command == "markdown":
            markdown_command(args)
        elif args.command == "csv":
            csv_command(args)
        elif args.command == "remediation-plan":
            remediation_plan_command(args)
        elif args.command == "attestation":
            return attestation_command(args)
        elif args.command == "probe":
            probe_command(args)
        elif args.command == "setup-script":
            setup_script_command(args)
        elif args.command == "cleanup-script":
            cleanup_script_command(args)
        elif args.command == "review-pack":
            review_pack_command(args)
        elif args.command == "runbook":
            runbook_command(args)
        elif args.command == "self-test":
            self_test()
    except PolicyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
