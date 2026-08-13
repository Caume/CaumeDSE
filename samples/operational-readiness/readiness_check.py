#!/usr/bin/env python3
"""
CaumeDSE operational readiness sample.

Reports safe machine-readable and human-readable readiness for operators and
automation. It checks paths and declared runtime settings without reading
protected data or accepting secret values.
"""

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path


SENSITIVE_KEYS = {"orgKey", "newOrgKey", "accessPassword", "oauthConsumerSecret", "privateKey", "secret"}
SECRET_PATTERNS = [
    (re.compile(r"(?i)(orgKey|newOrgKey|accessPassword|oauthConsumerSecret|password)=([^&\s\"']+)"), r"\1=<redacted>"),
]
HERRADURA_PROFILES = {"hsk-en-la-aead-256", "HERRADURAKEX_HSK_EN_LA_AEAD_256"}
AES_PROFILES = {"aes-256-cbc", "CME_OPENSSL_AES256_CBC"}
STATE_RANK = {"healthy": 0, "degraded": 1, "misconfigured": 2, "unsafe": 3}
ENV_FIELDS = {
    "CDSE_READINESS_STORAGE_PATH": "storage_path",
    "CDSE_READINESS_PARSER_TEMP_DIR": "parser_temp_dir",
    "CDSE_READINESS_STORAGE_PROFILE": "storage_profile",
    "CDSE_READINESS_TLS_AUTH_STATE": "tls_auth_state",
    "CDSE_READINESS_BUILD_MODE": "build_mode",
    "CDSE_READINESS_MAX_CONNECTIONS": "max_connections",
    "CDSE_READINESS_THREAD_POOL_SIZE": "thread_pool_size",
}
BOOL_ENV_FIELDS = {
    "CDSE_READINESS_HERRADURA_AVAILABLE": "herradura_available",
    "CDSE_READINESS_PARSER_POLICY_ENABLED": "parser_policy_enabled",
}


class ReadinessError(Exception):
    pass


def redact(value):
    if isinstance(value, dict):
        return {key: ("<redacted>" if key in SENSITIVE_KEYS else redact(val)) for key, val in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = value
        for pattern, replacement in SECRET_PATTERNS:
            text = pattern.sub(replacement, text)
        return text
    return value


def add_check(checks, name, state, message, **fields):
    if state not in STATE_RANK:
        raise ReadinessError(f"unsupported readiness state: {state}")
    item = {"name": name, "state": state, "message": message}
    item.update(fields)
    checks.append(item)


def load_json(path):
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise ReadinessError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReadinessError(f"Invalid JSON in {path}: {exc}") from exc


def bool_from_text(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def apply_config_and_env(args):
    if args.config:
        config = load_json(args.config)
        if not isinstance(config, dict):
            raise ReadinessError("config must be a JSON object.")
        for key, value in config.items():
            if hasattr(args, key):
                setattr(args, key, value)
    for env_name, field in ENV_FIELDS.items():
        if env_name in os.environ:
            value = os.environ[env_name]
            if field in {"max_connections", "thread_pool_size"}:
                value = int(value)
            setattr(args, field, value)
    for env_name, field in BOOL_ENV_FIELDS.items():
        if env_name in os.environ:
            setattr(args, field, bool_from_text(os.environ[env_name]))
    return args


def path_check(checks, name, path, require_write=False):
    target = Path(path)
    if not target.exists():
        add_check(checks, name, "misconfigured", "path does not exist", path=str(target))
        return
    if not target.is_dir():
        add_check(checks, name, "misconfigured", "path is not a directory", path=str(target))
        return
    if not os.access(target, os.R_OK):
        add_check(checks, name, "misconfigured", "path is not readable", path=str(target))
        return
    if require_write and not os.access(target, os.W_OK):
        add_check(checks, name, "misconfigured", "path is not writable", path=str(target))
        return
    add_check(checks, name, "healthy", "path is accessible", path=str(target), writable=bool(os.access(target, os.W_OK)))


def temp_dir_check(checks, path):
    target = Path(path)
    path_check(checks, "parserTempDirectory", target, require_write=True)
    if not target.exists() or not target.is_dir():
        return
    mode = target.stat().st_mode
    world_writable = bool(mode & stat.S_IWOTH)
    sticky = bool(mode & stat.S_ISVTX)
    if world_writable and not sticky:
        add_check(checks, "parserTempDirectorySafety", "unsafe", "world-writable temp directory lacks sticky bit", path=str(target))
    else:
        add_check(checks, "parserTempDirectorySafety", "healthy", "temp directory permissions are acceptable", path=str(target))


def build_report(args):
    checks = []
    profile = args.storage_profile
    herradura_available = args.herradura_available
    path_check(checks, "storagePath", args.storage_path, require_write=True)
    temp_dir_check(checks, args.parser_temp_dir)
    if profile in HERRADURA_PROFILES and not herradura_available:
        add_check(checks, "storageCryptoProfile", "misconfigured", "Herradura profile requested but provider is unavailable", profile=profile)
    elif profile in HERRADURA_PROFILES or profile in AES_PROFILES:
        add_check(checks, "storageCryptoProfile", "healthy", "configured storage crypto profile is recognized", profile=profile)
    else:
        add_check(checks, "storageCryptoProfile", "degraded", "storage crypto profile is unknown to this sample", profile=profile)
    add_check(checks, "herraduraBuild", "healthy" if herradura_available else "degraded",
              "Herradura provider is available" if herradura_available else "Herradura provider is not available",
              available=herradura_available)
    if args.tls_auth_state == "bypass":
        add_check(checks, "tlsAuth", "unsafe", "TLS client-auth bypass is enabled; use only for DEBUG verification")
    elif args.tls_auth_state == "required":
        add_check(checks, "tlsAuth", "healthy", "TLS client-auth is required")
    else:
        add_check(checks, "tlsAuth", "degraded", "TLS auth state was not provided")
    if args.build_mode == "debug":
        add_check(checks, "buildMode", "unsafe", "DEBUG build mode is active")
    elif args.build_mode == "release":
        add_check(checks, "buildMode", "healthy", "release build mode declared")
    else:
        add_check(checks, "buildMode", "degraded", "build mode was not provided")
    add_check(checks, "parserPolicy", "healthy" if args.parser_policy_enabled else "degraded",
              "parser policy is enabled" if args.parser_policy_enabled else "parser policy state is disabled or unknown",
              enabled=args.parser_policy_enabled)
    worst = max(checks, key=lambda item: STATE_RANK[item["state"]])["state"]
    return redact({
        "safeForAgent": True,
        "readinessSchemaVersion": 1,
        "state": worst,
        "checks": checks,
        "limits": {
            "maxConnections": args.max_connections,
            "threadPoolSize": args.thread_pool_size,
        },
    })


def print_text(report):
    print(f"state: {report['state']}")
    for item in report["checks"]:
        print(f"{item['state']}: {item['name']} - {item['message']}")


def compare_reports(current, baseline):
    current_checks = {item["name"]: item for item in current.get("checks", [])}
    baseline_checks = {item["name"]: item for item in baseline.get("checks", [])}
    drift = []
    for name in sorted(set(current_checks) | set(baseline_checks)):
        current_state = current_checks.get(name, {}).get("state")
        baseline_state = baseline_checks.get(name, {}).get("state")
        if current_state != baseline_state:
            drift.append({
                "check": name,
                "baselineState": baseline_state,
                "currentState": current_state,
                "severity": "regression" if STATE_RANK.get(current_state, 9) > STATE_RANK.get(baseline_state, 9) else "change",
            })
    return redact({
        "safeForAgent": True,
        "readinessSchemaVersion": 1,
        "baselineState": baseline.get("state"),
        "currentState": current.get("state"),
        "summary": {
            "changes": len(drift),
            "regressions": sum(1 for item in drift if item["severity"] == "regression"),
        },
        "drift": drift,
    })


def agent_context(report):
    attention = [
        {
            "name": item["name"],
            "state": item["state"],
            "message": item["message"],
        }
        for item in report.get("checks", [])
        if item.get("state") in {"misconfigured", "unsafe"}
    ]
    degraded = [
        {
            "name": item["name"],
            "message": item["message"],
        }
        for item in report.get("checks", [])
        if item.get("state") == "degraded"
    ]
    return redact({
        "safeForAgent": True,
        "state": report.get("state"),
        "attentionRequired": attention,
        "degradedChecks": degraded,
        "limits": report.get("limits", {}),
        "promptBoundary": "Use readiness context for preflight decisions only; do not request secrets or protected data.",
    })


def prometheus_metrics(report):
    lines = [
        "# HELP cdse_readiness_state CaumeDSE readiness state rank, higher is worse.",
        "# TYPE cdse_readiness_state gauge",
        f"cdse_readiness_state{{state=\"{report.get('state', 'unknown')}\"}} {STATE_RANK.get(report.get('state'), 9)}",
        "# HELP cdse_readiness_check_state CaumeDSE individual readiness check state rank.",
        "# TYPE cdse_readiness_check_state gauge",
    ]
    for item in report.get("checks", []):
        name = re.sub(r"[^A-Za-z0-9_]", "_", item.get("name", "unknown"))
        state = item.get("state", "unknown")
        lines.append(f"cdse_readiness_check_state{{check=\"{name}\",state=\"{state}\"}} {STATE_RANK.get(state, 9)}")
    limits = report.get("limits", {})
    lines.extend([
        "# HELP cdse_readiness_limit Configured verifier/runtime limits.",
        "# TYPE cdse_readiness_limit gauge",
        f"cdse_readiness_limit{{name=\"maxConnections\"}} {int(limits.get('maxConnections') or 0)}",
        f"cdse_readiness_limit{{name=\"threadPoolSize\"}} {int(limits.get('threadPoolSize') or 0)}",
    ])
    return "\n".join(lines) + "\n"


def state_summary(report):
    counts = {state: 0 for state in STATE_RANK}
    for item in report.get("checks", []):
        state = item.get("state", "degraded")
        counts[state if state in counts else "degraded"] += 1
    return redact({
        "safeForAgent": True,
        "state": report.get("state"),
        "summary": counts,
        "limits": report.get("limits", {}),
    })


def nagios_line(report):
    state = report.get("state", "degraded")
    code = {"healthy": 0, "degraded": 1, "misconfigured": 2, "unsafe": 2}.get(state, 3)
    counts = state_summary(report)["summary"]
    text = (
        f"CDSE READINESS {state.upper()} - "
        f"healthy={counts['healthy']} degraded={counts['degraded']} "
        f"misconfigured={counts['misconfigured']} unsafe={counts['unsafe']}"
    )
    return code, text


def readiness_runbook(config_path=None):
    config_arg = f" --config {config_path}" if config_path else ""
    base = "python3 samples/operational-readiness/readiness_check.py"
    return {
        "safeForAgent": True,
        "phases": [
            {"name": "json", "command": f"{base} check{config_arg}"},
            {"name": "agentContext", "command": f"{base} context{config_arg}"},
            {"name": "prometheusMetrics", "command": f"{base} metrics{config_arg}"},
            {"name": "stateSummary", "command": f"{base} summary{config_arg}"},
            {"name": "nagios", "command": f"{base} nagios{config_arg}"},
        ],
        "baselineCompare": f"{base} compare --current readiness-current.json --baseline readiness-baseline.json",
    }


def sarif_report(report):
    results = []
    for item in report.get("checks", []):
        state = item.get("state")
        if state not in {"degraded", "misconfigured", "unsafe"}:
            continue
        level = "error" if state in {"misconfigured", "unsafe"} else "warning"
        results.append({
            "ruleId": f"cdse.readiness.{item.get('name', 'unknown')}",
            "level": level,
            "message": {"text": item.get("message", "")},
            "properties": {"state": state, "safeForAgent": True},
        })
    return redact({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "CaumeDSE readiness sample", "informationUri": "https://github.com/openmindedtw/CaumeDSE"}},
            "results": results,
        }],
    })


def remediation_report(report):
    actions = {
        "storagePath": "verify the configured storage path exists and is readable/writable by the CaumeDSE process",
        "parserTempDirectory": "create a dedicated writable parser temp directory owned by the service account",
        "parserTempDirectorySafety": "set the sticky bit or move parser temp files to a private directory",
        "storageCryptoProfile": "select an available storage crypto profile or enable the required provider",
        "herraduraBuild": "install or enable HerraduraKEx support before selecting Herradura storage profiles",
        "tlsAuth": "require TLS client authentication outside DEBUG-only verifier runs",
        "buildMode": "use a release build for production readiness",
        "parserPolicy": "enable parser policy controls before accepting generated parser scripts",
    }
    items = []
    for item in report.get("checks", []):
        state = item.get("state")
        if state == "healthy":
            continue
        name = item.get("name", "unknown")
        items.append({
            "check": name,
            "state": state,
            "priority": "high" if state in {"misconfigured", "unsafe"} else "normal",
            "message": item.get("message", ""),
            "recommendedAction": actions.get(name, "review the readiness check and update local configuration"),
        })
    return redact({
        "safeForAgent": True,
        "state": report.get("state"),
        "summary": {
            "actionItems": len(items),
            "highPriority": sum(1 for item in items if item["priority"] == "high"),
        },
        "items": items,
    })


def check_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    if args.output == "text":
        print_text(report)
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["state"] in {"healthy", "degraded"} else 2


def context_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    print(json.dumps(agent_context(report), indent=2, sort_keys=True))
    return 0 if report["state"] in {"healthy", "degraded"} else 2


def metrics_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    print(prometheus_metrics(report), end="")
    return 0 if report["state"] in {"healthy", "degraded"} else 2


def summary_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    result = state_summary(report)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if report["state"] in {"healthy", "degraded"} else 2


def nagios_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    code, text = nagios_line(report)
    print(text)
    return code


def runbook_command(args):
    print(json.dumps(readiness_runbook(args.config), indent=2, sort_keys=True))


def sarif_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    print(json.dumps(sarif_report(report), indent=2, sort_keys=True))
    return 0 if report["state"] in {"healthy", "degraded"} else 2


def remediation_command(args):
    args = apply_config_and_env(args)
    report = build_report(args)
    print(json.dumps(remediation_report(report), indent=2, sort_keys=True))
    return 0 if report["state"] in {"healthy", "degraded"} else 2


def compare_command(args):
    current = load_json(args.current)
    baseline = load_json(args.baseline)
    result = compare_reports(current, baseline)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["summary"]["regressions"] == 0 else 2


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        args = argparse.Namespace(
            storage_path=tmp,
            parser_temp_dir=tmp,
            storage_profile="hsk-en-la-aead-256",
            herradura_available=False,
            tls_auth_state="bypass",
            build_mode="debug",
            parser_policy_enabled=True,
            max_connections=16,
            thread_pool_size=4,
            output="json",
        )
        report = build_report(args)
    if report["safeForAgent"] is not True or report["state"] != "unsafe":
        raise ReadinessError("self-test expected unsafe DEBUG readiness.")
    serialized = json.dumps(redact({"route": "/x?orgKey=abc&newOrgKey=def", "privateKey": "secret"}))
    if "abc" in serialized or "secret" in serialized:
        raise ReadinessError("self-test redaction leaked secret markers.")
    bad_args = argparse.Namespace(**vars(args))
    bad_args.storage_path = "/path/that/does/not/exist"
    bad_report = build_report(bad_args)
    if bad_report["state"] not in {"misconfigured", "unsafe"}:
        raise ReadinessError("self-test missing storage path did not affect readiness.")
    comparison = compare_reports(bad_report, report)
    if comparison["summary"]["changes"] == 0:
        raise ReadinessError("self-test readiness comparison did not detect drift.")
    context = agent_context(report)
    if context["safeForAgent"] is not True or not context["attentionRequired"]:
        raise ReadinessError("self-test agent context failed.")
    metrics = prometheus_metrics(report)
    if "cdse_readiness_state" not in metrics or "privateKey" in metrics:
        raise ReadinessError("self-test metrics output failed.")
    summary = state_summary(report)
    if summary["summary"]["unsafe"] == 0:
        raise ReadinessError("self-test readiness summary failed.")
    code, line = nagios_line(report)
    if code != 2 or "UNSAFE" not in line:
        raise ReadinessError("self-test Nagios output failed.")
    rb = readiness_runbook("samples/operational-readiness/config.example.json")
    if len(rb["phases"]) != 5 or "check --config" not in rb["phases"][0]["command"]:
        raise ReadinessError("self-test runbook output failed.")
    sarif = sarif_report(report)
    if sarif["version"] != "2.1.0" or not sarif["runs"][0]["results"]:
        raise ReadinessError("self-test SARIF output failed.")
    remediation = remediation_report(report)
    if remediation["summary"]["highPriority"] == 0 or not remediation["items"]:
        raise ReadinessError("self-test remediation report failed.")
    print("PASS operational readiness self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Render safe CaumeDSE operational readiness.")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Run local readiness checks.")
    check.add_argument("--config", help="Optional JSON config; environment variables override it.")
    check.add_argument("--storage-path", default=os.getcwd())
    check.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    check.add_argument("--storage-profile", default="aes-256-cbc")
    check.add_argument("--herradura-available", action="store_true")
    check.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    check.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    check.add_argument("--parser-policy-enabled", action="store_true")
    check.add_argument("--max-connections", type=int, default=0)
    check.add_argument("--thread-pool-size", type=int, default=0)
    check.add_argument("--output", choices=["json", "text"], default="json")
    context = sub.add_parser("context", help="Render compact agent-safe readiness context.")
    context.add_argument("--config", help="Optional JSON config; environment variables override it.")
    context.add_argument("--storage-path", default=os.getcwd())
    context.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    context.add_argument("--storage-profile", default="aes-256-cbc")
    context.add_argument("--herradura-available", action="store_true")
    context.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    context.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    context.add_argument("--parser-policy-enabled", action="store_true")
    context.add_argument("--max-connections", type=int, default=0)
    context.add_argument("--thread-pool-size", type=int, default=0)
    context.set_defaults(output="json")
    metrics = sub.add_parser("metrics", help="Render Prometheus-style readiness metrics.")
    metrics.add_argument("--config", help="Optional JSON config; environment variables override it.")
    metrics.add_argument("--storage-path", default=os.getcwd())
    metrics.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    metrics.add_argument("--storage-profile", default="aes-256-cbc")
    metrics.add_argument("--herradura-available", action="store_true")
    metrics.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    metrics.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    metrics.add_argument("--parser-policy-enabled", action="store_true")
    metrics.add_argument("--max-connections", type=int, default=0)
    metrics.add_argument("--thread-pool-size", type=int, default=0)
    metrics.set_defaults(output="json")
    summary = sub.add_parser("summary", help="Render compact readiness state counts.")
    summary.add_argument("--config", help="Optional JSON config; environment variables override it.")
    summary.add_argument("--storage-path", default=os.getcwd())
    summary.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    summary.add_argument("--storage-profile", default="aes-256-cbc")
    summary.add_argument("--herradura-available", action="store_true")
    summary.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    summary.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    summary.add_argument("--parser-policy-enabled", action="store_true")
    summary.add_argument("--max-connections", type=int, default=0)
    summary.add_argument("--thread-pool-size", type=int, default=0)
    summary.set_defaults(output="json")
    nagios = sub.add_parser("nagios", help="Render a Nagios-compatible one-line readiness status.")
    nagios.add_argument("--config", help="Optional JSON config; environment variables override it.")
    nagios.add_argument("--storage-path", default=os.getcwd())
    nagios.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    nagios.add_argument("--storage-profile", default="aes-256-cbc")
    nagios.add_argument("--herradura-available", action="store_true")
    nagios.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    nagios.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    nagios.add_argument("--parser-policy-enabled", action="store_true")
    nagios.add_argument("--max-connections", type=int, default=0)
    nagios.add_argument("--thread-pool-size", type=int, default=0)
    nagios.set_defaults(output="json")
    runbook_parser = sub.add_parser("runbook", help="Render an ordered readiness monitoring runbook.")
    runbook_parser.add_argument("--config", help="Optional JSON config path to include in rendered commands.")
    sarif = sub.add_parser("sarif", help="Render SARIF readiness findings for security review tooling.")
    sarif.add_argument("--config", help="Optional JSON config; environment variables override it.")
    sarif.add_argument("--storage-path", default=os.getcwd())
    sarif.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    sarif.add_argument("--storage-profile", default="aes-256-cbc")
    sarif.add_argument("--herradura-available", action="store_true")
    sarif.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    sarif.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    sarif.add_argument("--parser-policy-enabled", action="store_true")
    sarif.add_argument("--max-connections", type=int, default=0)
    sarif.add_argument("--thread-pool-size", type=int, default=0)
    sarif.set_defaults(output="json")
    remediation = sub.add_parser("remediation", help="Render action items for degraded, misconfigured, or unsafe checks.")
    remediation.add_argument("--config", help="Optional JSON config; environment variables override it.")
    remediation.add_argument("--storage-path", default=os.getcwd())
    remediation.add_argument("--parser-temp-dir", default=tempfile.gettempdir())
    remediation.add_argument("--storage-profile", default="aes-256-cbc")
    remediation.add_argument("--herradura-available", action="store_true")
    remediation.add_argument("--tls-auth-state", choices=["required", "bypass", "unknown"], default="unknown")
    remediation.add_argument("--build-mode", choices=["release", "debug", "unknown"], default="unknown")
    remediation.add_argument("--parser-policy-enabled", action="store_true")
    remediation.add_argument("--max-connections", type=int, default=0)
    remediation.add_argument("--thread-pool-size", type=int, default=0)
    remediation.set_defaults(output="json")
    compare = sub.add_parser("compare", help="Compare two JSON readiness reports for state drift.")
    compare.add_argument("--current", required=True)
    compare.add_argument("--baseline", required=True)
    sub.add_parser("self-test", help="Run offline readiness and redaction checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "check":
            return check_command(args)
        if args.command == "context":
            return context_command(args)
        if args.command == "metrics":
            return metrics_command(args)
        if args.command == "summary":
            return summary_command(args)
        if args.command == "nagios":
            return nagios_command(args)
        if args.command == "runbook":
            runbook_command(args)
            return 0
        if args.command == "sarif":
            return sarif_command(args)
        if args.command == "remediation":
            return remediation_command(args)
        if args.command == "compare":
            return compare_command(args)
        if args.command == "self-test":
            self_test()
            return 0
    except ReadinessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
