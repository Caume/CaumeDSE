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
    (re.compile(r"(?i)(orgKey|newOrgKey|accessPassword|oauthConsumerSecret|password)=([^&\s\"]+)"), r"\1=<redacted>"),
]
HERRADURA_PROFILES = {"hsk-en-la-aead-256", "HERRADURAKEX_HSK_EN_LA_AEAD_256"}
AES_PROFILES = {"aes-256-cbc", "CME_OPENSSL_AES256_CBC"}
STATE_RANK = {"healthy": 0, "degraded": 1, "misconfigured": 2, "unsafe": 3}


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


def check_command(args):
    report = build_report(args)
    if args.output == "text":
        print_text(report)
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["state"] in {"healthy", "degraded"} else 2


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
    print("PASS operational readiness self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Render safe CaumeDSE operational readiness.")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="Run local readiness checks.")
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
    sub.add_parser("self-test", help="Run offline readiness and redaction checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "check":
            return check_command(args)
        if args.command == "self-test":
            self_test()
            return 0
    except ReadinessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
