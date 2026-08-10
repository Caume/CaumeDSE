#!/usr/bin/env python3
"""
CaumeDSE explicit re-protect workflow planner sample.

Builds a redacted operator plan and resumable journal skeleton for key/profile
rotation of selected ColumnFile databases. It does not accept or print key
material; the actual mutation remains inside CaumeDSE's protected DB helpers.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent
DEFAULT_SCOPE = SAMPLE_DIR / "scope.example.json"
SUPPORTED_PROFILES = {
    "aes-256-cbc",
    "CME_OPENSSL_AES256_CBC",
    "hsk-en-la-aead-256",
    "HERRADURAKEX_HSK_EN_LA_AEAD_256",
}
SENSITIVE_KEYS = {"orgKey", "newOrgKey", "sourceOrgKey", "targetOrgKey", "key", "secret", "password"}
SECRET_PATTERNS = [
    (re.compile(r"(?i)(orgKey|newOrgKey|sourceOrgKey|targetOrgKey|password)=([^&\s\"]+)"), r"\1=<redacted>"),
]


class ReprotectError(Exception):
    pass


def load_json(path):
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise ReprotectError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReprotectError(f"Invalid JSON in {path}: {exc}") from exc


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


def require_string(container, field, context):
    value = container.get(field)
    if not isinstance(value, str) or not value:
        raise ReprotectError(f"{context} must define non-empty string field: {field}")
    return value


def require_int(container, field, context):
    value = container.get(field)
    if not isinstance(value, int) or value < 0:
        raise ReprotectError(f"{context} must define non-negative integer field: {field}")
    return value


def validate_scope(scope):
    if not isinstance(scope, dict):
        raise ReprotectError("scope must be a JSON object.")
    if scope.get("reprotectSchemaVersion") != 1:
        raise ReprotectError("reprotectSchemaVersion must be 1.")
    operator = scope.get("operator")
    if not isinstance(operator, dict):
        raise ReprotectError("scope must define operator object.")
    require_string(operator, "organization", "operator")
    require_string(operator, "confirmedScope", "operator")
    target_profile = require_string(scope, "targetProfile", "scope")
    if target_profile not in SUPPORTED_PROFILES:
        raise ReprotectError(f"targetProfile is not supported by this sample: {target_profile}")
    databases = scope.get("databases")
    if not isinstance(databases, list) or not databases:
        raise ReprotectError("scope must define at least one database.")
    names = set()
    for index, item in enumerate(databases):
        context = f"databases[{index}]"
        if not isinstance(item, dict):
            raise ReprotectError(f"{context} must be an object.")
        name = require_string(item, "name", context)
        if name in names:
            raise ReprotectError(f"duplicate database name: {name}")
        names.add(name)
        require_string(item, "storage", context)
        require_string(item, "document", context)
        require_string(item, "documentType", context)
        require_string(item, "sourceProfile", context)
        require_int(item, "dataRows", context)
        require_int(item, "metaRows", context)
        require_int(item, "protectedValueRows", context)
        if item.get("hasMacOrSignature") is True:
            raise ReprotectError(f"{context} has MAC/sign metadata; use the dedicated recomputation workflow first.")
    return scope


def stable_id(*parts):
    digest = hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return digest[:16]


def build_plan(scope, dry_run=True):
    scope = validate_scope(scope)
    target_profile = scope["targetProfile"]
    journal_id = stable_id(scope["operator"]["organization"], scope["operator"]["confirmedScope"], target_profile)
    steps = []
    for index, item in enumerate(scope["databases"], start=1):
        db_id = stable_id(journal_id, item["storage"], item["documentType"], item["document"], item["name"])
        steps.append({
            "step": index,
            "databaseId": db_id,
            "storage": item["storage"],
            "documentType": item["documentType"],
            "document": item["document"],
            "database": item["name"],
            "sourceProfile": item["sourceProfile"],
            "targetProfile": target_profile,
            "dataRows": item["dataRows"],
            "metaRows": item["metaRows"],
            "protectedValueRows": item["protectedValueRows"],
            "legacyAESValueRows": item.get("legacyAESValueRows", 0),
            "herraduraValueRows": item.get("herraduraValueRows", 0),
            "actions": [
                "write pre-mutation checkpoint",
                "run cmeInventoryMemSecureDBReprotect dry-run",
                "run cmeReprotectMemSecureDB mutation only after operator confirmation",
                "write post-transaction checkpoint",
                "verify readback with target key/profile",
                "mark journal step complete",
            ],
        })
    return {
        "safeForAgent": True,
        "dryRun": bool(dry_run),
        "journalId": journal_id,
        "createdAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "operator": scope["operator"],
        "targetProfile": target_profile,
        "summary": {
            "databases": len(steps),
            "dataRows": sum(item["dataRows"] for item in scope["databases"]),
            "metaRows": sum(item["metaRows"] for item in scope["databases"]),
            "protectedValueRows": sum(item["protectedValueRows"] for item in scope["databases"]),
        },
        "steps": steps,
        "rollback": {
            "beforeCommit": "restore the pre-mutation checkpoint for the failed database",
            "afterCommitBeforeReadback": "restore the post-transaction or pre-mutation checkpoint after operator review",
            "afterReadbackFailure": "restore the pre-mutation checkpoint and keep the journal open",
        },
    }


def plan_command(args):
    result = redact(build_plan(load_json(args.scope), dry_run=args.dry_run))
    print(json.dumps(result, indent=2, sort_keys=True))


def self_test():
    plan = redact(build_plan(load_json(DEFAULT_SCOPE), dry_run=True))
    if plan.get("safeForAgent") is not True or plan["summary"]["databases"] != 2:
        raise ReprotectError("self-test plan summary failed.")
    if plan["steps"][0]["legacyAESValueRows"] == 0 or plan["steps"][1]["herraduraValueRows"] == 0:
        raise ReprotectError("self-test did not preserve mixed AES/Herradura inventory.")
    leaked = json.dumps(redact({"route": "/x?orgKey=abc&newOrgKey=def", "sourceOrgKey": "old"}))
    if "abc" in leaked or "old" in leaked:
        raise ReprotectError("self-test redaction leaked key material.")
    invalid = dict(load_json(DEFAULT_SCOPE))
    invalid["databases"] = [dict(invalid["databases"][0], hasMacOrSignature=True)]
    try:
        build_plan(invalid)
    except ReprotectError:
        pass
    else:
        raise ReprotectError("self-test accepted MAC/sign metadata scope.")
    print("PASS re-protect workflow self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Render a CaumeDSE key/profile re-protect workflow plan.")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="Validate scope and render a redacted journal/checkpoint plan.")
    plan.add_argument("--scope", default=str(DEFAULT_SCOPE))
    plan.add_argument("--dry-run", action="store_true", default=True)
    sub.add_parser("self-test", help="Run offline plan, redaction, and fail-closed checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "plan":
            plan_command(args)
        elif args.command == "self-test":
            self_test()
    except ReprotectError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
