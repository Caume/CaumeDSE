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
import shlex
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
    (re.compile(r"(?i)(orgKey|newOrgKey|sourceOrgKey|targetOrgKey|password)=([^&\s\"']+)"), r"\1=<redacted>"),
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


def build_operator_commands(plan):
    def quote_command(parts):
        rendered = []
        for part in parts:
            rendered.append(part if part.startswith("$CDSE_") else shlex.quote(part))
        return " ".join(rendered)

    commands = []
    for step in plan["steps"]:
        base = [
            "caumedse-admin",
            "reprotect-columnfile",
            "--storage", step["storage"],
            "--document-type", step["documentType"],
            "--document", step["document"],
            "--database", step["database"],
            "--target-profile", step["targetProfile"],
            "--confirmed-scope", plan["operator"]["confirmedScope"],
            "--source-key-file", "$CDSE_SOURCE_ORG_KEY_FILE",
            "--target-key-file", "$CDSE_TARGET_ORG_KEY_FILE",
        ]
        commands.append({
            "step": step["step"],
            "databaseId": step["databaseId"],
            "dryRun": quote_command(base + ["--dry-run"]),
            "commit": quote_command(base + ["--commit"]),
        })
    return {
        "safeForAgent": True,
        "journalId": plan["journalId"],
        "secretInputs": ["CDSE_SOURCE_ORG_KEY_FILE", "CDSE_TARGET_ORG_KEY_FILE"],
        "commands": commands,
    }


def load_journal(path):
    journal = load_json(path)
    if not isinstance(journal, dict) or journal.get("safeForAgent") is not True:
        raise ReprotectError("journal must be a safeForAgent plan generated by this sample.")
    steps = journal.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ReprotectError("journal must contain at least one step.")
    return journal


def summarize_journal(journal):
    states = {"pending": 0, "readyToResume": 0, "complete": 0, "blocked": 0}
    next_step = None
    for step in journal["steps"]:
        state = step.get("state", "pending")
        if state not in states:
            state = "blocked"
        states[state] += 1
        if next_step is None and state in {"pending", "readyToResume"}:
            next_step = {
                "step": step["step"],
                "databaseId": step["databaseId"],
                "database": step["database"],
                "state": state,
                "nextAction": step.get("nextAction", step["actions"][0]),
            }
    readiness = "complete" if states["complete"] == len(journal["steps"]) else "readyToResume"
    if states["blocked"]:
        readiness = "blocked"
    return {
        "safeForAgent": True,
        "journalId": journal["journalId"],
        "readiness": readiness,
        "summary": states,
        "nextStep": next_step,
    }


def final_report(journal):
    summary = summarize_journal(journal)
    incomplete = [
        {
            "step": step["step"],
            "databaseId": step["databaseId"],
            "database": step["database"],
            "state": step.get("state", "pending"),
        }
        for step in journal["steps"]
        if step.get("state", "pending") != "complete"
    ]
    return {
        "safeForAgent": True,
        "journalId": journal["journalId"],
        "complete": not incomplete,
        "readiness": summary["readiness"],
        "summary": {
            "databases": len(journal["steps"]),
            "dataRows": sum(step.get("dataRows", 0) for step in journal["steps"]),
            "metaRows": sum(step.get("metaRows", 0) for step in journal["steps"]),
            "protectedValueRows": sum(step.get("protectedValueRows", 0) for step in journal["steps"]),
        },
        "incompleteSteps": incomplete,
        "operatorCloseout": [
            "confirm target-key readback for every complete step",
            "archive the final redacted journal with backup metadata",
            "destroy old key material only after external recovery checks pass",
        ],
    }


def gate_journal(journal):
    report = final_report(journal)
    blocked = [step for step in report["incompleteSteps"] if step["state"] == "blocked"]
    pending = [step for step in report["incompleteSteps"] if step["state"] != "blocked"]
    report["gate"] = {
        "passed": report["complete"],
        "blockedSteps": len(blocked),
        "pendingSteps": len(pending),
    }
    return report


def audit_events(journal):
    events = []
    for step in journal["steps"]:
        state = step.get("state", "pending")
        events.append({
            "auditSchemaVersion": 1,
            "safeForAgent": True,
            "category": "reprotect",
            "event": "columnfile-step",
            "outcome": "allow" if state == "complete" else "pending",
            "journalId": journal["journalId"],
            "step": step["step"],
            "databaseId": step["databaseId"],
            "storage": step["storage"],
            "documentType": step["documentType"],
            "document": step["document"],
            "state": state,
            "sourceProfile": step.get("sourceProfile"),
            "targetProfile": step.get("targetProfile"),
            "protectedValueRows": step.get("protectedValueRows", 0),
        })
    closeout = final_report(journal)
    events.append({
        "auditSchemaVersion": 1,
        "safeForAgent": True,
        "category": "reprotect",
        "event": "journal-closeout",
        "outcome": "allow" if closeout["complete"] else "deny",
        "journalId": journal["journalId"],
        "complete": closeout["complete"],
        "incompleteSteps": len(closeout["incompleteSteps"]),
        "protectedValueRows": closeout["summary"]["protectedValueRows"],
    })
    return {"safeForAgent": True, "journalId": journal["journalId"], "events": events}


def checkpoint_manifest(journal):
    checkpoints = []
    for step in journal["steps"]:
        for phase in ("preMutation", "postTransaction", "postReadback"):
            checkpoints.append({
                "checkpointId": stable_id(journal["journalId"], step["databaseId"], phase),
                "databaseId": step["databaseId"],
                "step": step["step"],
                "phase": phase,
                "required": True,
                "pathVisibleToAgent": False,
            })
    return {
        "safeForAgent": True,
        "journalId": journal["journalId"],
        "checkpointCount": len(checkpoints),
        "checkpoints": checkpoints,
    }


def runbook(plan):
    commands = build_operator_commands(plan)["commands"]
    steps = []
    for step, command in zip(plan["steps"], commands):
        steps.append({
            "step": step["step"],
            "databaseId": step["databaseId"],
            "database": step["database"],
            "phases": [
                {"name": "preMutationCheckpoint", "action": "create checkpoint outside model-visible storage"},
                {"name": "dryRun", "command": command["dryRun"]},
                {"name": "commit", "command": command["commit"]},
                {
                    "name": "markComplete",
                    "command": (
                        "python3 samples/reprotect-workflow/reprotect_workflow.py journal-update "
                        f"--journal rotation-journal.json --step {step['step']} --state complete "
                        "--out rotation-journal.json"
                    ),
                },
            ],
        })
    return {
        "safeForAgent": True,
        "journalId": plan["journalId"],
        "humanApprovalRequired": True,
        "secretInputs": ["CDSE_SOURCE_ORG_KEY_FILE", "CDSE_TARGET_ORG_KEY_FILE"],
        "steps": steps,
        "finalGate": "python3 samples/reprotect-workflow/reprotect_workflow.py gate --journal rotation-journal.json",
    }


def step_key(step):
    return "\x1f".join([
        step.get("storage", ""),
        step.get("documentType", ""),
        step.get("document", ""),
        step.get("database", ""),
    ])


def scope_diff(current_scope, baseline_scope):
    current = build_plan(current_scope, dry_run=True)
    baseline = build_plan(baseline_scope, dry_run=True)
    current_steps = {step_key(step): step for step in current["steps"]}
    baseline_steps = {step_key(step): step for step in baseline["steps"]}
    added = sorted(set(current_steps) - set(baseline_steps))
    removed = sorted(set(baseline_steps) - set(current_steps))
    changed = []
    for key in sorted(set(current_steps) & set(baseline_steps)):
        current_step = current_steps[key]
        baseline_step = baseline_steps[key]
        fields = {}
        for field in ("sourceProfile", "targetProfile", "dataRows", "metaRows", "protectedValueRows"):
            if current_step.get(field) != baseline_step.get(field):
                fields[field] = {"baseline": baseline_step.get(field), "current": current_step.get(field)}
        if fields:
            changed.append({
                "databaseId": current_step["databaseId"],
                "database": current_step["database"],
                "changes": fields,
            })
    return {
        "safeForAgent": True,
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "addedDatabases": [current_steps[key]["database"] for key in added],
        "removedDatabases": [baseline_steps[key]["database"] for key in removed],
        "changedDatabases": changed,
    }


def action_items(journal):
    items = []
    for step in journal["steps"]:
        state = step.get("state", "pending")
        if state == "complete":
            continue
        priority = "high" if state == "blocked" else "normal"
        items.append({
            "step": step["step"],
            "databaseId": step["databaseId"],
            "database": step["database"],
            "state": state,
            "priority": priority,
            "nextAction": step.get("nextAction", step["actions"][0]),
            "requiresHumanApproval": state == "blocked",
        })
    return redact({
        "safeForAgent": True,
        "journalId": journal["journalId"],
        "summary": {
            "actionItems": len(items),
            "blocked": sum(1 for item in items if item["state"] == "blocked"),
        },
        "items": items,
    })


def update_journal(journal, step_number=None, database_id=None, state=None, next_action=None):
    if state not in {"pending", "readyToResume", "complete", "blocked"}:
        raise ReprotectError("state must be pending, readyToResume, complete, or blocked.")
    matched = False
    for step in journal["steps"]:
        if (step_number is not None and step.get("step") == step_number) or \
           (database_id is not None and step.get("databaseId") == database_id):
            step["state"] = state
            if next_action:
                step["nextAction"] = next_action
            step["updatedAt"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            matched = True
            break
    if not matched:
        raise ReprotectError("no journal step matched the requested selector.")
    journal["updatedAt"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return journal


def plan_command(args):
    result = build_plan(load_json(args.scope), dry_run=args.dry_run)
    if args.include_commands:
        result["operatorCommands"] = build_operator_commands(result)
    result = redact(result)
    print(json.dumps(result, indent=2, sort_keys=True))


def journal_command(args):
    result = redact(summarize_journal(load_journal(args.journal)))
    print(json.dumps(result, indent=2, sort_keys=True))


def journal_update_command(args):
    if args.step is None and not args.database_id:
        raise ReprotectError("journal-update requires --step or --database-id.")
    result = redact(update_journal(load_journal(args.journal), args.step, args.database_id, args.state, args.next_action))
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))


def final_report_command(args):
    result = redact(final_report(load_journal(args.journal)))
    print(json.dumps(result, indent=2, sort_keys=True))


def gate_command(args):
    result = redact(gate_journal(load_journal(args.journal)))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["gate"]["passed"] else 2


def audit_events_command(args):
    result = redact(audit_events(load_journal(args.journal)))
    print(json.dumps(result, indent=2, sort_keys=True))


def checkpoint_manifest_command(args):
    result = redact(checkpoint_manifest(load_journal(args.journal)))
    print(json.dumps(result, indent=2, sort_keys=True))


def runbook_command(args):
    result = redact(runbook(build_plan(load_json(args.scope), dry_run=True)))
    print(json.dumps(result, indent=2, sort_keys=True))


def scope_diff_command(args):
    result = redact(scope_diff(load_json(args.current), load_json(args.baseline)))
    print(json.dumps(result, indent=2, sort_keys=True))


def action_items_command(args):
    result = action_items(load_journal(args.journal))
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
    staged = dict(plan)
    staged["steps"] = [dict(plan["steps"][0], state="complete"), dict(plan["steps"][1], state="readyToResume")]
    summary = summarize_journal(staged)
    if summary["readiness"] != "readyToResume" or summary["nextStep"]["step"] != 2:
        raise ReprotectError("self-test journal resume summary failed.")
    commands = redact(build_operator_commands(plan))
    serialized_commands = json.dumps(commands)
    if "CDSE_SOURCE_ORG_KEY_FILE" not in serialized_commands or "orgKey" in serialized_commands:
        raise ReprotectError("self-test operator command rendering failed.")
    updated = update_journal(staged, step_number=2, state="blocked", next_action="restore pre-mutation checkpoint")
    updated_summary = summarize_journal(updated)
    if updated_summary["readiness"] != "blocked" or updated_summary["summary"]["blocked"] != 1:
        raise ReprotectError("self-test journal state update failed.")
    complete = dict(plan)
    complete["steps"] = [dict(step, state="complete") for step in complete["steps"]]
    closeout = final_report(complete)
    if closeout["complete"] is not True or closeout["summary"]["protectedValueRows"] != 20:
        raise ReprotectError("self-test final report failed.")
    gate = gate_journal(staged)
    if gate["gate"]["passed"] is True or gate["gate"]["blockedSteps"] != 1:
        raise ReprotectError("self-test journal gate failed.")
    audit = audit_events(complete)
    if len(audit["events"]) != 3 or audit["events"][-1]["complete"] is not True:
        raise ReprotectError("self-test audit event rendering failed.")
    manifest = checkpoint_manifest(complete)
    if manifest["checkpointCount"] != 6 or manifest["checkpoints"][0]["pathVisibleToAgent"] is not False:
        raise ReprotectError("self-test checkpoint manifest failed.")
    rb = runbook(plan)
    if rb["humanApprovalRequired"] is not True or len(rb["steps"]) != 2:
        raise ReprotectError("self-test runbook rendering failed.")
    changed_scope = dict(load_json(DEFAULT_SCOPE))
    changed_scope["databases"] = [dict(item) for item in changed_scope["databases"]]
    changed_scope["databases"][0]["protectedValueRows"] += 1
    diff = scope_diff(changed_scope, load_json(DEFAULT_SCOPE))
    if diff["summary"]["changed"] != 1:
        raise ReprotectError("self-test scope diff failed.")
    actions = action_items(updated)
    if actions["summary"]["actionItems"] != 1 or actions["items"][0]["priority"] != "high":
        raise ReprotectError("self-test action items failed.")
    print("PASS re-protect workflow self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Render a CaumeDSE key/profile re-protect workflow plan.")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="Validate scope and render a redacted journal/checkpoint plan.")
    plan.add_argument("--scope", default=str(DEFAULT_SCOPE))
    plan.add_argument("--dry-run", action="store_true", default=True)
    plan.add_argument("--include-commands", action="store_true", help="Include secret-free operator command templates.")
    journal = sub.add_parser("journal-status", help="Summarize a saved plan or journal for resumable operation.")
    journal.add_argument("--journal", required=True)
    journal_update = sub.add_parser("journal-update", help="Update one saved journal step state.")
    journal_update.add_argument("--journal", required=True)
    journal_update.add_argument("--step", type=int)
    journal_update.add_argument("--database-id")
    journal_update.add_argument("--state", required=True, choices=["pending", "readyToResume", "complete", "blocked"])
    journal_update.add_argument("--next-action")
    journal_update.add_argument("--out", help="Write updated journal to this path instead of stdout.")
    final = sub.add_parser("final-report", help="Render a closeout report for a completed re-protect journal.")
    final.add_argument("--journal", required=True)
    gate = sub.add_parser("gate", help="Return non-zero until every journal step is complete.")
    gate.add_argument("--journal", required=True)
    audit = sub.add_parser("audit-events", help="Render redacted JSON audit events for a re-protect journal.")
    audit.add_argument("--journal", required=True)
    checkpoints = sub.add_parser("checkpoint-manifest", help="Render required checkpoint IDs without exposing paths.")
    checkpoints.add_argument("--journal", required=True)
    runbook_parser = sub.add_parser("runbook", help="Render an ordered secret-free re-protect operator runbook.")
    runbook_parser.add_argument("--scope", default=str(DEFAULT_SCOPE))
    scope_diff_parser = sub.add_parser("scope-diff", help="Compare two re-protect scope files before migration.")
    scope_diff_parser.add_argument("--current", required=True)
    scope_diff_parser.add_argument("--baseline", required=True)
    action_parser = sub.add_parser("action-items", help="Render operator action items for incomplete journal steps.")
    action_parser.add_argument("--journal", required=True)
    sub.add_parser("self-test", help="Run offline plan, redaction, and fail-closed checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "plan":
            plan_command(args)
        elif args.command == "journal-status":
            journal_command(args)
        elif args.command == "journal-update":
            journal_update_command(args)
        elif args.command == "final-report":
            final_report_command(args)
        elif args.command == "gate":
            return gate_command(args)
        elif args.command == "audit-events":
            audit_events_command(args)
        elif args.command == "checkpoint-manifest":
            checkpoint_manifest_command(args)
        elif args.command == "runbook":
            runbook_command(args)
        elif args.command == "scope-diff":
            scope_diff_command(args)
        elif args.command == "action-items":
            action_items_command(args)
        elif args.command == "self-test":
            self_test()
    except ReprotectError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
