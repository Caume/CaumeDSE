#!/usr/bin/env python3
"""
CaumeDSE backup/restore manifest utility sample.

Builds a portable integrity manifest for a CaumeDSE data directory, verifies
manifest/file consistency, and renders restore plans without exposing secrets.
Uses only Python's standard library; encryption wrapping is intentionally a
separate follow-up around this manifest contract.
"""

import argparse
import hashlib
import json
import re
import sys
import tempfile
import time
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent
MANIFEST_SCHEMA_VERSION = 1
SENSITIVE_NAME_RE = re.compile(r"(?i)(orgKey|newOrgKey|accessPassword|oauthConsumerSecret|privateKey|secret)")
HEXISH_RE = re.compile(r"\b[A-Fa-f0-9]{16,}\b")


class BackupError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact_text(value):
    text = str(value)
    text = SENSITIVE_NAME_RE.sub("<redacted>", text)
    text = HEXISH_RE.sub("<redacted-hex>", text)
    return text


def relative_files(root):
    root = Path(root)
    if not root.is_dir():
        raise BackupError(f"Source directory does not exist: {root}")
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith("."):
            continue
        files.append((rel, path))
    return files


def classify_file(rel_path):
    name = Path(rel_path).name
    if name == "ResourcesDB":
        return "resourcesDB"
    if name == "RolesDB":
        return "rolesDB"
    if name == "LogsDB":
        return "logsDB"
    if name.endswith(".sqlite") or name.endswith(".db") or "column" in name.lower():
        return "columnFileOrSQLite"
    return "storageFile"


def build_manifest(source_dir, label=None, profile="mixed-existing"):
    source = Path(source_dir).resolve()
    entries = []
    total_size = 0
    for rel, path in relative_files(source):
        size = path.stat().st_size
        total_size += size
        entries.append({
            "path": rel,
            "redactedPath": redact_text(rel),
            "size": size,
            "sha256": sha256_file(path),
            "kind": classify_file(rel),
        })
    manifest = {
        "manifestSchemaVersion": MANIFEST_SCHEMA_VERSION,
        "safeForAgent": True,
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": {
            "label": redact_text(label or source.name),
            "rootName": redact_text(source.name),
        },
        "storageCrypto": {
            "profile": profile,
            "note": "Manifest preserves existing protected AES/Herradura data without rewriting values.",
        },
        "summary": {
            "fileCount": len(entries),
            "totalBytes": total_size,
        },
        "files": entries,
    }
    return manifest


def verify_manifest(manifest, source_dir):
    if not isinstance(manifest, dict) or manifest.get("manifestSchemaVersion") != MANIFEST_SCHEMA_VERSION:
        raise BackupError("Unsupported or invalid manifest schema.")
    source = Path(source_dir)
    results = []
    for entry in manifest.get("files", []):
        rel = entry.get("path")
        if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts:
            raise BackupError(f"Unsafe manifest path: {rel}")
        path = source / rel
        if not path.is_file():
            results.append({"path": redact_text(rel), "status": "missing", "passed": False})
            continue
        size = path.stat().st_size
        digest = sha256_file(path)
        passed = size == entry.get("size") and digest == entry.get("sha256")
        results.append({
            "path": redact_text(rel),
            "status": "ok" if passed else "mismatch",
            "passed": passed,
            "expectedSize": entry.get("size"),
            "actualSize": size,
        })
    passed_count = sum(1 for item in results if item["passed"])
    return {
        "safeForAgent": True,
        "summary": {
            "passed": passed_count,
            "failed": len(results) - passed_count,
        },
        "results": results,
    }


def restore_plan(manifest, target_dir, overwrite=False):
    target = Path(target_dir)
    planned = []
    for entry in manifest.get("files", []):
        rel = entry["path"]
        destination = target / rel
        planned.append({
            "path": redact_text(rel),
            "destination": redact_text(destination),
            "size": entry["size"],
            "action": "overwrite" if overwrite and destination.exists() else "create",
        })
    return {
        "safeForAgent": True,
        "target": redact_text(target),
        "overwrite": overwrite,
        "plannedFiles": planned,
    }


def load_json(path):
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise BackupError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BackupError(f"Invalid JSON in {path}: {exc}") from exc


def write_json(data, path=None):
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if path:
        Path(path).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def manifest_command(args):
    manifest = build_manifest(args.source, args.label, args.profile)
    write_json(manifest, args.output)


def verify_command(args):
    report = verify_manifest(load_json(args.manifest), args.source)
    write_json(report, args.output)
    return 0 if report["summary"]["failed"] == 0 else 1


def plan_restore_command(args):
    plan = restore_plan(load_json(args.manifest), args.target, args.overwrite)
    write_json(plan, args.output)


def self_test():
    with tempfile.TemporaryDirectory(prefix="cdse-backup-self-test-") as tmp:
        root = Path(tmp) / "source"
        root.mkdir()
        (root / "ResourcesDB").write_text("resources fixture\n", encoding="utf-8")
        (root / "column-0001.db").write_bytes(b"column data")
        nested = root / "storage"
        nested.mkdir()
        (nested / "document.csv").write_text("name,salary\nAda,10\n", encoding="utf-8")
        manifest = build_manifest(root, label="OrgKeyABCDEF1234567890abcdef", profile="mixed-aes-herradura")
        if manifest["summary"]["fileCount"] != 3:
            raise BackupError("self-test manifest file count mismatch.")
        if "ABCDEF1234567890abcdef" in json.dumps(manifest):
            raise BackupError("self-test manifest leaked an identifier-like value.")
        ok = verify_manifest(manifest, root)
        if ok["summary"]["failed"] != 0:
            raise BackupError("self-test verification failed for unchanged source.")
        (nested / "document.csv").write_text("name,salary\nAda,999\n", encoding="utf-8")
        tampered = verify_manifest(manifest, root)
        if tampered["summary"]["failed"] != 1:
            raise BackupError("self-test did not detect tampered file.")
        plan = restore_plan(manifest, Path(tmp) / "restore")
        if len(plan["plannedFiles"]) != 3 or plan["safeForAgent"] is not True:
            raise BackupError("self-test restore plan mismatch.")
    print("PASS encrypted backup restore self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Create and verify CaumeDSE backup manifests.")
    sub = parser.add_subparsers(dest="command", required=True)
    manifest = sub.add_parser("manifest", help="Create an integrity manifest for a data directory.")
    manifest.add_argument("--source", required=True)
    manifest.add_argument("--label")
    manifest.add_argument("--profile", default="mixed-existing")
    manifest.add_argument("--output")
    verify = sub.add_parser("verify", help="Verify a manifest against a data directory.")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--source", required=True)
    verify.add_argument("--output")
    plan = sub.add_parser("plan-restore", help="Render a safe restore plan without writing files.")
    plan.add_argument("--manifest", required=True)
    plan.add_argument("--target", required=True)
    plan.add_argument("--overwrite", action="store_true")
    plan.add_argument("--output")
    sub.add_parser("self-test", help="Run offline manifest, tamper, and restore-plan checks.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.command == "manifest":
            manifest_command(args)
        elif args.command == "verify":
            return verify_command(args)
        elif args.command == "plan-restore":
            plan_restore_command(args)
        elif args.command == "self-test":
            self_test()
    except BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
