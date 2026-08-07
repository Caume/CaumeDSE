#!/usr/bin/env python3
"""
CaumeDSE backup/restore manifest utility sample.

Builds a portable encrypted backup package for a CaumeDSE data directory,
verifies manifest/file consistency, and restores payloads without exposing
secrets on command lines or in model-visible logs.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent
MANIFEST_SCHEMA_VERSION = 1
BACKUP_PACKAGE_VERSION = 1
PBKDF2_ITERATIONS = 250000
MAC_KEY_LABEL = b"CaumeDSE backup package MAC v1"
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


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def redact_text(value):
    text = str(value)
    text = SENSITIVE_NAME_RE.sub("<redacted>", text)
    text = HEXISH_RE.sub("<redacted-hex>", text)
    return text


def read_backup_key(key_env=None, key_file=None):
    if key_env and key_file:
        raise BackupError("Use either --key-env or --key-file, not both.")
    if key_file:
        try:
            key = Path(key_file).read_bytes().strip()
        except OSError as exc:
            raise BackupError(f"Cannot read backup key file: {exc}") from exc
    else:
        env_name = key_env or "CDSE_BACKUP_KEY"
        key_value = os.environ.get(env_name)
        if not key_value:
            raise BackupError(f"Backup key is required in ${env_name} or via --key-file.")
        key = key_value.encode("utf-8")
    if len(key) < 16:
        raise BackupError("Backup key must be at least 16 bytes.")
    return key


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


def load_manifest_from_path(path):
    return load_json(path)


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


def ensure_manifest_compatible(manifest, expected_profile=None):
    if not isinstance(manifest, dict) or manifest.get("manifestSchemaVersion") != MANIFEST_SCHEMA_VERSION:
        raise BackupError("Unsupported or invalid manifest schema.")
    profile = manifest.get("storageCrypto", {}).get("profile")
    if expected_profile and profile != expected_profile:
        raise BackupError(f"Backup profile {profile!r} does not match expected profile {expected_profile!r}.")
    return profile


def restore_plan(manifest, target_dir, overwrite=False):
    ensure_manifest_compatible(manifest)
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


def safe_destination(root, rel_path):
    rel = Path(rel_path)
    if rel.is_absolute() or ".." in rel.parts:
        raise BackupError(f"Unsafe manifest path: {rel_path}")
    destination = root / rel
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise BackupError(f"Unsafe restore path: {rel_path}") from exc
    return destination


def write_tar_payload(source_dir, manifest, output_path):
    source = Path(source_dir)
    with tarfile.open(output_path, "w") as archive:
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest_bytes)
        manifest_info.mode = 0o600
        manifest_info.mtime = 0
        archive.addfile(manifest_info, fileobj=BytesReader(manifest_bytes))
        for entry in manifest["files"]:
            rel = entry["path"]
            archive.add(source / rel, arcname=f"data/{rel}", recursive=False)


class BytesReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.data) - self.offset
        chunk = self.data[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


def run_openssl_enc(input_bytes, key_bytes, decrypt=False):
    openssl = shutil.which("openssl")
    if not openssl:
        raise BackupError("openssl CLI is required for encrypted backup packages.")
    read_fd, write_fd = os.pipe()
    mode = "-d" if decrypt else "-e"
    cmd = [
        openssl,
        "enc",
        "-aes-256-cbc",
        mode,
        "-pbkdf2",
        "-iter",
        str(PBKDF2_ITERATIONS),
        "-salt",
        "-pass",
        f"fd:{read_fd}",
    ]
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(read_fd,),
        )
        os.close(read_fd)
        with os.fdopen(write_fd, "wb") as handle:
            handle.write(key_bytes)
            handle.write(b"\n")
        output, stderr = process.communicate(input_bytes)
    finally:
        for fd in (read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass
    if process.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["openssl failed"]
        raise BackupError(redact_text(detail[0]))
    return output


def derive_mac_key(key_bytes, salt):
    return hashlib.pbkdf2_hmac("sha256", key_bytes + MAC_KEY_LABEL, salt, PBKDF2_ITERATIONS, dklen=32)


def package_hmac(key_bytes, salt, ciphertext):
    mac_key = derive_mac_key(key_bytes, salt)
    return hmac.new(mac_key, ciphertext, hashlib.sha256).hexdigest()


def create_backup_package(source_dir, output_path, key_bytes, label=None, profile="mixed-existing"):
    manifest = build_manifest(source_dir, label=label, profile=profile)
    with tempfile.TemporaryDirectory(prefix="cdse-backup-package-") as tmp:
        tar_path = Path(tmp) / "payload.tar"
        write_tar_payload(source_dir, manifest, tar_path)
        tar_bytes = tar_path.read_bytes()
    ciphertext = run_openssl_enc(tar_bytes, key_bytes)
    mac_salt = os.urandom(16)
    package = {
        "backupPackageVersion": BACKUP_PACKAGE_VERSION,
        "safeForAgent": True,
        "createdAt": manifest["createdAt"],
        "manifest": manifest,
        "payload": {
            "cipher": "openssl-enc-aes-256-cbc-pbkdf2",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "hash": "SHA-256",
            "ciphertextSha256": sha256_bytes(ciphertext),
            "hmacSaltB64": base64.b64encode(mac_salt).decode("ascii"),
            "hmacSha256": package_hmac(key_bytes, mac_salt, ciphertext),
            "ciphertextB64": base64.b64encode(ciphertext).decode("ascii"),
        },
    }
    write_json(package, output_path)
    return package


def load_backup_package(path):
    package = load_json(path)
    if not isinstance(package, dict) or package.get("backupPackageVersion") != BACKUP_PACKAGE_VERSION:
        raise BackupError("Unsupported or invalid backup package.")
    ensure_manifest_compatible(package.get("manifest"))
    payload = package.get("payload", {})
    for field in ("ciphertextB64", "hmacSaltB64", "hmacSha256"):
        if not payload.get(field):
            raise BackupError(f"Backup package payload is missing {field}.")
    return package


def decrypt_backup_payload(package, key_bytes):
    payload = package["payload"]
    try:
        ciphertext = base64.b64decode(payload["ciphertextB64"], validate=True)
        mac_salt = base64.b64decode(payload["hmacSaltB64"], validate=True)
    except ValueError as exc:
        raise BackupError("Backup package payload is not valid base64.") from exc
    if sha256_bytes(ciphertext) != payload.get("ciphertextSha256"):
        raise BackupError("Backup package ciphertext hash mismatch.")
    expected = package_hmac(key_bytes, mac_salt, ciphertext)
    if not hmac.compare_digest(expected, payload.get("hmacSha256", "")):
        raise BackupError("Backup package authentication failed.")
    return run_openssl_enc(ciphertext, key_bytes, decrypt=True)


def extract_tar_payload(tar_bytes, target_dir):
    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)
    tar_path = target / "payload.tar"
    tar_path.write_bytes(tar_bytes)
    try:
        with tarfile.open(tar_path, "r") as archive:
            for member in archive.getmembers():
                if member.name.startswith("/") or ".." in Path(member.name).parts:
                    raise BackupError(f"Unsafe archive member: {member.name}")
            archive.extractall(target)
    finally:
        try:
            tar_path.unlink()
        except OSError:
            pass


def restore_backup_package(package_path, target_dir, key_bytes, overwrite=False, dry_run=False, expected_profile=None):
    package = load_backup_package(package_path)
    manifest = package["manifest"]
    ensure_manifest_compatible(manifest, expected_profile=expected_profile)
    plan = restore_plan(manifest, target_dir, overwrite=overwrite)
    target = Path(target_dir)
    for entry in manifest["files"]:
        destination = safe_destination(target, entry["path"])
        if destination.exists() and not overwrite:
            raise BackupError(f"Restore target already exists: {redact_text(destination)}")
    if dry_run:
        return {"safeForAgent": True, "dryRun": True, "plan": plan}
    with tempfile.TemporaryDirectory(prefix="cdse-restore-payload-") as tmp:
        tmp_root = Path(tmp)
        extract_tar_payload(decrypt_backup_payload(package, key_bytes), tmp_root)
        extracted_manifest = load_manifest_from_path(tmp_root / "manifest.json")
        if json.dumps(extracted_manifest, sort_keys=True) != json.dumps(manifest, sort_keys=True):
            raise BackupError("Embedded manifest does not match backup package manifest.")
        extracted_data = tmp_root / "data"
        report = verify_manifest(manifest, extracted_data)
        if report["summary"]["failed"]:
            raise BackupError("Decrypted payload failed manifest verification.")
        for entry in manifest["files"]:
            destination = safe_destination(target, entry["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(extracted_data / entry["path"], destination)
    post_restore = verify_manifest(manifest, target)
    if post_restore["summary"]["failed"]:
        raise BackupError("Restored files failed manifest verification.")
    return {
        "safeForAgent": True,
        "dryRun": False,
        "summary": post_restore["summary"],
        "plan": plan,
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


def create_backup_command(args):
    key = read_backup_key(args.key_env, args.key_file)
    package = create_backup_package(args.source, args.output, key, label=args.label, profile=args.profile)
    summary = {
        "safeForAgent": True,
        "output": redact_text(args.output),
        "fileCount": package["manifest"]["summary"]["fileCount"],
        "totalBytes": package["manifest"]["summary"]["totalBytes"],
        "profile": package["manifest"]["storageCrypto"]["profile"],
        "ciphertextSha256": package["payload"]["ciphertextSha256"],
    }
    write_json(summary, args.summary_output)


def restore_command(args):
    key = read_backup_key(args.key_env, args.key_file)
    report = restore_backup_package(
        args.backup,
        args.target,
        key,
        overwrite=args.overwrite,
        dry_run=args.dry_run,
        expected_profile=args.expected_profile,
    )
    write_json(report, args.output)


def verify_backup_command(args):
    key = read_backup_key(args.key_env, args.key_file)
    package = load_backup_package(args.backup)
    decrypt_backup_payload(package, key)
    report = {
        "safeForAgent": True,
        "summary": {
            "fileCount": package["manifest"]["summary"]["fileCount"],
            "totalBytes": package["manifest"]["summary"]["totalBytes"],
            "authenticated": True,
        },
        "profile": package["manifest"]["storageCrypto"]["profile"],
        "ciphertextSha256": package["payload"]["ciphertextSha256"],
    }
    write_json(report, args.output)


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
        backup_path = Path(tmp) / "backup.cdsebackup.json"
        key = b"correct horse battery staple"
        create_backup_package(root, backup_path, key, label="OrgKeyABCDEF1234567890abcdef", profile="mixed-aes-herradura")
        package_text = backup_path.read_text(encoding="utf-8")
        if "ABCDEF1234567890abcdef" in package_text:
            raise BackupError("self-test backup package leaked an identifier-like value.")
        try:
            restore_backup_package(backup_path, Path(tmp) / "wrong-key-restore", b"wrong backup passphrase")
        except BackupError as exc:
            if "authentication failed" not in str(exc):
                raise
        else:
            raise BackupError("self-test did not reject wrong backup key.")
        restored = Path(tmp) / "restore"
        restore_report = restore_backup_package(backup_path, restored, key, expected_profile="mixed-aes-herradura")
        if restore_report["summary"]["failed"] != 0:
            raise BackupError("self-test restore verification failed.")
        if (restored / "storage" / "document.csv").read_text(encoding="utf-8") != "name,salary\nAda,999\n":
            raise BackupError("self-test restore readback mismatch.")
        package = load_backup_package(backup_path)
        package["payload"]["ciphertextB64"] = package["payload"]["ciphertextB64"][:-4] + "AAAA"
        tampered_path = Path(tmp) / "tampered.cdsebackup.json"
        write_json(package, tampered_path)
        try:
            restore_backup_package(tampered_path, Path(tmp) / "tampered-restore", key)
        except BackupError as exc:
            if "hash mismatch" not in str(exc) and "authentication failed" not in str(exc):
                raise
        else:
            raise BackupError("self-test did not reject tampered backup package.")
    print("PASS encrypted backup restore self-test")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Create, verify, and restore CaumeDSE backup packages.")
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
    create = sub.add_parser("create-backup", help="Create an encrypted backup package.")
    create.add_argument("--source", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--label")
    create.add_argument("--profile", default="mixed-existing")
    create.add_argument("--key-env", default="CDSE_BACKUP_KEY")
    create.add_argument("--key-file")
    create.add_argument("--summary-output")
    verify_backup = sub.add_parser("verify-backup", help="Authenticate and inspect an encrypted backup package.")
    verify_backup.add_argument("--backup", required=True)
    verify_backup.add_argument("--key-env", default="CDSE_BACKUP_KEY")
    verify_backup.add_argument("--key-file")
    verify_backup.add_argument("--output")
    restore = sub.add_parser("restore", help="Restore an encrypted backup package.")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--target", required=True)
    restore.add_argument("--key-env", default="CDSE_BACKUP_KEY")
    restore.add_argument("--key-file")
    restore.add_argument("--expected-profile")
    restore.add_argument("--overwrite", action="store_true")
    restore.add_argument("--dry-run", action="store_true")
    restore.add_argument("--output")
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
        elif args.command == "create-backup":
            create_backup_command(args)
        elif args.command == "verify-backup":
            return verify_backup_command(args)
        elif args.command == "restore":
            restore_command(args)
        elif args.command == "self-test":
            self_test()
    except BackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
