#!/usr/bin/env python3
"""Inspect persisted test storage for Herradura frames and plaintext canaries."""

import argparse
import base64
import sqlite3
import string
from contextlib import closing
from pathlib import Path

MAGIC = b"CDSEHKX1"
SQLITE_MAGIC = b"SQLite format 3\0"
CANARIES = {"Jacob", "Nieves", "82400"}


def frame_profile(value: str) -> int | None:
    compact = "".join(value.split())
    candidates = [compact]
    if len(compact) > 64 and all(c in string.hexdigits for c in compact[:64]):
        candidates.append(compact[64:])
    for candidate in candidates:
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except ValueError:
            continue
        if len(decoded) >= 74 and decoded.startswith(MAGIC):
            return decoded[8]
    return None


def inspect_storage(engine: Path, storage: Path) -> tuple[int, dict[int, int], list[str]]:
    # Installed executables and input fixtures are not persisted storage artifacts.
    storage_paths = set(p for p in storage.rglob("*") if p.is_file())
    paths = set(storage_paths)
    for path in engine.iterdir():
        if path.is_file():
            with path.open("rb") as stream:
                if stream.read(16) == SQLITE_MAGIC:
                    paths.add(path)
    profiles: dict[int, int] = {}
    failures: list[str] = []
    sqlite_count = 0
    storage_has_nla1 = False

    def inspect_value(value: str, location: str, in_storage: bool) -> None:
        nonlocal storage_has_nla1
        clear_canary = value in CANARIES or any(
            value[prefix:] in CANARIES and all(c in string.hexdigits for c in value[:prefix])
            for prefix in (32, 64, 96)
        )
        if clear_canary:
            failures.append(f"plaintext canary: {location}")
        profile = frame_profile(value)
        if profile is not None:
            profiles[profile] = profiles.get(profile, 0) + 1
            storage_has_nla1 = storage_has_nla1 or (in_storage and profile == 1)

    for path in sorted(paths):
        raw = path.read_bytes()
        if not raw.startswith(SQLITE_MAGIC):
            if path.parent == engine:
                continue
            if any(token in raw for token in (b"Jacob,Nieves", b",82400,")):
                failures.append(f"plaintext CSV canary: {path}")
            try:
                inspect_value(raw.decode("ascii"), str(path), path in storage_paths)
            except UnicodeDecodeError:
                pass
            continue
        sqlite_count += 1
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                quoted_table = '"' + table.replace('"', '""') + '"'
                for row in db.execute(f"SELECT * FROM {quoted_table}"):
                    for value in row:
                        if isinstance(value, str):
                            inspect_value(value, f"{path}:{table}", path in storage_paths)
    if not storage_has_nla1:
        failures.append("missing HSKE-NL-A1 frames in target storage")
    return sqlite_count, profiles, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--storage-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not args.engine_dir.is_dir() or not args.storage_dir.is_dir():
            raise ValueError("engine and storage directories must exist")
        count, profiles, failures = inspect_storage(args.engine_dir, args.storage_dir)
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"FAIL {error}")
        return 1
    print(f"sqlite_files={count}")
    print(f"herradura_frames={sum(profiles.values())}")
    print("profile_ids=" + ",".join(str(profile) for profile in sorted(profiles)))
    for failure in failures:
        print(f"FAIL {failure}")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
