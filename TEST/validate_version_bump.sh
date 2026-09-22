#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_REF="${CDSE_VERSION_BASE_REF:-}"
LABELS="${CDSE_VERSION_LABELS:-}"

fail() {
    printf 'FAIL version bump validation: %s\n' "$1" >&2
    exit 1
}

version_from_configure() {
    sed -n 's/^AC_INIT(\[CaumeDSE\], \[\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)\].*/\1/p'
}

if [ -z "$BASE_REF" ]; then
    fail "CDSE_VERSION_BASE_REF is required"
fi

impact=""
IFS=',' read -r -a labels <<< "$LABELS"
for label in "${labels[@]}"; do
    case "$label" in
        version:major|version:minor|version:patch)
            if [ -n "$impact" ]; then
                fail "exactly one version impact label is required"
            fi
            impact="${label#version:}"
            ;;
    esac
done

if [ -z "$impact" ]; then
    fail "add exactly one of version:major, version:minor, or version:patch"
fi

base_version="$(git show "$BASE_REF:configure.ac" 2>/dev/null | version_from_configure)"
current_version="$(version_from_configure < "$ROOT_DIR/configure.ac")"

if [[ ! "$base_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "could not read a MAJOR.MINOR.PATCH version from $BASE_REF:configure.ac"
fi
if [[ ! "$current_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    fail "configure.ac must use a MAJOR.MINOR.PATCH version"
fi

IFS='.' read -r base_major base_minor base_patch <<< "$base_version"
case "$impact" in
    major)
        expected_version="$((base_major + 1)).0.0"
        ;;
    minor)
        expected_version="$base_major.$((base_minor + 1)).0"
        ;;
    patch)
        expected_version="$base_major.$base_minor.$((base_patch + 1))"
        ;;
esac

if [ "$current_version" != "$expected_version" ]; then
    fail "version:$impact requires $expected_version from base $base_version, found $current_version"
fi

printf 'Version bump validation passed: %s -> %s (%s)\n' \
    "$base_version" "$current_version" "$impact"
