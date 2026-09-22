#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT_DIR/TEST/validate_version_bump.sh"
FIXTURES_DIR="$ROOT_DIR/TEST/testfiles/version-bump"
BASE="$FIXTURES_DIR/base-1.0.11.configure.ac"

failures=0

expect_pass() {
    local name="$1"
    local labels="$2"
    local current="$3"
    local expected="$4"
    local output

    if ! output="$(CDSE_VERSION_LABELS="$labels" CDSE_VERSION_BASE_CONFIGURE="$BASE" CDSE_VERSION_CURRENT_CONFIGURE="$current" "$VALIDATOR" 2>&1)"; then
        printf 'FAIL %s unexpectedly failed:\n%s\n' "$name" "$output" >&2
        failures=$((failures + 1))
        return
    fi
    if [[ "$output" != *"$expected"* ]]; then
        printf 'FAIL %s did not report %s:\n%s\n' "$name" "$expected" "$output" >&2
        failures=$((failures + 1))
        return
    fi
    printf 'PASS %s\n' "$name"
}

expect_failure() {
    local name="$1"
    local labels="$2"
    local current="$3"
    local expected="$4"
    local output

    if output="$(CDSE_VERSION_LABELS="$labels" CDSE_VERSION_BASE_CONFIGURE="$BASE" CDSE_VERSION_CURRENT_CONFIGURE="$current" "$VALIDATOR" 2>&1)"; then
        printf 'FAIL %s unexpectedly passed:\n%s\n' "$name" "$output" >&2
        failures=$((failures + 1))
        return
    fi
    if [[ "$output" != *"$expected"* ]]; then
        printf 'FAIL %s did not report %s:\n%s\n' "$name" "$expected" "$output" >&2
        failures=$((failures + 1))
        return
    fi
    printf 'PASS %s\n' "$name"
}

expect_pass "patch increment" "version:patch" "$FIXTURES_DIR/current-1.0.12.configure.ac" "1.0.11 -> 1.0.12 (patch)"
expect_pass "minor increment" "version:minor" "$FIXTURES_DIR/current-1.1.0.configure.ac" "1.0.11 -> 1.1.0 (minor)"
expect_pass "major increment" "version:major" "$FIXTURES_DIR/current-2.0.0.configure.ac" "1.0.11 -> 2.0.0 (major)"
expect_failure "skipped patch increment" "version:patch" "$FIXTURES_DIR/current-1.0.13.configure.ac" "requires 1.0.12"
expect_failure "minor reset violation" "version:minor" "$FIXTURES_DIR/current-1.1.1.configure.ac" "requires 1.1.0"
expect_failure "malformed version" "version:patch" "$FIXTURES_DIR/current-malformed.configure.ac" "must use a MAJOR.MINOR.PATCH version"
expect_failure "missing impact label" "" "$FIXTURES_DIR/current-1.0.12.configure.ac" "add exactly one"
expect_failure "duplicate impact labels" "version:patch,version:minor" "$FIXTURES_DIR/current-1.0.12.configure.ac" "exactly one version impact label"

if [ "$failures" -ne 0 ]; then
    printf 'Version bump validator fixture tests failed: %d issue(s)\n' "$failures" >&2
    exit 1
fi

printf 'Version bump validator fixture tests passed\n'
