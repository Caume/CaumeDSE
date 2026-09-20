#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT_DIR/TEST/validate_workflow_actions.sh"
FIXTURES_DIR="$ROOT_DIR/TEST/testfiles/workflow-action-validator"

failures=0

expect_pass() {
    local name="$1"
    local fixture="$2"
    local expected="$3"
    local output

    if ! output="$(CDSE_WORKFLOWS_DIR="$fixture" "$VALIDATOR" 2>&1)"; then
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
    local fixture="$2"
    local expected="$3"
    local output

    if output="$(CDSE_WORKFLOWS_DIR="$fixture" "$VALIDATOR" 2>&1)"; then
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

expect_pass "valid SHA pins, local action, and nested workflow" "$FIXTURES_DIR/valid" "3 immutable reference(s)"
expect_failure "mutable action tag" "$FIXTURES_DIR/invalid-mutable-tag" "actions/checkout@v4"
expect_failure "malformed SHA lengths" "$FIXTURES_DIR/invalid-sha-length" "actions/cache@"

if [ "$failures" -ne 0 ]; then
    printf 'Workflow action validator fixture tests failed: %d issue(s)\n' "$failures" >&2
    exit 1
fi

printf 'Workflow action validator fixture tests passed\n'
