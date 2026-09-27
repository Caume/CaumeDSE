#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="$ROOT_DIR/TEST/validate_openapi_operations.sh"
FIXTURES_DIR="$ROOT_DIR/TEST/testfiles/openapi-operation-validator"
failures=0

expect_pass() {
    local name="$1"
    local spec="$2"
    local contract="$3"
    local output

    if ! output="$("$VALIDATOR" "$spec" "$contract" 2>&1)"; then
        printf 'FAIL %s unexpectedly failed:\n%s\n' "$name" "$output" >&2
        failures=$((failures + 1))
        return
    fi
    if [[ "$output" != *"3 operation(s)"* ]]; then
        printf 'FAIL %s did not report 3 operation(s):\n%s\n' "$name" "$output" >&2
        failures=$((failures + 1))
        return
    fi
    printf 'PASS %s\n' "$name"
}

expect_failure() {
    local name="$1"
    local spec="$2"
    local contract="$3"
    local expected="$4"
    local output

    if output="$("$VALIDATOR" "$spec" "$contract" 2>&1)"; then
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

expect_pass "direct and anchored operations" "$FIXTURES_DIR/valid.yaml" "$FIXTURES_DIR/valid.contract"
expect_failure "missing required method" "$FIXTURES_DIR/missing-method.yaml" "$FIXTURES_DIR/missing-method.contract" "post /direct"

if [ "$failures" -ne 0 ]; then
    printf 'OpenAPI operation validator fixture tests failed: %d issue(s)\n' "$failures" >&2
    exit 1
fi

printf 'OpenAPI operation validator fixture tests passed\n'
