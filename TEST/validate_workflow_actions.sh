#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOWS_DIR="${CDSE_WORKFLOWS_DIR:-$ROOT_DIR/.github/workflows}"

failures=0
references=0

if [ ! -d "$WORKFLOWS_DIR" ]; then
    printf 'FAIL missing workflow directory: %s\n' "$WORKFLOWS_DIR" >&2
    exit 1
fi

while IFS= read -r -d '' workflow; do
    line_number=0
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [[ ! "$line" =~ ^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.+)$ ]]; then
            continue
        fi

        reference="${BASH_REMATCH[2]}"
        reference="${reference%%[[:space:]]*}"
        references=$((references + 1))

        # Local composite actions are versioned with this repository.
        if [[ "$reference" == ./* ]]; then
            continue
        fi

        if [[ ! "$reference" =~ ^[^[:space:]@]+@[[:xdigit:]]{40}$ ]]; then
            printf 'FAIL %s:%d uses a non-immutable action reference: %s\n' \
                "$workflow" "$line_number" "$reference" >&2
            failures=$((failures + 1))
        fi
    done < "$workflow"
done < <(find "$WORKFLOWS_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)

if [ "$failures" -ne 0 ]; then
    printf 'Workflow action validation failed: %d issue(s) across %d reference(s)\n' \
        "$failures" "$references" >&2
    exit 1
fi

printf 'Workflow action validation passed: %d immutable reference(s)\n' "$references"
