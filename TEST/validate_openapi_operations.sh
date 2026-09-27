#!/usr/bin/env bash
set -u

SPEC="${1:-}"
CONTRACT="${2:-}"
failures=0
operations=0

if [ ! -f "$SPEC" ]; then
    printf 'FAIL missing OpenAPI specification: %s\n' "$SPEC" >&2
    exit 1
fi
if [ ! -f "$CONTRACT" ]; then
    printf 'FAIL missing OpenAPI operation contract: %s\n' "$CONTRACT" >&2
    exit 1
fi

require_operation() {
    local path="$1"
    local method="$2"

    if ! awk -v path="  $path:" -v method="$method" '
        $0 == path {
            in_path = 1
            next
        }
        in_path && /^  \// {
            exit
        }
        in_path && index($0, "    " method ":") == 1 {
            found = 1
            exit
        }
        END {
            exit !found
        }
    ' "$SPEC"; then
        printf 'FAIL OpenAPI operation missing from %s: %s %s\n' \
            "$SPEC" "$method" "$path" >&2
        failures=$((failures + 1))
    fi
}

while IFS= read -r entry || [ -n "$entry" ]; do
    case "$entry" in
        ''|'#'*)
            continue
            ;;
    esac

    read -r path methods <<< "$entry"
    if [ -z "$path" ] || [ -z "$methods" ]; then
        printf 'FAIL malformed OpenAPI operation contract entry: %s\n' "$entry" >&2
        failures=$((failures + 1))
        continue
    fi

    for method in $methods; do
        require_operation "$path" "$method"
        operations=$((operations + 1))
    done
done < "$CONTRACT"

if [ "$operations" -eq 0 ]; then
    printf 'FAIL OpenAPI operation contract has no operations: %s\n' "$CONTRACT" >&2
    exit 1
fi
if [ "$failures" -ne 0 ]; then
    printf 'OpenAPI operation validation failed: %d issue(s)\n' "$failures" >&2
    exit 1
fi

printf 'OpenAPI operation validation passed: %d operation(s)\n' "$operations"
