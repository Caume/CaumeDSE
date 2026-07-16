#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="$ROOT_DIR/openapi.yaml"
README="$ROOT_DIR/README.md"
EXAMPLES="$ROOT_DIR/API_EXAMPLES.md"
VERIFIER="$ROOT_DIR/TEST/run_debug_components.sh"

failures=0

require_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        printf 'FAIL missing file: %s\n' "$file" >&2
        failures=$((failures + 1))
    fi
}

require_pattern() {
    local file="$1"
    local pattern="$2"
    local label="$3"
    if ! grep -Fq "$pattern" "$file"; then
        printf 'FAIL %s missing pattern in %s: %s\n' "$label" "$file" "$pattern" >&2
        failures=$((failures + 1))
    fi
}

require_file "$SPEC"
require_file "$README"
require_file "$EXAMPLES"
require_file "$VERIFIER"

if [ "$failures" -ne 0 ]; then
    exit 1
fi

require_pattern "$SPEC" "openapi: 3.0.3" "openapi version"
require_pattern "$README" "openapi.yaml" "README OpenAPI link"
require_pattern "$EXAMPLES" "openapi.yaml" "API examples OpenAPI link"
require_pattern "$VERIFIER" "validate_openapi_routes.sh" "verifier OpenAPI validation"

required_paths=(
    "/organizations:"
    "/organizations/{organization}:"
    "/organizations/{organization}/users/{user}:"
    "/organizations/{organization}/users/{user}/roleTables/{roleTable}:"
    "/organizations/{organization}/users/{user}/filterWhitelist/{filterUser}:"
    "/organizations/{organization}/users/{user}/filterBlacklist/{filterUser}:"
    "/organizations/{organization}/storage/{storage}:"
    "/organizations/{organization}/storage/{storage}/documentTypes:"
    "/organizations/{organization}/storage/{storage}/documentTypes/{documentType}:"
    "/organizations/{organization}/storage/{storage}/documentTypes/{documentType}/documents:"
    "/organizations/{organization}/storage/{storage}/documentTypes/{documentType}/documents/{document}:"
    "/organizations/{organization}/storage/{storage}/documentTypes/{documentType}/documents/{document}/content:"
    "/organizations/{organization}/storage/{storage}/documentTypes/file.csv/documents/{document}/contentRows/{contentRow}:"
    "/organizations/{organization}/storage/{storage}/documentTypes/file.csv/documents/{document}/contentColumns/{contentColumn}:"
    "/organizations/{organization}/storage/{storage}/documentTypes/file.csv/documents/{document}/parserScripts/{parserScript}:"
    "/organizations/{organization}/storage/{storage}/dbNames:"
    "/organizations/{organization}/storage/{storage}/dbNames/{dbName}/dbTables:"
    "/organizations/{organization}/storage/{storage}/dbNames/{dbName}/dbTables/{dbTable}/tableRows/{tableRow}:"
    "/organizations/{organization}/storage/{storage}/dbNames/{dbName}/dbTables/{dbTable}/tableColumns/{tableColumn}:"
)

for path in "${required_paths[@]}"; do
    require_pattern "$SPEC" "$path" "OpenAPI path"
done

live_markers=(
    "create_org"
    "create_storage"
    "create_user"
    "document_types_get"
    "role_table_post"
    "filter_whitelist_post"
    "filter_blacklist_post"
    "upload_csv"
    "content_get"
    "row_get"
    "column_get"
    "db_names_get"
    "db_tables_get"
    "table_row_get"
    "table_column_get"
    "parser_get"
    "python_parser_get"
)

for marker in "${live_markers[@]}"; do
    require_pattern "$VERIFIER" "$marker" "live verifier marker"
done

if [ "$failures" -ne 0 ]; then
    printf 'OpenAPI route validation failed: %d issue(s)\n' "$failures" >&2
    exit 1
fi

printf 'OpenAPI route validation passed: %s\n' "$SPEC"
