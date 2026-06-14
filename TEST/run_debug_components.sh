#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CDSE_VERIFY_PREFIX:-/tmp/cdse-verify}"
LOG_ROOT="${CDSE_VERIFY_LOG_DIR:-/tmp/cdse-debug-components-$(date +%Y%m%d-%H%M%S)}"
HTTP_PORT="${CDSE_DEBUG_TEST_HTTP_PORT:-18080}"
HTTPS_PORT="${CDSE_DEBUG_TEST_HTTPS_PORT:-18443}"
RUN_TIMEOUT="${CDSE_DEBUG_TEST_TIMEOUT:-30s}"
SKIP_BUILD=0
SKIP_WEB=0

PASSED=0
FAILED=0
SKIPPED=0
SUMMARY_FILE=""

usage() {
    printf 'Usage: %s [--skip-build] [--skip-web]\n' "$0"
    printf '\n'
    printf 'Environment:\n'
    printf '  CDSE_VERIFY_PREFIX         install prefix, default /tmp/cdse-verify\n'
    printf '  CDSE_VERIFY_LOG_DIR        log directory, default /tmp/cdse-debug-components-<timestamp>\n'
    printf '  CDSE_DEBUG_TEST_HTTP_PORT  HTTP test port, default 18080\n'
    printf '  CDSE_DEBUG_TEST_HTTPS_PORT HTTPS test port, default 18443\n'
    printf '  CDSE_DEBUG_TEST_TIMEOUT    executable timeout, default 30s\n'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=1
            ;;
        --skip-web)
            SKIP_WEB=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

mkdir -p "$LOG_ROOT"
SUMMARY_FILE="$LOG_ROOT/summary.txt"
: > "$SUMMARY_FILE"

note() {
    printf '%s\n' "$*" | tee -a "$SUMMARY_FILE"
}

record_pass() {
    PASSED=$((PASSED + 1))
    note "PASS $1"
}

record_fail() {
    FAILED=$((FAILED + 1))
    note "FAIL $1 - $2"
}

record_skip() {
    SKIPPED=$((SKIPPED + 1))
    note "SKIP $1 - $2"
}

run_step() {
    local name="$1"
    shift
    local log="$LOG_ROOT/${name}.log"

    note "RUN  $name"
    (
        cd "$ROOT_DIR" || exit 1
        "$@"
    ) > "$log" 2>&1
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        record_pass "$name"
    else
        record_fail "$name" "exit=$rc log=$log"
    fi
    return "$rc"
}

port_in_use() {
    local port="$1"
    if ! command -v ss >/dev/null 2>&1; then
        return 1
    fi
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

check_required() {
    local log="$1"
    local marker="$2"
    grep -Fq -- "$marker" "$log"
}

check_forbidden() {
    local log="$1"
    if [ "$SKIP_WEB" -eq 1 ]; then
        grep -E 'CaumeDSE Error|FAILED|FAIL:|Segmentation fault|Assertion .*failed|assertion .*failed|core dumped|timeout: the monitored command dumped core' "$log" \
            | grep -Ev 'cmeWebServiceSetup\(\).*can.t start (HTTP|HTTPS) server on port 0' >/dev/null
        return $?
    fi
    grep -Eq 'CaumeDSE Error|FAILED|FAIL:|Segmentation fault|Assertion .*failed|assertion .*failed|core dumped|timeout: the monitored command dumped core' "$log"
}

extract_component_log() {
    local out="$1"
    local pattern="$2"
    local source="$3"
    grep -nE -- "$pattern" "$source" > "$out" 2>/dev/null || true
}

check_component() {
    local name="$1"
    local extract_pattern="$2"
    local source="$3"
    shift 3
    local log="$LOG_ROOT/${name}.log"
    local marker
    local missing=0

    extract_component_log "$log" "$extract_pattern" "$source"

    for marker in "$@"; do
        if ! check_required "$source" "$marker"; then
            record_fail "$name" "missing marker: $marker log=$log"
            missing=1
            break
        fi
    done
    if [ "$missing" -eq 0 ]; then
        record_pass "$name"
    fi
}

note "CaumeDSE DEBUG component verification"
note "root=$ROOT_DIR"
note "prefix=$PREFIX"
note "logs=$LOG_ROOT"
note "http_port=$HTTP_PORT https_port=$HTTPS_PORT timeout=$RUN_TIMEOUT"

if [ "$SKIP_BUILD" -eq 0 ]; then
    run_step configure ./configure --prefix="$PREFIX" --enable-DEBUG --enable-TESTDATABASE || exit 1
    run_step make make || exit 1
    run_step make_check make check || exit 1
    run_step make_install make install || exit 1
else
    record_skip configure "requested --skip-build"
    record_skip make "requested --skip-build"
    record_skip make_check "requested --skip-build"
    record_skip make_install "requested --skip-build"
fi

if [ "$SKIP_WEB" -eq 0 ]; then
    if port_in_use "$HTTP_PORT"; then
        record_fail webservice_ports "HTTP port $HTTP_PORT is already in use"
        exit 1
    fi
    if port_in_use "$HTTPS_PORT"; then
        record_fail webservice_ports "HTTPS port $HTTPS_PORT is already in use"
        exit 1
    fi
else
    record_skip webservice_ports "requested --skip-web"
fi

FULL_LOG="$LOG_ROOT/full-debug-run.log"
note "RUN  debug_engine"
(
    cd "$ROOT_DIR" || exit 1
    if [ "$SKIP_WEB" -eq 0 ]; then
        env CDSE_DEBUG_TESTS_NONINTERACTIVE=1 \
            CDSE_DEBUG_TEST_HTTP_PORT="$HTTP_PORT" \
            CDSE_DEBUG_TEST_HTTPS_PORT="$HTTPS_PORT" \
            timeout "$RUN_TIMEOUT" "$PREFIX/cdse/bin/CaumeDSE-debug-tests"
    else
        env CDSE_DEBUG_TESTS_NONINTERACTIVE=1 \
            CDSE_DEBUG_TEST_HTTP_PORT=0 \
            CDSE_DEBUG_TEST_HTTPS_PORT=0 \
            timeout "$RUN_TIMEOUT" "$PREFIX/cdse/bin/CaumeDSE-debug-tests"
    fi
) > "$FULL_LOG" 2>&1
ENGINE_RC=$?

if [ "$ENGINE_RC" -eq 0 ]; then
    record_pass debug_engine
else
    record_fail debug_engine "exit=$ENGINE_RC log=$FULL_LOG"
fi

if check_forbidden "$FULL_LOG"; then
    record_fail forbidden_markers "found forbidden marker in $FULL_LOG"
else
    record_pass forbidden_markers
fi

check_component locale_printf 'locale .*printf|MB_CUR_MAX' "$FULL_LOG" \
    "supports multibyte printf output"

check_component crypto_gcm_direct 'GCM ciphertext size|GCM B64|GCM decrypted text' "$FULL_LOG" \
    'GCM decrypted text: This is cleartext for GCM.'

check_component crypto_gcm_bytestring 'testCryptoSymmetricGCM_ByteString|cipher mode|PBKDF' "$FULL_LOG" \
    'TESTS: testCryptoSymmetricGCM_ByteString(), PASS: plaintext matches.'

check_component crypto_streaming '---ctSize|---etSize|Decrypted text|Unprotected text' "$FULL_LOG" \
    'Unprotected text: This is cleartext This is cleartext This is cleartext This is cleartext.'

check_component digest 'HASH parameters|HASH digest Size|HASH digest with integrated function|StrToB64|B64ToStr' "$FULL_LOG" \
    '--- HASH digest Size (bytes): 32' \
    '--- HASH digest Size (chars) with integrated function: 64'

check_component hmac_pbkdf 'HMAC parameters|HMAC MAC Size|HMAC MAC with integrated function|cmeHMAC' "$FULL_LOG" \
    '--- HMAC MAC Size (bytes): 32' \
    '--- HMAC MAC Size (chars) with integrated function: 64'

check_component perl_interpreter 'PERL sub|perl function result|cmePerlParser' "$FULL_LOG" \
    'perl function result 1:' \
    'PERL sub cmePERLProcessColumnNames, result array:'

check_component engine_admin_db 'cmeSetupEngineAdminDBs|ResourcesDB|RolesDB|LogsDB' "$FULL_LOG" \
    'ResourcesDB' \
    'RolesDB' \
    'LogsDB'

check_component role_tables_resource 'Testing roleTables resource handlers|testRoleTables|roleTables resource' "$FULL_LOG" \
    '--- Testing roleTables resource handlers:' \
    'TESTS: testRoleTables(), PASS: roleTables resource POST responseCode=201' \
    'TESTS: testRoleTables(), PASS: roleTables permission reject responseCode=403' \
    'roleTables permission allow responseCode=200' \
    'TESTS: testRoleTables(), PASS: create/read/update/head/delete/options verified.'

check_component filter_whitelist_resource 'Testing filterWhitelist resource handlers|testFilterWhitelist|filterWhitelist resource' "$FULL_LOG" \
    '--- Testing filterWhitelist resource handlers:' \
    'TESTS: testFilterWhitelist(), PASS: filterWhitelist resource POST responseCode=201' \
    'TESTS: testFilterWhitelist(), PASS: allowlisted permission responseCode=200' \
    'TESTS: testFilterWhitelist(), PASS: missing whitelist reject responseCode=403' \
    'TESTS: testFilterWhitelist(), PASS: create/read/update/head/delete/options and enforcement verified.'

check_component filter_blacklist_resource 'Testing filterBlacklist resource handlers|testFilterBlacklist|filterBlacklist resource' "$FULL_LOG" \
    '--- Testing filterBlacklist resource handlers:' \
    'TESTS: testFilterBlacklist(), PASS: filterBlacklist resource POST responseCode=201' \
    'TESTS: testFilterBlacklist(), PASS: blacklist conflict reject responseCode=403' \
    'TESTS: testFilterBlacklist(), PASS: whitelist allow after blacklist delete responseCode=200' \
    'TESTS: testFilterBlacklist(), PASS: create/read/update/head/delete/options and deny precedence verified.'

check_component document_types_resource 'Testing documentTypes resource handlers|testDocumentTypes|documentTypes' "$FULL_LOG" \
    '--- Testing documentTypes resource handlers:' \
    'TESTS: testDocumentTypes(), PASS: documentTypes class GET responseCode=200' \
    'TESTS: testDocumentTypes(), PASS: documentTypes file.csv GET responseCode=200' \
    'TESTS: testDocumentTypes(), PASS: documentTypes unsupported GET responseCode=404' \
    'TESTS: testDocumentTypes(), PASS: class listing and resource validation verified.'

check_component parser_scripts_resource 'Testing parserScripts resource handlers|testParserScripts|parserScripts' "$FULL_LOG" \
    '--- Testing parserScripts resource handlers:' \
    'TESTS: testParserScripts(), PASS: parserScripts class OPTIONS responseCode=200' \
    'TESTS: testParserScripts(), PASS: parserScripts resource OPTIONS responseCode=200' \
    'TESTS: testParserScripts(), PASS: parserScripts missing script HEAD responseCode=404' \
    'TESTS: testParserScripts(), PASS: class options and missing script handling verified.'

check_component content_rows_resource 'Testing contentRows resource handlers|testContentRows|contentRows' "$FULL_LOG" \
    '--- Testing contentRows resource handlers:' \
    'TESTS: testContentRows(), PASS: contentRows class OPTIONS responseCode=200' \
    'TESTS: testContentRows(), PASS: contentRows row GET responseCode=200' \
    'TESTS: testContentRows(), PASS: contentRows append POST responseCode=201' \
    'TESTS: testContentRows(), PASS: contentRows appended DELETE responseCode=200' \
    'TESTS: testContentRows(), PASS: row get/append/update/delete/options verified.'

check_component content_columns_resource 'Testing contentColumns resource handlers|testContentColumns|contentColumns' "$FULL_LOG" \
    '--- Testing contentColumns resource handlers:' \
    'TESTS: testContentColumns(), PASS: contentColumns class OPTIONS responseCode=200' \
    'TESTS: testContentColumns(), PASS: contentColumns existing column GET responseCode=200' \
    'TESTS: testContentColumns(), PASS: contentColumns empty document POST responseCode=201' \
    'TESTS: testContentColumns(), PASS: contentColumns last column DELETE responseCode=200' \
    'TESTS: testContentColumns(), PASS: column get/create/delete/options and edge cases verified.'

check_component db_browsing_resource 'Testing dbNames secure DB browsing resource handlers|testDBBrowsing|dbNames|dbTables|tableRows|tableColumns' "$FULL_LOG" \
    '--- Testing dbNames secure DB browsing resource handlers:' \
    'TESTS: testDBBrowsing(), PASS: dbNames class GET responseCode=200' \
    'TESTS: testDBBrowsing(), PASS: dbTables class GET responseCode=200' \
    'TESTS: testDBBrowsing(), PASS: tableRow resource GET responseCode=200' \
    'TESTS: testDBBrowsing(), PASS: dbNames/dbTables/tableRows/tableColumns browsing verified.'

check_component sqlite_thread_safety 'Testing thread safety|Thread safety test|test_thread_' "$FULL_LOG" \
    '--- Thread safety test: PASSED'

check_component csv_securedb_roundtrip 'CSV file to secure DB|AcmeIncPayroll.csv|Retrieved data from secure table|Omar|Pablo' "$FULL_LOG" \
    '--- Retrieved data from secure table (CSV file to secure DB):' \
    '[10][10][Pablo][Martinez][14000.5]'

check_component memtable_securedb_roundtrip 'Memory Table to secure DB|AcmeIncPayroll Tests.csv|Retrieved data from secure table' "$FULL_LOG" \
    '--- Retrieved data from secure table (Memory Table to secure DB):' \
    '[10][10][Pablo][Martinez][14000.5]'

check_component mac_macprotected 'MAC and MACProtected|MACProtected test|verified MACProtected|Retrieved data from secure table' "$FULL_LOG" \
    '--- Testing MAC and MACProtected column attributes:' \
    "--- Retrieved data from secure table (MAC+MACProtected test):" \
    "verified MACProtected for 'value' in row id 10."

if [ "$SKIP_WEB" -eq 0 ]; then
    check_component webservice_startup 'Testing Web server|cmeLoadStrFromFile|server.key|server.pem|ca.pem' "$FULL_LOG" \
        "--- Testing Web server HTTP port $HTTP_PORT" \
        "--- Testing Web server HTTPS port $HTTPS_PORT" \
        "read 306 bytes from file $PREFIX/cdse/server.key" \
        "read 1119 bytes from file $PREFIX/cdse/server.pem" \
        "read 1054 bytes from file $PREFIX/cdse/ca.pem"
else
    record_skip webservice_startup "requested --skip-web"
fi

note "RESULT passed=$PASSED failed=$FAILED skipped=$SKIPPED"
note "summary=$SUMMARY_FILE"
note "full_log=$FULL_LOG"

if [ "$FAILED" -eq 0 ]; then
    exit 0
fi
exit 1
