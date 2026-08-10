#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CDSE_VERIFY_PREFIX:-/tmp/cdse-verify}"
LOG_ROOT="${CDSE_VERIFY_LOG_DIR:-/tmp/cdse-debug-components-$(date +%Y%m%d-%H%M%S)}"
HTTP_PORT="${CDSE_DEBUG_TEST_HTTP_PORT:-18080}"
HTTPS_PORT="${CDSE_DEBUG_TEST_HTTPS_PORT:-18443}"
HTTP_PORT_SET=0
HTTPS_PORT_SET=0
[ "${CDSE_DEBUG_TEST_HTTP_PORT+x}" = "x" ] && HTTP_PORT_SET=1
[ "${CDSE_DEBUG_TEST_HTTPS_PORT+x}" = "x" ] && HTTPS_PORT_SET=1
RUN_TIMEOUT="${CDSE_DEBUG_TEST_TIMEOUT:-120s}"
SKIP_BUILD=0
SKIP_WEB=0
LIVE_ONLY=0
WEB_PROTOCOL="both"
WEB_PROTOCOL_SET=0
CI_SMOKE=0
LIVE_FLOW_ID="liveflow$$"
REDACT_OUTPUT="${CDSE_VERIFY_REDACT:-0}"
VERIFY_PARSER_NETWORK_ISOLATION="${CDSE_VERIFY_PARSER_NETWORK_ISOLATION:-0}"
VERIFY_PARSER_CHROOT_ISOLATION="${CDSE_VERIFY_PARSER_CHROOT_ISOLATION:-0}"
VERIFY_PARSER_NO_NEW_PRIVS="${CDSE_VERIFY_PARSER_NO_NEW_PRIVS:-0}"
VERIFY_PARSER_REQUIRE_REVIEWED="${CDSE_VERIFY_PARSER_REQUIRE_REVIEWED:-0}"
VERIFY_PARSER_REQUIRE_POLICY_PROFILES="${CDSE_VERIFY_PARSER_REQUIRE_POLICY_PROFILES:-0}"
VERIFY_HERRADURAKEX_DIR="${CDSE_VERIFY_HERRADURAKEX_DIR:-}"
VERIFY_HERRADURAKEX_DEFAULT_PROFILE="${CDSE_VERIFY_HERRADURAKEX_DEFAULT_PROFILE:-}"
VERIFY_AUTO_PORTS="${CDSE_VERIFY_AUTO_PORTS:-1}"
VERIFY_PORT_SEARCH_LIMIT="${CDSE_VERIFY_PORT_SEARCH_LIMIT:-40}"

PASSED=0
FAILED=0
SKIPPED=0
SUMMARY_FILE=""
LIVE_COVERAGE_CSV=""
LIVE_COVERAGE_TXT=""
LIVE_LAST_STATUS=""
LIVE_LAST_CURL_RC=""

usage() {
    printf 'Usage: %s [--skip-build] [--skip-web] [--live-only] [--ci-smoke] [--web-protocol=http|https|both]\n' "$0"
    printf '\n'
    printf 'Options:\n'
    printf '  --skip-build              reuse the current install prefix\n'
    printf '  --skip-web                skip DEBUG web startup and live API checks\n'
    printf '  --live-only               run only live API checks; implies --skip-build\n'
    printf '  --ci-smoke                run build, component markers, and one live protocol; default http\n'
    printf '  --web-protocol=VALUE      live protocol to run: http, https, or both; default both\n'
    printf '\n'
    printf 'Environment:\n'
    printf '  CDSE_VERIFY_PREFIX         install prefix, default /tmp/cdse-verify\n'
    printf '  CDSE_VERIFY_LOG_DIR        log directory, default /tmp/cdse-debug-components-<timestamp>\n'
    printf '  CDSE_DEBUG_TEST_HTTP_PORT  HTTP test port, default 18080\n'
    printf '  CDSE_DEBUG_TEST_HTTPS_PORT HTTPS test port, default 18443\n'
    printf '  CDSE_DEBUG_TEST_TIMEOUT    executable timeout, default 120s\n'
    printf '  CDSE_VERIFY_AUTO_PORTS     choose alternate default web ports when occupied, default 1\n'
    printf '  CDSE_VERIFY_PORT_SEARCH_LIMIT number of candidate alternate ports to scan, default 40\n'
    printf '  CDSE_VERIFY_REDACT         redact live verifier secrets from summaries and artifacts when set to 1/true/on\n'
    printf '  CDSE_VERIFY_PARSER_NO_NEW_PRIVS       run live parser children with Linux no_new_privs when set to 1/true/on\n'
    printf '  CDSE_VERIFY_PARSER_NETWORK_ISOLATION run optional network-isolation parser check when set to 1/true/on\n'
    printf '  CDSE_VERIFY_PARSER_CHROOT_ISOLATION  run optional chroot parser filesystem check when set to 1/true/on\n'
    printf '  CDSE_VERIFY_PARSER_REQUIRE_REVIEWED  require parser.reviewed:true metadata in live parser checks\n'
    printf '  CDSE_VERIFY_PARSER_REQUIRE_POLICY_PROFILES require parser interpreter/timeout/isolation metadata in live parser checks\n'
    printf '  CDSE_VERIFY_HERRADURAKEX_DIR         enable HerraduraKEx build checks with the directory containing herradura.h\n'
    printf '  CDSE_VERIFY_HERRADURAKEX_DEFAULT_PROFILE set an opt-in Herradura default profile for the DEBUG run\n'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=1
            ;;
        --skip-web)
            SKIP_WEB=1
            ;;
        --live-only)
            LIVE_ONLY=1
            SKIP_BUILD=1
            ;;
        --ci-smoke)
            CI_SMOKE=1
            ;;
        --web-protocol=*)
            WEB_PROTOCOL="${1#*=}"
            WEB_PROTOCOL_SET=1
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

if [ "$CI_SMOKE" -eq 1 ] && [ "$WEB_PROTOCOL_SET" -eq 0 ]; then
    WEB_PROTOCOL="http"
fi

case "$WEB_PROTOCOL" in
    http|https|both)
        ;;
    *)
        printf 'Invalid --web-protocol value: %s\n' "$WEB_PROTOCOL" >&2
        usage >&2
        exit 2
        ;;
esac

if [ "$LIVE_ONLY" -eq 1 ] && [ "$SKIP_WEB" -eq 1 ]; then
    printf '%s\n' '--live-only cannot be combined with --skip-web' >&2
    exit 2
fi

if [ "$CI_SMOKE" -eq 1 ] && [ "$LIVE_ONLY" -eq 1 ]; then
    printf '%s\n' '--ci-smoke cannot be combined with --live-only' >&2
    exit 2
fi

if [ "$CI_SMOKE" -eq 1 ] && [ "$SKIP_WEB" -eq 1 ]; then
    printf '%s\n' '--ci-smoke cannot be combined with --skip-web' >&2
    exit 2
fi

case "$VERIFY_PORT_SEARCH_LIMIT" in
    ''|*[!0-9]*|0)
        printf 'CDSE_VERIFY_PORT_SEARCH_LIMIT must be a positive integer: %s\n' "$VERIFY_PORT_SEARCH_LIMIT" >&2
        exit 2
        ;;
esac

if [ -n "$VERIFY_HERRADURAKEX_DIR" ] && [ ! -f "$VERIFY_HERRADURAKEX_DIR/herradura.h" ]; then
    printf 'CDSE_VERIFY_HERRADURAKEX_DIR must point to a directory containing herradura.h: %s\n' "$VERIFY_HERRADURAKEX_DIR" >&2
    exit 2
fi

if [ -n "$VERIFY_HERRADURAKEX_DEFAULT_PROFILE" ] && [ -z "$VERIFY_HERRADURAKEX_DIR" ]; then
    printf '%s\n' 'CDSE_VERIFY_HERRADURAKEX_DEFAULT_PROFILE requires CDSE_VERIFY_HERRADURAKEX_DIR' >&2
    exit 2
fi

if [ -n "$VERIFY_HERRADURAKEX_DIR" ] && [ -z "$VERIFY_HERRADURAKEX_DEFAULT_PROFILE" ]; then
    VERIFY_HERRADURAKEX_DEFAULT_PROFILE="herradura-hske-nla1-aead-256"
fi

mkdir -p "$LOG_ROOT"
SUMMARY_FILE="$LOG_ROOT/summary.txt"
LIVE_COVERAGE_CSV="$LOG_ROOT/live-api-coverage.csv"
LIVE_COVERAGE_TXT="$LOG_ROOT/live-api-coverage.txt"
: > "$SUMMARY_FILE"
printf 'protocol,feature,method,expected_status,actual_status,curl_rc,marker,status,elapsed,body,meta\n' > "$LIVE_COVERAGE_CSV"
printf '%-7s %-32s %-7s %-8s %-8s %-7s %-6s %-8s %-7s %s\n' \
    "proto" "feature" "method" "expect" "actual" "curl" "marker" "status" "elapsed" "logs" > "$LIVE_COVERAGE_TXT"

elapsed_seconds() {
    local start="$1"
    local now

    now="$(date +%s)"
    printf '%ss' "$((now - start))"
}

csv_escape() {
    local value="$1"
    value="${value//\"/\"\"}"
    printf '"%s"' "$value"
}

redaction_enabled() {
    case "$REDACT_OUTPUT" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
    esac
    return 1
}

parser_network_isolation_enabled() {
    case "$VERIFY_PARSER_NETWORK_ISOLATION" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
    esac
    return 1
}

parser_chroot_isolation_enabled() {
    case "$VERIFY_PARSER_CHROOT_ISOLATION" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
    esac
    return 1
}

parser_review_policy_enabled() {
    case "$VERIFY_PARSER_REQUIRE_REVIEWED" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
    esac
    return 1
}

redact_stream() {
    if ! redaction_enabled; then
        cat
        return 0
    fi

    sed -E \
        -e 's/([?&])(\*?)(orgKey|newOrgKey|accessPath|accessUser|accessPassword|basicAuthPwdHash|oauthConsumerSecret|certificate|publicKey)=([^&"[:space:]]*)/\1\2\3=<redacted>/g' \
        -e 's/(^|[[:space:]])(\*?)(orgKey|newOrgKey|accessPath|accessUser|accessPassword|basicAuthPwdHash|oauthConsumerSecret|certificate|publicKey)=([^"[:space:]]*)/\1\2\3=<redacted>/g' \
        -e 's/(")(\*?)(orgKey|newOrgKey|accessPath|accessUser|accessPassword|basicAuthPwdHash|oauthConsumerSecret|certificate|publicKey)=([^"]*)(")/\1\2\3=<redacted>\5/g' \
        -e 's#([^"[:space:]]*/[^"[:space:]]+\.(key|pem|srl|req|cnf))#<redacted-cert-path>#g'
}

redact_file_in_place() {
    local file="$1"
    local tmp

    if ! redaction_enabled || [ ! -f "$file" ]; then
        return 0
    fi
    tmp="${file}.redacted.$$"
    if redact_stream < "$file" > "$tmp"; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
        return 1
    fi
}

note() {
    printf '%s\n' "$*" | redact_stream | tee -a "$SUMMARY_FILE"
}

record_pass() {
    PASSED=$((PASSED + 1))
    note "PASS $1"
}

record_fail() {
    FAILED=$((FAILED + 1))
    note "FAIL $1 - $2"
}

record_hint() {
    note "HINT $1 - $2"
}

record_skip() {
    SKIPPED=$((SKIPPED + 1))
    note "SKIP $1 - $2"
}

infer_live_method() {
    local method="GET"
    local arg
    local prev_x=0

    for arg in "$@"; do
        if [ "$prev_x" -eq 1 ]; then
            method="$arg"
            prev_x=0
            continue
        fi
        case "$arg" in
            -X)
                prev_x=1
                ;;
            -X*)
                method="${arg#-X}"
                ;;
            --request)
                prev_x=1
                ;;
            --request=*)
                method="${arg#--request=}"
                ;;
            -I|--head)
                method="HEAD"
                ;;
            -F|--form|-F*|--form=*)
                if [ "$method" = "GET" ]; then
                    method="POST"
                fi
                ;;
        esac
    done
    printf '%s' "$method"
}

record_live_coverage() {
    local protocol="$1"
    local feature="$2"
    local method="$3"
    local expected="$4"
    local actual="$5"
    local curl_rc="$6"
    local marker_status="$7"
    local status="$8"
    local elapsed="$9"
    local body="${10}"
    local meta="${11}"

    {
        csv_escape "$protocol"; printf ','
        csv_escape "$feature"; printf ','
        csv_escape "$method"; printf ','
        csv_escape "$expected"; printf ','
        csv_escape "$actual"; printf ','
        csv_escape "$curl_rc"; printf ','
        csv_escape "$marker_status"; printf ','
        csv_escape "$status"; printf ','
        csv_escape "$elapsed"; printf ','
        csv_escape "$body"; printf ','
        csv_escape "$meta"; printf '\n'
    } >> "$LIVE_COVERAGE_CSV"

    printf '%-7s %-32s %-7s %-8s %-8s %-7s %-6s %-8s %-7s body=%s meta=%s\n' \
        "$protocol" "$feature" "$method" "$expected" "$actual" "$curl_rc" \
        "$marker_status" "$status" "$elapsed" "$body" "$meta" >> "$LIVE_COVERAGE_TXT"
}

append_live_coverage_summary() {
    if [ ! -s "$LIVE_COVERAGE_TXT" ] || [ "$(wc -l < "$LIVE_COVERAGE_TXT")" -le 1 ]; then
        return 0
    fi
    note "LIVE API COVERAGE MATRIX"
    while IFS= read -r line; do
        note "$line"
    done < "$LIVE_COVERAGE_TXT"
    note "live_api_coverage_csv=$LIVE_COVERAGE_CSV"
    note "live_api_coverage_txt=$LIVE_COVERAGE_TXT"
}

run_step() {
    local name="$1"
    shift
    local log="$LOG_ROOT/${name}.log"
    local start

    note "RUN  $name"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        "$@"
    ) > "$log" 2>&1
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        record_pass "$name ($(elapsed_seconds "$start"))"
    else
        record_fail "$name" "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    fi
    return "$rc"
}

run_release_bypass_config_guard() {
    local log="$LOG_ROOT/configure_release_bypass_guard.log"
    local start
    local rc

    note "RUN  configure_release_bypass_guard"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        ./configure --prefix="$PREFIX-release-bypass-guard" --enable-BYPASSTLSAUTHINHTTP
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -ne 0 ] && grep -Fq -- "--enable-BYPASSTLSAUTHINHTTP requires --enable-DEBUG" "$log"; then
        record_pass "configure_release_bypass_guard ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail configure_release_bypass_guard "expected release configure to reject --enable-BYPASSTLSAUTHINHTTP rc=$rc log=$log"
    return 1
}

run_delegated_token_broker_self_test() {
    local log="$LOG_ROOT/delegated_token_broker_self_test.log"
    local start
    local rc

    note "RUN  delegated_token_broker_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/delegated-token-broker/delegated_token_broker.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS delegated token broker self-test" "$log"; then
        record_pass "delegated_token_broker_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail delegated_token_broker_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

run_agent_rag_connector_self_test() {
    local log="$LOG_ROOT/agent_rag_connector_self_test.log"
    local start
    local rc

    note "RUN  agent_rag_connector_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/agent-rag-connector/caumedse_rag_connector.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS agent RAG connector self-test" "$log"; then
        record_pass "agent_rag_connector_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail agent_rag_connector_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

run_review_workspace_self_test() {
    local log="$LOG_ROOT/review_workspace_self_test.log"
    local start
    local rc

    note "RUN  review_workspace_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/review-workspace/review_workspace.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS review workspace self-test" "$log"; then
        record_pass "review_workspace_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail review_workspace_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

run_audit_dashboard_self_test() {
    local log="$LOG_ROOT/audit_dashboard_self_test.log"
    local start
    local rc

    note "RUN  audit_dashboard_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/audit-dashboard/audit_dashboard.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS audit dashboard self-test" "$log"; then
        record_pass "audit_dashboard_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail audit_dashboard_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

run_mcp_write_guard_self_test() {
    local log="$LOG_ROOT/mcp_write_guard_self_test.log"
    local start
    local rc

    note "RUN  mcp_write_guard_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/mcp-server/caumedse_mcp_server.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS MCP write guard self-test" "$log"; then
        record_pass "mcp_write_guard_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail mcp_write_guard_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

run_policy_authz_tester_self_test() {
    local log="$LOG_ROOT/policy_authz_tester_self_test.log"
    local start
    local rc

    note "RUN  policy_authz_tester_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/policy-authz-tester/policy_authz_tester.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS policy authz tester self-test" "$log"; then
        record_pass "policy_authz_tester_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail policy_authz_tester_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

run_backup_restore_self_test() {
    local log="$LOG_ROOT/backup_restore_self_test.log"
    local start
    local rc

    note "RUN  backup_restore_self_test"
    start="$(date +%s)"
    (
        cd "$ROOT_DIR" || exit 1
        python3 samples/encrypted-backup-restore/cdse_backup_restore.py self-test
    ) > "$log" 2>&1
    rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ] && grep -Fq "PASS encrypted backup restore self-test" "$log"; then
        record_pass "backup_restore_self_test ($(elapsed_seconds "$start"))"
        return 0
    fi
    record_fail backup_restore_self_test "exit=$rc elapsed=$(elapsed_seconds "$start") log=$log"
    return 1
}

protocol_enabled() {
    local protocol="$1"

    [ "$WEB_PROTOCOL" = "both" ] || [ "$WEB_PROTOCOL" = "$protocol" ]
}

port_in_use() {
    local port="$1"
    if ! command -v ss >/dev/null 2>&1; then
        return 1
    fi
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

valid_tcp_port() {
    local port="$1"
    case "$port" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac
    [ "$port" -gt 0 ] && [ "$port" -le 65535 ]
}

env_enabled() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|on|ON)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

find_available_port() {
    local start="$1"
    local limit="$2"
    local avoid="${3:-}"
    local candidate="$start"
    local checked=0

    while [ "$checked" -lt "$limit" ] && [ "$candidate" -le 65535 ]; do
        if valid_tcp_port "$candidate" &&
           { [ -z "$avoid" ] || [ "$candidate" -ne "$avoid" ]; } &&
           ! port_in_use "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
        candidate=$((candidate + 1))
        checked=$((checked + 1))
    done
    return 1
}

resolve_webservice_ports() {
    local selected

    if ! env_enabled "$VERIFY_AUTO_PORTS"; then
        return 0
    fi
    if protocol_enabled http && [ "$HTTP_PORT_SET" -eq 0 ] && valid_tcp_port "$HTTP_PORT" && port_in_use "$HTTP_PORT"; then
        selected="$(find_available_port "$((HTTP_PORT + 1))" "$VERIFY_PORT_SEARCH_LIMIT" "$HTTPS_PORT")" || return 1
        note "webservice_ports fallback http original=$HTTP_PORT selected=$selected"
        HTTP_PORT="$selected"
    fi
    if protocol_enabled https && [ "$HTTPS_PORT_SET" -eq 0 ] && valid_tcp_port "$HTTPS_PORT" && port_in_use "$HTTPS_PORT"; then
        selected="$(find_available_port "$((HTTPS_PORT + 1))" "$VERIFY_PORT_SEARCH_LIMIT" "$HTTP_PORT")" || return 1
        note "webservice_ports fallback https original=$HTTPS_PORT selected=$selected"
        HTTPS_PORT="$selected"
    fi
    if [ "$WEB_PROTOCOL" = "both" ] && valid_tcp_port "$HTTP_PORT" && valid_tcp_port "$HTTPS_PORT" &&
       [ "$HTTP_PORT" -eq "$HTTPS_PORT" ] && [ "$HTTPS_PORT_SET" -eq 0 ]; then
        selected="$(find_available_port "$((HTTPS_PORT + 1))" "$VERIFY_PORT_SEARCH_LIMIT" "$HTTP_PORT")" || return 1
        note "webservice_ports fallback https original=$HTTPS_PORT selected=$selected reason=same-as-http"
        HTTPS_PORT="$selected"
    fi
    return 0
}

run_webservice_preflight_self_test() {
    local log="$LOG_ROOT/webservice-preflight-self-test.log"

    : > "$log"
    if valid_tcp_port 1 && valid_tcp_port 65535 &&
       ! valid_tcp_port 0 && ! valid_tcp_port 65536 && ! valid_tcp_port abc &&
       env_enabled 1 && env_enabled true && ! env_enabled 0 &&
       ! find_available_port 65535 1 65535 >/dev/null 2>&1; then
        printf 'PASS valid_tcp_port boundary checks\n' > "$log"
        printf 'PASS auto port helper checks\n' >> "$log"
        record_pass webservice_preflight_self_test
    else
        printf 'FAIL webservice preflight helper checks\n' > "$log"
        record_fail webservice_preflight_self_test "log=$log"
    fi
}

write_webservice_startup_preflight() {
    local log="$LOG_ROOT/webservice-startup-preflight.log"
    local protocol
    local port
    local file
    local size

    {
        printf 'CaumeDSE webservice startup preflight\n'
        printf 'root=%s\n' "$ROOT_DIR"
        printf 'prefix=%s\n' "$PREFIX"
        printf 'web_protocol=%s skip_web=%s live_only=%s\n' "$WEB_PROTOCOL" "$SKIP_WEB" "$LIVE_ONLY"
        printf 'http_port=%s https_port=%s run_timeout=%s\n' "$HTTP_PORT" "$HTTPS_PORT" "$RUN_TIMEOUT"
        printf 'auto_ports=%s port_search_limit=%s explicit_http_port=%s explicit_https_port=%s\n' \
            "$VERIFY_AUTO_PORTS" "$VERIFY_PORT_SEARCH_LIMIT" "$HTTP_PORT_SET" "$HTTPS_PORT_SET"
        printf 'curl=%s\n' "$(command -v curl 2>/dev/null || printf '<missing>')"
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libmicrohttpd 2>/dev/null; then
            printf 'libmicrohttpd=%s\n' "$(pkg-config --modversion libmicrohttpd 2>/dev/null)"
        elif command -v microhttpd-config >/dev/null 2>&1; then
            printf 'libmicrohttpd=%s\n' "$(microhttpd-config --version 2>/dev/null)"
        else
            printf 'libmicrohttpd=<version-unavailable>\n'
        fi
        for protocol in http https; do
            if protocol_enabled "$protocol"; then
                if [ "$protocol" = "http" ]; then
                    port="$HTTP_PORT"
                else
                    port="$HTTPS_PORT"
                fi
                if valid_tcp_port "$port"; then
                    printf '%s_port_valid=yes port=%s\n' "$protocol" "$port"
                else
                    printf '%s_port_valid=no port=%s\n' "$protocol" "$port"
                fi
                if command -v ss >/dev/null 2>&1; then
                    printf '%s_port_listeners:\n' "$protocol"
                    ss -ltnp 2>/dev/null | awk -v port="$port" '$4 ~ ":" port "$" { print $0 }'
                else
                    printf '%s_port_listeners=<ss-unavailable>\n' "$protocol"
                fi
            fi
        done
        if protocol_enabled https; then
            for file in "$PREFIX/cdse/server.key" "$PREFIX/cdse/server.pem" "$PREFIX/cdse/ca.pem"; do
                if [ -r "$file" ]; then
                    size="$(wc -c < "$file" 2>/dev/null || printf '0')"
                    printf 'certificate_file readable=yes bytes=%s path=%s\n' "$size" "$file"
                else
                    printf 'certificate_file readable=no bytes=0 path=%s\n' "$file"
                fi
            done
        fi
    } > "$log" 2>&1
    redact_file_in_place "$log"
    record_pass "webservice_startup_preflight log=$log"
}

check_required() {
    local log="$1"
    local marker="$2"
    grep -Fq -- "$marker" "$log"
}

check_forbidden() {
    local log="$1"
    local filtered_log="$LOG_ROOT/forbidden_markers_filtered.log"

    grep -Ev 'CaumeDSE Error: cmeCipherByteString\(\), unsupported storage crypto profile: herradura-hske-nla1-aead-256!' "$log" > "$filtered_log"
    if [ -n "$VERIFY_HERRADURAKEX_DIR" ]; then
        grep -Ev 'CaumeDSE Error: cmeCipherByteString\(\), unsupported HerraduraKEx frame profile id: 255!' "$filtered_log" | \
            grep -Eq 'CaumeDSE Error|FAILED|FAIL:|Segmentation fault|Assertion .*failed|assertion .*failed|core dumped|timeout: the monitored command dumped core'
        return $?
    fi
    grep -Eq 'CaumeDSE Error|FAILED|FAIL:|Segmentation fault|Assertion .*failed|assertion .*failed|core dumped|timeout: the monitored command dumped core' "$filtered_log"
}

certificate_read_marker_seen() {
    local log="$1"
    local marker="$2"
    local marker_dir="${marker%/*}"
    local marker_size

    if grep -E "read [1-9][0-9]* bytes from file " "$log" | grep -Fq -- "$marker"; then
        return 0
    fi
    if grep -E ", of length [1-9][0-9]*\\." "$log" | grep -Fq -- "$marker"; then
        return 0
    fi
    if [ -f "$marker" ]; then
        marker_size="$(wc -c < "$marker" | tr -d '[:space:]')"
        if [ "$marker_size" -gt 0 ] 2>/dev/null && \
           grep -Eq "read ${marker_size} bytes from file ${marker_dir}/" "$log"; then
            return 0
        fi
    fi
    return 1
}

extract_component_log() {
    local out="$1"
    local pattern="$2"
    local source="$3"
    grep -nE -- "$pattern" "$source" > "$out" 2>/dev/null || true
    redact_file_in_place "$out"
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

check_herradurakex_component() {
    local source="$1"

    if [ -z "$VERIFY_HERRADURAKEX_DIR" ]; then
        record_skip herradurakex_at_rest "HerraduraKEx provider not requested"
        return 0
    fi
    check_component herradurakex_at_rest 'HerraduraKEx|legacy AES profile|embedded profile|CDSEHKX1' "$source" \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD storage profile metadata resolved.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx implementation availability follows build flag.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD profile round trip.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx frame decrypts via embedded profile metadata.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD rejects wrong key.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD rejects wrong salt.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD rejects tampered tag.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD rejects tampered nonce.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE-NL-A1 AEAD rejects tampered ciphertext.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx frame rejects unsupported profile id.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx frame rejects truncated frame.' \
        'TESTS: testCryptoSymmetric(), PASS: legacy AES profile decrypts when Herradura is configured.' \
        'TESTS: testCryptoSymmetric(), PASS: HerraduraKEx HSKE duplex profile round trip.'
}

check_herradurakex_independent_component() {
    local source="$1"

    if [ -z "$VERIFY_HERRADURAKEX_DIR" ]; then
        record_skip herradurakex_independent "HerraduraKEx provider not requested"
        return 0
    fi
    check_component herradurakex_independent 'testHerraduraIndependent|HFSCX|HSKE direct APIs' "$source" \
        'TESTS: testHerraduraIndependent(), PASS: HSKE-NL-A1 AEAD known-answer vector matches.' \
        'TESTS: testHerraduraIndependent(), PASS: HSKE duplex known-answer vector matches.' \
        'TESTS: testHerraduraIndependent(), PASS: HSKE-NL-A1 AEAD empty-plaintext vector matches.' \
        'TESTS: testHerraduraIndependent(), PASS: HSKE duplex empty-plaintext vector matches.' \
        'TESTS: testHerraduraIndependent(), PASS: HSKE direct APIs round trip fixed boundary sizes.' \
        'TESTS: testHerraduraIndependent(), PASS: HSKE direct APIs reject mutated auth inputs and wrong profile selection.' \
        'TESTS: testHerraduraIndependent(), PASS: HFSCX-256 known-answer vector matches.' \
        'TESTS: testHerraduraIndependent(), PASS: HFSCX-256-DS known-answer vector matches.'
}

check_key_rotation_component() {
    local source="$1"

    check_component key_rotation_reprotect 'testCryptoReprotectDBValue|re-protect' "$source" \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB value re-protect rotates key with AES profile.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB value dry-run re-protect reports plaintext length without writing.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB value re-protect rejects wrong source key.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB re-protect inventory reports AES protected row scope.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB-level re-protect dry-run reports row scope without mutation.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB-level re-protect rejects wrong source key.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB-level re-protect rotates protected rows and reads back with new key.'
}

check_key_rotation_herradurakex_component() {
    local source="$1"

    if [ -z "$VERIFY_HERRADURAKEX_DIR" ]; then
        record_skip key_rotation_herradurakex "HerraduraKEx provider not requested"
        return 0
    fi
    check_component key_rotation_herradurakex 'testCryptoReprotectDBValue|Herradura.*re-protect' "$source" \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB value re-protect migrates AES to Herradura profile.' \
        'TESTS: testCryptoReprotectDBValue(), PASS: DB value re-protect rolls Herradura back to AES profile.'
}

check_live_herradurakex_storage_at_rest() {
    local protocol="$1"
    local storage_path="$2"
    local csv_name="$3"
    local large_csv_name="$4"
    local log="$LOG_ROOT/live_${protocol}_herradurakex_storage.log"

    if [ -z "$VERIFY_HERRADURAKEX_DIR" ]; then
        record_skip "live_${protocol}_herradurakex_storage_at_rest" "HerraduraKEx provider not requested"
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        record_skip "live_${protocol}_herradurakex_storage_at_rest" "python3 not available"
        return 0
    fi

    CDSE_VERIFY_PREFIX_PATH="$PREFIX/cdse" \
    CDSE_VERIFY_STORAGE_PATH="$storage_path" \
    CDSE_VERIFY_DOC_NAMES="$csv_name,$large_csv_name" \
    python3 - <<'PY' > "$log" 2>&1
import base64
import os
import sqlite3
import string
import sys

roots = [
    os.environ["CDSE_VERIFY_PREFIX_PATH"],
    os.environ["CDSE_VERIFY_STORAGE_PATH"],
]
doc_names = [v for v in os.environ["CDSE_VERIFY_DOC_NAMES"].split(",") if v]
plaintext_tokens = [b"Jacob", b"Nieves", b"82400"]
magic = b"CDSEHKX1"
hexchars = set(string.hexdigits)
sqlite_files = []
frame_count = 0
profile_ids = set()
plaintext_hits = []

for root in roots:
    if not os.path.isdir(root):
        continue
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if any(token in raw for token in plaintext_tokens):
                plaintext_hits.append(path)
            try:
                conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            except sqlite3.Error:
                continue
            sqlite_files.append(path)
            for (table_name,) in rows:
                try:
                    cursor = conn.execute(f'SELECT * FROM "{table_name}"')
                except sqlite3.Error:
                    continue
                for row in cursor:
                    for value in row:
                        if not isinstance(value, str):
                            continue
                        if any(token.decode("ascii") in value for token in plaintext_tokens):
                            plaintext_hits.append(f"{path}:{table_name}")
                        if len(value) <= 64 or any(ch not in hexchars for ch in value[:64]):
                            continue
                        try:
                            decoded = base64.b64decode(value[64:], validate=True)
                        except Exception:
                            continue
                        if decoded.startswith(magic):
                            frame_count += 1
                            if len(decoded) > len(magic):
                                profile_ids.add(decoded[len(magic)])
            conn.close()

print(f"sqlite_files={len(sqlite_files)}")
print(f"herradura_frames={frame_count}")
print("profile_ids=" + ",".join(str(v) for v in sorted(profile_ids)))
print("documents=" + ",".join(doc_names))
if plaintext_hits:
    print("plaintext_hits=" + ",".join(sorted(set(plaintext_hits))[:10]))
    sys.exit(2)
if frame_count <= 0:
    print("missing_herradura_frames=1")
    sys.exit(3)
if 1 not in profile_ids:
    print("missing_hske_nla1_profile=1")
    sys.exit(4)
PY
    local rc=$?
    redact_file_in_place "$log"
    if [ "$rc" -eq 0 ]; then
        record_pass "live_${protocol}_herradurakex_storage_at_rest"
    else
        record_fail "live_${protocol}_herradurakex_storage_at_rest" "rc=$rc log=$log"
    fi
}

record_herradurakex_perf_smoke() {
    local protocol="$1"
    local feature="$2"
    local file_path="$3"
    local started="$4"
    local file_bytes

    if [ -z "$VERIFY_HERRADURAKEX_DIR" ]; then
        return 0
    fi
    file_bytes="$(wc -c < "$file_path" | tr -d '[:space:]')"
    note "INFO live_${protocol}_herradurakex_perf_smoke feature=$feature bytes=$file_bytes elapsed=$(elapsed_seconds "$started") threshold=none"
}

wait_for_log_marker() {
    local log="$1"
    local marker="$2"
    local timeout_seconds="$3"
    local waited=0

    while [ "$waited" -lt "$timeout_seconds" ]; do
        if grep -Fq -- "$marker" "$log" 2>/dev/null; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

run_https_startup_failure_redaction_check() {
    local probe_log="$LOG_ROOT/https-startup-failure.log"
    local holder_log="$LOG_ROOT/https-port-holder.log"
    local listener_pid=""

    : > "$probe_log"
    : > "$holder_log"

    python3 - "$HTTPS_PORT" > "$holder_log" 2>&1 <<'PY' &
import socket
import sys
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", int(sys.argv[1])))
sock.listen(1)
print("ready", flush=True)
time.sleep(30)
PY
    listener_pid=$!

    if ! wait_for_log_marker "$holder_log" "ready" 10; then
        stop_live_service "$listener_pid"
        record_fail https_startup_failure_redaction "could not reserve HTTPS test port $HTTPS_PORT log=$holder_log"
        return
    fi

    (
        cd "$ROOT_DIR" || exit 1
        CDSE_DEBUG_TEST_HTTPS_PORT="$HTTPS_PORT" timeout 20s "$PREFIX/cdse/bin/CaumeDSE-debug-tests" --web-service https
    ) > "$probe_log" 2>&1 || true

    stop_live_service "$listener_pid"

    if grep -Fq "can't start HTTPS server" "$probe_log"; then
        :
    else
        record_fail https_startup_failure_redaction "missing HTTPS startup failure marker log=$probe_log"
        return
    fi

    if grep -Eq 'BEGIN (RSA |EC |)PRIVATE KEY|END (RSA |EC |)PRIVATE KEY' "$probe_log"; then
        record_fail https_startup_failure_redaction "private key PEM marker leaked in $probe_log"
    else
        record_pass https_startup_failure_redaction
    fi
}

check_live_debug_secret_redaction() {
    local protocol="$1"
    local service_log="$2"
    local org_key="$3"
    local leak_log="$LOG_ROOT/live_${protocol}_debug_secret_leaks.log"
    local leaked=0

    : > "$leak_log"

    if grep -F "parameter orgKey: '" "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi
    if grep -F "parameter newOrgKey: '" "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi
    if grep -F " key $org_key" "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi
    if grep -F " the key $org_key" "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi
    if grep -E "cmeUnprotect(ByteString|DBValue|DBSaltedValue).* -> [^v]" "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi
    if grep -E "cmeProtect(ByteString|DBSaltedValue).*: [^v]" "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi
    if grep -F "Result: " "$service_log" >> "$leak_log" 2>/dev/null; then
        leaked=1
    fi

    if [ "$leaked" -eq 0 ]; then
        record_pass "live_${protocol}_debug_secret_redaction"
        rm -f "$leak_log"
    else
        redact_file_in_place "$leak_log"
        record_fail "live_${protocol}_debug_secret_redaction" "secret-bearing DEBUG diagnostic found log=$leak_log"
    fi
}

check_live_transaction_log_redaction() {
    local protocol="$1"
    local org_key="$2"
    local long_value="$3"
    local db_path="$PREFIX/cdse/LogsDB"
    local query_log="$LOG_ROOT/live_${protocol}_transaction_log_redaction.log"
    local leaked=0

    : > "$query_log"

    if [ ! -f "$db_path" ]; then
        record_fail "live_${protocol}_transaction_log_redaction" "LogsDB not found at $db_path"
        return
    fi
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$db_path" "SELECT requestUrl, requestHeaders FROM transactions WHERE authenticated='0' AND requestUrl LIKE '%logProbe%';" > "$query_log" 2>&1
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$db_path" > "$query_log" 2>&1 <<'PY'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
try:
    for request_url, request_headers in conn.execute(
        "SELECT requestUrl, requestHeaders FROM transactions "
        "WHERE authenticated='0' AND requestUrl LIKE '%logProbe%'"
    ):
        print(request_url or "")
        print(request_headers or "")
finally:
    conn.close()
PY
    else
        record_skip "live_${protocol}_transaction_log_redaction" "sqlite3 CLI or python3 is required to inspect LogsDB"
        return
    fi
    if [ "$?" -ne 0 ]; then
        redact_file_in_place "$query_log"
        record_fail "live_${protocol}_transaction_log_redaction" "could not query LogsDB log=$query_log"
        return
    fi
    if [ ! -s "$query_log" ]; then
        record_fail "live_${protocol}_transaction_log_redaction" "missing log redaction probe row in LogsDB"
        return
    fi

    if grep -F "$org_key" "$query_log" >/dev/null 2>&1; then
        leaked=1
    fi
    if grep -F "$long_value" "$query_log" >/dev/null 2>&1; then
        leaked=1
    fi
    if ! grep -Fq "orgKey=<redacted>" "$query_log"; then
        leaked=1
    fi
    if ! grep -Fq "newOrgKey=<redacted>" "$query_log"; then
        leaked=1
    fi
    if ! grep -Fq "accessPassword=<redacted>" "$query_log"; then
        leaked=1
    fi
    if ! grep -Fq "...<truncated>" "$query_log"; then
        leaked=1
    fi

    if [ "$leaked" -eq 0 ]; then
        record_pass "live_${protocol}_transaction_log_redaction"
        rm -f "$query_log"
    else
        redact_file_in_place "$query_log"
        record_fail "live_${protocol}_transaction_log_redaction" "request log secret redaction or truncation check failed log=$query_log"
    fi
}

check_live_structured_audit_redaction() {
    local protocol="$1"
    local service_log="$2"
    local org_key="$3"
    local audit_log="$LOG_ROOT/live_${protocol}_structured_audit.log"

    : > "$audit_log"

    if ! command -v python3 >/dev/null 2>&1; then
        record_skip "live_${protocol}_structured_audit_redaction" "python3 is required to inspect structured audit JSON"
        return
    fi
    if ! python3 "$ROOT_DIR/samples/ai-agent/recent_audit_reader.py" "$service_log" --limit 5 >> "$audit_log" 2>&1; then
        redact_file_in_place "$audit_log"
        record_fail "live_${protocol}_structured_audit_redaction" "sample audit reader failed log=$audit_log"
        return
    fi
    if ! python3 - "$service_log" "$org_key" >> "$audit_log" 2>&1 <<'PY'
import json
import sys

prefix = "CaumeDSE AuditJSON: "
service_log, org_key = sys.argv[1], sys.argv[2]
required = {"auth", "authorization", "request", "parserPolicy", "parserUpload", "parserExecution"}
seen = set()
count = 0
with open(service_log, "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        if prefix not in line:
            continue
        payload = line.split(prefix, 1)[1].strip()
        if not payload.startswith("{"):
            continue
        event, _ = json.JSONDecoder().raw_decode(payload)
        if not isinstance(event, dict):
            continue
        count += 1
        if event.get("auditSchemaVersion") != 1:
            raise SystemExit("unexpected audit schema version")
        if event.get("safeForAgent") is not True:
            raise SystemExit("audit event is not marked safeForAgent")
        seen.add(event.get("category"))
        serialized = json.dumps(event, sort_keys=True)
        for marker in (org_key, "Authorization:", "Bearer "):
            if marker and marker in serialized:
                raise SystemExit(f"structured audit leaked marker: {marker}")
if count == 0:
    raise SystemExit("no structured audit events found")
missing = sorted(required - seen)
if missing:
    raise SystemExit("missing structured audit categories: " + ",".join(missing))
print(f"structured audit events={count} categories={','.join(sorted(str(x) for x in seen if x))}")
PY
    then
        redact_file_in_place "$audit_log"
        record_fail "live_${protocol}_structured_audit_redaction" "structured audit JSON validation failed log=$audit_log"
        return
    fi

    record_pass "live_${protocol}_structured_audit_redaction"
    rm -f "$audit_log"
}

check_live_mcp_readonly_smoke() {
    local protocol="$1"
    local base_url="$2"
    local org_name="$3"
    local storage_name="$4"
    local user_id="$5"
    local org_key="$6"
    local csv_name="$7"
    local parser_name="$8"
    local pending_parser_name="$9"
    local client_chain="${10:-}"
    local client_key="${11:-}"
    local mcp_log="$LOG_ROOT/live_${protocol}_mcp_readonly_smoke.log"

    : > "$mcp_log"

    if ! command -v python3 >/dev/null 2>&1; then
        record_skip "live_${protocol}_mcp_readonly_smoke" "python3 is required for MCP stdio smoke"
        return
    fi

    if ! env \
        CDSE_MCP_BASE_URL="$base_url" \
        CDSE_MCP_ORG="$org_name" \
        CDSE_MCP_USER="$user_id" \
        CDSE_MCP_STORAGE="$storage_name" \
        CDSE_MCP_ORG_KEY="$org_key" \
        CDSE_MCP_CSV_DOC="$csv_name" \
        CDSE_MCP_PARSER_DOC="$parser_name" \
        CDSE_MCP_PENDING_PARSER_DOC="$pending_parser_name" \
        CDSE_MCP_CA_CERT="$PREFIX/cdse/ca.pem" \
        CDSE_MCP_CLIENT_CERT="$client_chain" \
        CDSE_MCP_CLIENT_KEY="$client_key" \
        python3 - "$ROOT_DIR/samples/mcp-server/caumedse_mcp_server.py" > "$mcp_log" 2>&1 <<'PY'
import json
import os
import subprocess
import sys

server = sys.argv[1]
requests = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "agentCapabilities_read", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "documentSchema_read", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "contentColumns_read", "arguments": {"column": "name", "limit": 1}}},
    {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "parserScripts_run", "arguments": {"limit": 1}}},
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "parserScripts_preview", "arguments": {"limit": 1, "preview_rows": 1}}},
    {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "dbTableSchema_read", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "dbTableColumns_read", "arguments": {"column": "name", "limit": 1}}},
]
payload = "\n".join(json.dumps(item) for item in requests) + "\n"
proc = subprocess.run(
    [sys.executable, server],
    input=payload,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=os.environ.copy(),
    timeout=90,
)
print(proc.stdout)
if proc.stderr:
    print(proc.stderr, file=sys.stderr)
if proc.returncode != 0:
    raise SystemExit(f"MCP server exited {proc.returncode}")
responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
by_id = {response.get("id"): response for response in responses}
if set(by_id) != set(range(1, 10)):
    raise SystemExit(f"unexpected MCP response ids: {sorted(by_id)}")
tool_names = {tool["name"] for tool in by_id[2]["result"]["tools"]}
required = {
    "agentCapabilities_read",
    "documentTypes_list",
    "documentSchema_read",
    "contentColumns_read",
    "parserScripts_run",
    "parserScripts_preview",
    "dbTableSchema_read",
    "dbTableColumns_read",
}
for name in required:
    if name not in tool_names:
        raise SystemExit(f"missing read-only MCP tool: {name}")
for name in ("create_workspace", "upload_csv", "upload_parser", "cleanup_workspace"):
    if name in tool_names:
        raise SystemExit(f"write helper exposed without CDSE_MCP_ENABLE_WRITE_TOOLS: {name}")
for request_id in range(3, 10):
    result = by_id[request_id].get("result", {})
    if result.get("isError"):
        raise SystemExit(f"MCP tool call {request_id} failed: {result}")
    content = result.get("content") or []
    if not content:
        raise SystemExit(f"MCP tool call {request_id} returned no content")
    text = content[0].get("text", "")
    if any(marker in text for marker in (os.environ["CDSE_MCP_ORG_KEY"], "Authorization:", "Bearer ")):
        raise SystemExit("MCP tool result leaked a credential marker")
    parsed = json.loads(text)
    if request_id in (4, 8) and parsed.get("safeForAgent") is not True:
        raise SystemExit("schema read did not return safeForAgent metadata")
print("MCP read-only smoke passed")
PY
    then
        redact_file_in_place "$mcp_log"
        record_fail "live_${protocol}_mcp_readonly_smoke" "MCP read-only smoke failed log=$mcp_log"
        return
    fi

    record_pass "live_${protocol}_mcp_readonly_smoke"
    rm -f "$mcp_log"
}

check_live_agent_rag_connector_smoke() {
    local protocol="$1"
    local base_url="$2"
    local org_name="$3"
    local storage_name="$4"
    local user_id="$5"
    local org_key="$6"
    local csv_name="$7"
    local client_chain="${8:-}"
    local client_key="${9:-}"
    local rag_log="$LOG_ROOT/live_${protocol}_agent_rag_connector_smoke.log"
    local rag_config="$LOG_ROOT/live_${protocol}_agent_rag_connector_config.json"

    : > "$rag_log"

    if ! command -v python3 >/dev/null 2>&1; then
        record_skip "live_${protocol}_agent_rag_connector_smoke" "python3 is required for agent RAG connector smoke"
        return
    fi

    cat > "$rag_config" <<EOF
{
  "documents": {
    "$csv_name": {
      "documentType": "file.csv",
      "allowedColumns": ["name", "salary"],
      "maxRows": 1,
      "redactions": {
        "salary": "[redacted-salary]"
      }
    }
  }
}
EOF

    if ! env \
        CDSE_RAG_BASE_URL="$base_url" \
        CDSE_RAG_ORG="$org_name" \
        CDSE_RAG_USER="$user_id" \
        CDSE_RAG_STORAGE="$storage_name" \
        CDSE_RAG_ORG_KEY="$org_key" \
        CDSE_RAG_CA_CERT="$PREFIX/cdse/ca.pem" \
        CDSE_RAG_CLIENT_CERT="$client_chain" \
        CDSE_RAG_CLIENT_KEY="$client_key" \
        python3 "$ROOT_DIR/samples/agent-rag-connector/caumedse_rag_connector.py" live \
            --config "$rag_config" \
            --document "$csv_name" \
            --columns name,salary \
            --limit 1 > "$rag_log" 2>&1; then
        redact_file_in_place "$rag_log"
        record_fail "live_${protocol}_agent_rag_connector_smoke" "agent RAG connector failed log=$rag_log"
        return
    fi

    if ! python3 - "$rag_log" "$org_key" >> "$rag_log" 2>&1 <<'PY'
import json
import sys

path, org_key = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
text = json.dumps(data, sort_keys=True)
if data.get("safeForAgent") is not True:
    raise SystemExit("RAG connector output is not marked safeForAgent")
if data.get("mode") != "live":
    raise SystemExit("RAG connector did not run in live mode")
if data.get("policy", {}).get("returnedColumns") != ["name", "salary"]:
    raise SystemExit("RAG connector returned unexpected columns")
if data.get("rows", [{}])[0].get("salary") != "[redacted-salary]":
    raise SystemExit("RAG connector did not redact salary")
if not data.get("source", {}).get("requestIds"):
    raise SystemExit("RAG connector did not capture request IDs")
if org_key in text or "orgKey" in text or "newOrgKey" in text:
    raise SystemExit("RAG connector output leaked credential markers")
print("agent RAG connector live smoke passed")
PY
    then
        redact_file_in_place "$rag_log"
        record_fail "live_${protocol}_agent_rag_connector_smoke" "agent RAG connector validation failed log=$rag_log"
        return
    fi

    record_pass "live_${protocol}_agent_rag_connector_smoke"
    rm -f "$rag_log" "$rag_config"
}

stop_live_service() {
    local pid="$1"

    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

live_curl() {
    local protocol="$1"
    local name="$2"
    local expected="$3"
    local url="$4"
    shift 4
    local body="$LOG_ROOT/live_${protocol}_${name}.body"
    local meta="$LOG_ROOT/live_${protocol}_${name}.meta"
    local status
    local rc

    status="$(curl --silent --show-error --max-time 20 --output "$body" --write-out '%{http_code}' "$@" "$url" 2>"$meta")"
    rc=$?
    LIVE_LAST_STATUS="$status"
    LIVE_LAST_CURL_RC="$rc"
    printf 'name=%s\nurl=%s\nstatus=%s\ncurl_rc=%s\n' "$name" "$url" "$status" "$rc" >> "$meta"
    redact_file_in_place "$body"
    redact_file_in_place "$meta"
    if [ "$rc" -ne 0 ]; then
        return 1
    fi
    [ "$status" = "$expected" ]
}

check_live_body_marker() {
    local protocol="$1"
    local name="$2"
    local marker="$3"
    local body="$LOG_ROOT/live_${protocol}_${name}.body"

    grep -Fq -- "$marker" "$body"
}

LIVE_FLOW_FAILED=0

live_api_check() {
    local protocol="$1"
    local feature="$2"
    local expected="$3"
    local url="$4"
    local marker="$5"
    shift 5
    local body="$LOG_ROOT/live_${protocol}_${feature}.body"
    local meta="$LOG_ROOT/live_${protocol}_${feature}.meta"
    local method
    local start
    local elapsed

    method="$(infer_live_method "$@")"
    start="$(date +%s)"

    if ! live_curl "$protocol" "$feature" "$expected" "$url" "$@"; then
        LIVE_FLOW_FAILED=1
        elapsed="$(elapsed_seconds "$start")"
        record_live_coverage "$protocol" "$feature" "$method" "$expected" "$LIVE_LAST_STATUS" "$LIVE_LAST_CURL_RC" "not_checked" "FAIL" "$elapsed" "$body" "$meta"
        record_fail "live_${protocol}_${feature}" "expected HTTP $expected elapsed=$elapsed body=$body meta=$meta"
        return 1
    fi
    if [ -n "$marker" ] && ! check_live_body_marker "$protocol" "$feature" "$marker"; then
        LIVE_FLOW_FAILED=1
        elapsed="$(elapsed_seconds "$start")"
        record_live_coverage "$protocol" "$feature" "$method" "$expected" "$LIVE_LAST_STATUS" "$LIVE_LAST_CURL_RC" "missing" "FAIL" "$elapsed" "$body" "$meta"
        record_fail "live_${protocol}_${feature}" "missing marker '$marker' elapsed=$elapsed body=$body meta=$meta"
        return 1
    fi
    elapsed="$(elapsed_seconds "$start")"
    if [ -n "$marker" ]; then
        record_live_coverage "$protocol" "$feature" "$method" "$expected" "$LIVE_LAST_STATUS" "$LIVE_LAST_CURL_RC" "found" "PASS" "$elapsed" "$body" "$meta"
    else
        record_live_coverage "$protocol" "$feature" "$method" "$expected" "$LIVE_LAST_STATUS" "$LIVE_LAST_CURL_RC" "none" "PASS" "$elapsed" "$body" "$meta"
    fi
    record_pass "live_${protocol}_${feature} ($elapsed)"
    return 0
}

write_cert_ext_files() {
    local ca_ext="$1"
    local user_ext="$2"

    cat > "$ca_ext" <<'EOF'
[req]
distinguished_name = req_dn
[req_dn]
[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = critical,CA:true
keyUsage               = critical,cRLSign,keyCertSign
EOF
    cat > "$user_ext" <<'EOF'
[usr_cert]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage               = critical,nonRepudiation,digitalSignature
extendedKeyUsage       = clientAuth
EOF
}

generate_live_client_cert_chain() {
    local protocol="$1"
    local org_id="$2"
    local user_id="$3"
    local org_key="$LOG_ROOT/live_${protocol}_org.key"
    local org_req="$LOG_ROOT/live_${protocol}_org.req"
    local org_pem="$LOG_ROOT/live_${protocol}_org.pem"
    local user_key="$LOG_ROOT/live_${protocol}_user.key"
    local user_req="$LOG_ROOT/live_${protocol}_user.req"
    local user_pem="$LOG_ROOT/live_${protocol}_user.pem"
    local ca_ext="$LOG_ROOT/live_${protocol}_ca_ext.cnf"
    local user_ext="$LOG_ROOT/live_${protocol}_user_ext.cnf"
    local chain="$LOG_ROOT/live_${protocol}_client_chain.pem"
    local ca_serial="$LOG_ROOT/live_${protocol}_ca.srl"
    local org_serial="$LOG_ROOT/live_${protocol}_org.srl"

    write_cert_ext_files "$ca_ext" "$user_ext"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$org_key" >/dev/null 2>&1
    openssl req -new -key "$org_key" \
        -subj "/C=MX/ST=DF/L=Mexico City/O=$org_id/OU=CA/CN=$org_id" \
        -sha384 -out "$org_req" >/dev/null 2>&1
    openssl x509 -req -days 3650 -in "$org_req" \
        -CA "$ROOT_DIR/TEST/testCertAuth/ca.pem" \
        -CAkey "$ROOT_DIR/TEST/testCertAuth/ca.key" \
        -CAserial "$ca_serial" -CAcreateserial \
        -extfile "$ca_ext" -extensions v3_ca \
        -sha384 -out "$org_pem" >/dev/null 2>&1
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$user_key" >/dev/null 2>&1
    openssl req -new -key "$user_key" \
        -subj "/C=MX/ST=DF/L=Mexico City/O=$org_id/OU=Webmaster/CN=$user_id" \
        -sha384 -out "$user_req" >/dev/null 2>&1
    openssl x509 -req -days 3650 -in "$user_req" \
        -CA "$org_pem" -CAkey "$org_key" \
        -CAserial "$org_serial" -CAcreateserial \
        -extfile "$user_ext" -extensions usr_cert \
        -sha384 -out "$user_pem" >/dev/null 2>&1
    cat "$user_pem" "$org_pem" > "$chain"
    printf '%s\n%s\n' "$chain" "$user_key"
}

run_live_web_flow() {
    local protocol="$1"
    local port="$2"
    local service_log="$LOG_ROOT/live_${protocol}_service.log"
    local base_url
    local service_pid
    local protocol_label
    local org_name="${LIVE_FLOW_ID}_${protocol}_org"
    local org_key="${LIVE_FLOW_ID}${protocol}"
    local storage_name="${LIVE_FLOW_ID}_${protocol}_storage"
    local storage_path="$LOG_ROOT/live_${protocol}_storage"
    local csv_name="${LIVE_FLOW_ID}_${protocol}.csv"
    local large_csv_name="${LIVE_FLOW_ID}_${protocol}_large.csv"
    local column_doc_name="${LIVE_FLOW_ID}_${protocol}_columns.csv"
    local script_name="${LIVE_FLOW_ID}_${protocol}.pl"
    local perl_timeout_script_name="${LIVE_FLOW_ID}_${protocol}_timeout.pl"
    local perl_oversize_script_name="${LIVE_FLOW_ID}_${protocol}_oversize.pl"
    local python_script_name="${LIVE_FLOW_ID}_${protocol}.py"
    local python_timeout_script_name="${LIVE_FLOW_ID}_${protocol}_timeout.py"
    local python_oversize_script_name="${LIVE_FLOW_ID}_${protocol}_oversize.py"
    local python_network_script_name="${LIVE_FLOW_ID}_${protocol}_network.py"
    local python_outside_file_script_name="${LIVE_FLOW_ID}_${protocol}_outside_file.py"
    local python_pending_script_name="${LIVE_FLOW_ID}_${protocol}_pending.py"
    local python_pending_static_bad_script_name="${LIVE_FLOW_ID}_${protocol}_pending_static_bad.py"
    local python_unreviewed_script_name="${LIVE_FLOW_ID}_${protocol}_unreviewed.py"
    local perl_policy_meta="parser.reviewed:true parser.interpreter:/usr/bin/perl parser.timeout:10 parser.isolation:none"
    local python_policy_meta="parser.reviewed:true parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
    local python_pending_policy_meta="parser.reviewStatus:pending parser.generated:true parser.generator:llm-test parser.promptHash:sha256-demo parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none"
    local user_id="User123"
    local role_user="${LIVE_FLOW_ID}_${protocol}_user"
    local auth="userId=$user_id&orgId=$org_name&orgKey=$org_key"
    local long_query_value=""
    local upload_start=0
    local curl_tls_args=()
    local client_chain
    local client_key

    if [ "$protocol" = "https" ]; then
        base_url="https://localhost:$port"
        protocol_label="HTTPS"
        {
            read -r client_chain
            read -r client_key
        } < <(generate_live_client_cert_chain "$protocol" "$org_name" "$user_id")
        curl_tls_args=(--cacert "$PREFIX/cdse/ca.pem" --cert "$client_chain" --key "$client_key")
    else
        base_url="http://localhost:$port"
        protocol_label="HTTP"
    fi
    mkdir -p "$storage_path"

    note "RUN  live_${protocol}_api_flow"
    LIVE_FLOW_FAILED=0
    (
        cd "$ROOT_DIR" || exit 1
        if [ -n "$VERIFY_HERRADURAKEX_DEFAULT_PROFILE" ]; then
            export CDSE_DEFAULT_ENC_ALG="$VERIFY_HERRADURAKEX_DEFAULT_PROFILE"
        fi
        env CDSE_DEBUG_TEST_SKIP_AUTHZ=1 \
            CDSE_DEBUG_TEST_HTTP_PORT="$HTTP_PORT" \
            CDSE_DEBUG_TEST_HTTPS_PORT="$HTTPS_PORT" \
            CDSE_PARSER_NO_NEW_PRIVS="$VERIFY_PARSER_NO_NEW_PRIVS" \
            CDSE_PARSER_ISOLATE_NETWORK="$VERIFY_PARSER_NETWORK_ISOLATION" \
            CDSE_PARSER_CHROOT_PATH="${CDSE_VERIFY_PARSER_CHROOT_PATH:-}" \
            CDSE_PARSER_REQUIRE_REVIEWED="$VERIFY_PARSER_REQUIRE_REVIEWED" \
            CDSE_PARSER_REQUIRE_POLICY_PROFILES="$VERIFY_PARSER_REQUIRE_POLICY_PROFILES" \
            "$PREFIX/cdse/bin/CaumeDSE-debug-tests" --web-service "$protocol"
    ) > "$service_log" 2>&1 &
    service_pid=$!

    if ! wait_for_log_marker "$service_log" "CaumeDSE Debug: cmeWebServiceSetup(), $protocol_label server started on port $port." 20; then
        stop_live_service "$service_pid"
        redact_file_in_place "$service_log"
        record_fail "live_${protocol}_api_flow" "service did not start log=$service_log"
        record_hint "live_${protocol}_api_flow" "check webservice-startup-preflight.log, selected ${protocol} port $port, auto_ports=$VERIFY_AUTO_PORTS, and service log errno diagnostics"
        return 1
    fi

    live_api_check "$protocol" agent_capabilities 200 "$base_url/agentCapabilities" '"capabilityManifestVersion":1' "${curl_tls_args[@]}"
    live_api_check "$protocol" auth_missing_all 401 "$base_url/organizations/$org_name" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" auth_missing_org_key 401 "$base_url/organizations/$org_name?userId=$user_id&orgId=$org_name" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" json_error_auth_missing_org_key 401 "$base_url/organizations/$org_name?userId=$user_id&orgId=$org_name&outputType=json" '"code":"authentication_required"' "${curl_tls_args[@]}"
    live_api_check "$protocol" json_error_auth_request_id 401 "$base_url/organizations/$org_name?userId=$user_id&orgId=$org_name&outputType=json" '"requestId":"cdse-' "${curl_tls_args[@]}"
    long_query_value="$(printf '%*s' 1500 '' | tr ' ' 'x')"
    live_api_check "$protocol" transaction_log_redaction_probe 401 "$base_url/organizations/${org_name}_logProbe?orgId=$org_name&orgKey=$org_key&newOrgKey=$org_key&accessPassword=$org_key&longParam=$long_query_value" "" "${curl_tls_args[@]}" -H "Authorization: Bearer $org_key"
    if [ "$protocol" = "https" ]; then
        live_api_check "$protocol" auth_missing_client_cert 401 "$base_url/organizations/$org_name?$auth" "" --cacert "$PREFIX/cdse/ca.pem"
        live_api_check "$protocol" auth_client_cert_user_mismatch 401 "$base_url/organizations/$org_name?userId=${user_id}_mismatch&orgId=$org_name&orgKey=$org_key" "" "${curl_tls_args[@]}"
    fi

    live_api_check "$protocol" create_org 201 "$base_url/organizations/$org_name?$auth&*resourceInfo=live%20$protocol%20organization&*certificate=undefined&*publicKey=undefined&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" create_storage 201 "$base_url/organizations/$org_name/storage/$storage_name?$auth&newOrgKey=$org_key&*resourceInfo=live%20$protocol%20storage&*location=localhost&*type=local&*accessPath=$storage_path&*accessUser=undefined&*accessPassword=undefined" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" create_user 201 "$base_url/organizations/$org_name/users/$role_user?$auth&newOrgKey=$org_key&*resourceInfo=live%20$protocol%20user&*certificate=undefined&*publicKey=undefined&*basicAuthPwdHash=undefined&*oauthConsumerKey=undefined&*oauthConsumerSecret=undefined" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" document_types_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes?$auth&newOrgKey=$org_key" "file.csv" "${curl_tls_args[@]}"
    live_api_check "$protocol" document_types_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    live_api_check "$protocol" document_type_csv_head 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -I
    live_api_check "$protocol" document_type_unsupported 404 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/unsupported.type?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" json_error_not_found 404 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/unsupported.type?$auth&newOrgKey=$org_key&outputType=json" '"code":"not_found"' "${curl_tls_args[@]}"
    live_api_check "$protocol" role_table_post 201 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key&*_get=1&*_post=0&*_put=1&*_delete=0&*_head=1&*_options=1" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" role_table_get 200 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key" "$role_user" "${curl_tls_args[@]}"
    live_api_check "$protocol" role_table_json_get 200 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    live_api_check "$protocol" filter_whitelist_post 201 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key&*_get=1&*_post=0&*_put=0&*_delete=0&*_head=1&*_options=1" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" filter_whitelist_get 200 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key" "$role_user" "${curl_tls_args[@]}"
    live_api_check "$protocol" filter_whitelist_json_get 200 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    live_api_check "$protocol" filter_blacklist_post 201 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key&*_get=0&*_post=1&*_put=0&*_delete=0&*_head=0&*_options=0" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" filter_blacklist_get 200 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key" "$role_user" "${curl_tls_args[@]}"
    live_api_check "$protocol" filter_blacklist_json_get 200 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    upload_start="$(date +%s)"
    live_api_check "$protocol" upload_csv 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/live-api-small.csv" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol CSV"
    record_herradurakex_perf_smoke "$protocol" "small_csv_upload" "$ROOT_DIR/TEST/testfiles/live-api-small.csv" "$upload_start"
    if [ -n "$VERIFY_HERRADURAKEX_DIR" ]; then
        upload_start="$(date +%s)"
        live_api_check "$protocol" upload_herradurakex_large_csv 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$large_csv_name" "" "${curl_tls_args[@]}" \
            -F "file=@$ROOT_DIR/TEST/testfiles/randomdata-620_A.csv" \
            -F "userId=$user_id" \
            -F "orgId=$org_name" \
            -F "orgKey=$org_key" \
            -F "newOrgKey=$org_key" \
            -F "*resourceInfo=live $protocol Herradura large CSV"
        record_herradurakex_perf_smoke "$protocol" "large_csv_upload" "$ROOT_DIR/TEST/testfiles/randomdata-620_A.csv" "$upload_start"
    else
        record_skip "live_${protocol}_herradurakex_large_csv_upload" "HerraduraKEx provider not requested"
    fi
    live_api_check "$protocol" documents_list 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents?$auth&newOrgKey=$org_key" "$csv_name" "${curl_tls_args[@]}"
    live_api_check "$protocol" documents_json_list 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    live_api_check "$protocol" document_head 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -I
    live_api_check "$protocol" document_schema_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/schema?$auth&newOrgKey=$org_key" '"resource":"document"' "${curl_tls_args[@]}"
    live_api_check "$protocol" document_schema_parser_policy 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/schema?$auth&newOrgKey=$org_key" '"parserPolicy":' "${curl_tls_args[@]}"
    live_api_check "$protocol" content_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/content?$auth&newOrgKey=$org_key&outputType=csv" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" content_rows_options 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X OPTIONS
    live_api_check "$protocol" json_error_method_not_allowed 405 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows?$auth&newOrgKey=$org_key&outputType=json" '"code":"method_not_allowed"' "${curl_tls_args[@]}"
    live_api_check "$protocol" row_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows/1?$auth&newOrgKey=$org_key&outputType=csv" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" row_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows/1?$auth&newOrgKey=$org_key&outputType=json" '"name":"Jacob"' "${curl_tls_args[@]}"
    live_api_check "$protocol" row_json_pagination 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows/1?$auth&newOrgKey=$org_key&outputType=json&limit=1&offset=0" '"returnedRows":1' "${curl_tls_args[@]}"
    live_api_check "$protocol" row_json_bad_pagination 409 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows/1?$auth&newOrgKey=$org_key&outputType=json&limit=0" '"code":"conflict"' "${curl_tls_args[@]}"
    live_api_check "$protocol" content_columns_options 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentColumns?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X OPTIONS
    live_api_check "$protocol" column_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentColumns/name?$auth&newOrgKey=$org_key&outputType=csv" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" column_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentColumns/name?$auth&newOrgKey=$org_key&outputType=json" '"name":"Jacob"' "${curl_tls_args[@]}"
    live_api_check "$protocol" column_create_empty_doc 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$column_doc_name/contentColumns/Col1?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" column_delete_empty_doc 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$column_doc_name/contentColumns/Col1?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" db_names_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames?$auth&newOrgKey=$org_key" "$csv_name" "${curl_tls_args[@]}"
    live_api_check "$protocol" db_names_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    live_api_check "$protocol" db_tables_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables?$auth&newOrgKey=$org_key" "data" "${curl_tls_args[@]}"
    live_api_check "$protocol" db_tables_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables?$auth&newOrgKey=$org_key&outputType=json" '"rows":[' "${curl_tls_args[@]}"
    live_api_check "$protocol" table_schema_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/schema?$auth&newOrgKey=$org_key" '"resource":"dbTable"' "${curl_tls_args[@]}"
    live_api_check "$protocol" table_schema_row_count 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/schema?$auth&newOrgKey=$org_key" '"rowCount":' "${curl_tls_args[@]}"
    live_api_check "$protocol" table_row_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableRows/1?$auth&newOrgKey=$org_key" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" table_row_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableRows/1?$auth&newOrgKey=$org_key&outputType=json" '"name":"Jacob"' "${curl_tls_args[@]}"
    live_api_check "$protocol" table_column_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableColumns/name?$auth&newOrgKey=$org_key" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" table_column_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableColumns/name?$auth&newOrgKey=$org_key&outputType=json" '"name":"Jacob"' "${curl_tls_args[@]}"
    live_api_check "$protocol" db_browse_bad_row 403 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableRows/0?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" json_error_forbidden 403 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableRows/0?$auth&newOrgKey=$org_key&outputType=json" '"code":"forbidden"' "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.perl/documents/$script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test.pl" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol Perl script $perl_policy_meta"
    live_api_check "$protocol" parser_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$script_name?$auth&newOrgKey=$org_key&outputType=csv" "82400" "${curl_tls_args[@]}"
    live_api_check "$protocol" parser_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$script_name?$auth&newOrgKey=$org_key&outputType=json" '"salary":"82400"' "${curl_tls_args[@]}"
    live_api_check "$protocol" parser_missing_head 404 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/missing.pl?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}" -I
    live_api_check "$protocol" upload_perl_timeout_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.perl/documents/$perl_timeout_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_timeout.pl" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol timeout Perl script $perl_policy_meta"
    live_api_check "$protocol" perl_parser_timeout 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$perl_timeout_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_perl_oversize_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.perl/documents/$perl_oversize_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_oversize.pl" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol oversize Perl script $perl_policy_meta"
    live_api_check "$protocol" perl_parser_oversize 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$perl_oversize_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_python_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol Python script $python_policy_meta"
    live_api_check "$protocol" python_parser_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_script_name?$auth&newOrgKey=$org_key&outputType=csv" "82400" "${curl_tls_args[@]}"
    live_api_check "$protocol" python_parser_json_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_script_name?$auth&newOrgKey=$org_key&outputType=json" '"salary":"82400"' "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_python_pending_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_pending_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol pending generated Python script $python_pending_policy_meta"
    live_api_check "$protocol" python_parser_pending_full_denied 403 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_pending_script_name?$auth&newOrgKey=$org_key&outputType=json" '"code":"forbidden"' "${curl_tls_args[@]}"
    live_api_check "$protocol" python_parser_pending_preview 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_pending_script_name?$auth&newOrgKey=$org_key&outputType=json&previewOnly=1&previewRows=1&limit=1" '"returnedRows":1' "${curl_tls_args[@]}"
    check_live_mcp_readonly_smoke "$protocol" "$base_url" "$org_name" "$storage_name" "$user_id" "$org_key" "$csv_name" "$python_script_name" "$python_pending_script_name" "${client_chain:-}" "${client_key:-}"
    check_live_agent_rag_connector_smoke "$protocol" "$base_url" "$org_name" "$storage_name" "$user_id" "$org_key" "$csv_name" "${client_chain:-}" "${client_key:-}"
    live_api_check "$protocol" upload_python_pending_static_bad_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_pending_static_bad_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_network_access.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol pending static bad Python script $python_pending_policy_meta"
    live_api_check "$protocol" python_parser_pending_static_denied 403 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_pending_static_bad_script_name?$auth&newOrgKey=$org_key&outputType=json&previewOnly=1&previewRows=1" '"code":"forbidden"' "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_python_timeout_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_timeout_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_timeout.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol timeout Python script $python_policy_meta"
    live_api_check "$protocol" python_parser_timeout 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_timeout_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_python_oversize_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_oversize_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_oversize.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol oversize Python script $python_policy_meta"
    live_api_check "$protocol" python_parser_oversize 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_oversize_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    if parser_network_isolation_enabled; then
        if [ "$protocol" = "http" ]; then
            live_api_check "$protocol" upload_python_network_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_network_script_name" "" "${curl_tls_args[@]}" \
                -F "file=@$ROOT_DIR/TEST/testfiles/test_network_access.py" \
                -F "userId=$user_id" \
                -F "orgId=$org_name" \
                -F "orgKey=$org_key" \
                -F "newOrgKey=$org_key" \
                -F "*resourceInfo=live $protocol network isolation Python script $python_policy_meta"
            live_api_check "$protocol" python_parser_network_isolation 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_network_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
        else
            record_skip "live_${protocol}_python_parser_network_isolation" "network fixture targets HTTP port $HTTP_PORT"
        fi
    fi
    if parser_chroot_isolation_enabled; then
        live_api_check "$protocol" upload_python_outside_file_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_outside_file_script_name" "" "${curl_tls_args[@]}" \
            -F "file=@$ROOT_DIR/TEST/testfiles/test_outside_file_access.py" \
            -F "userId=$user_id" \
            -F "orgId=$org_name" \
            -F "orgKey=$org_key" \
            -F "newOrgKey=$org_key" \
            -F "*resourceInfo=live $protocol chroot isolation Python script $python_policy_meta"
        live_api_check "$protocol" python_parser_chroot_isolation 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_outside_file_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    fi
    if parser_review_policy_enabled; then
        live_api_check "$protocol" upload_python_unreviewed_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_unreviewed_script_name" "" "${curl_tls_args[@]}" \
            -F "file=@$ROOT_DIR/TEST/testfiles/test.py" \
            -F "userId=$user_id" \
            -F "orgId=$org_name" \
            -F "orgKey=$org_key" \
            -F "newOrgKey=$org_key" \
            -F "*resourceInfo=live $protocol unreviewed Python script"
        live_api_check "$protocol" python_parser_policy_unreviewed 403 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_unreviewed_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    fi
    check_live_herradurakex_storage_at_rest "$protocol" "$storage_path" "$csv_name" "$large_csv_name"
    live_api_check "$protocol" document_delete 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    if [ -n "$VERIFY_HERRADURAKEX_DIR" ]; then
        live_api_check "$protocol" herradurakex_large_document_delete 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$large_csv_name?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    fi
    live_api_check "$protocol" role_table_delete 200 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" filter_whitelist_delete 200 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" filter_blacklist_delete 200 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" delete_user 200 "$base_url/organizations/$org_name/users/$role_user?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE

    stop_live_service "$service_pid"
    check_live_debug_secret_redaction "$protocol" "$service_log" "$org_key"
    check_live_transaction_log_redaction "$protocol" "$org_key" "$long_query_value"
    check_live_structured_audit_redaction "$protocol" "$service_log" "$org_key"
    redact_file_in_place "$service_log"
    if [ "$protocol" = "http" ]; then
        if grep -Fq "HTTP TLS authentication bypass active for DEBUG/test profile only." "$service_log" &&
           grep -Fq "bypassing TLS authentication in an HTTP session (DEBUG/test profile only)." "$service_log"; then
            record_pass "live_http_tls_auth_bypass_diagnostic"
        else
            record_fail "live_http_tls_auth_bypass_diagnostic" "missing DEBUG/test bypass startup or request marker log=$service_log"
        fi
    fi
    if grep -Fq "CaumeDSE Audit: parserExecution event=policy-allow" "$service_log" &&
       grep -Fq "CaumeDSE Audit: parserExecution event=execute-success" "$service_log"; then
        record_pass "live_${protocol}_parser_audit"
    else
        record_fail "live_${protocol}_parser_audit" "missing parser audit markers log=$service_log"
    fi

    if [ "$LIVE_FLOW_FAILED" -eq 0 ]; then
        record_pass "live_${protocol}_api_flow"
        return 0
    fi
    record_fail "live_${protocol}_api_flow" "request flow failed log=$service_log meta=$LOG_ROOT/live_${protocol}_*.meta"
    return 1
}

note "CaumeDSE DEBUG component verification"
note "root=$ROOT_DIR"
note "prefix=$PREFIX"
note "logs=$LOG_ROOT"
note "http_port=$HTTP_PORT https_port=$HTTPS_PORT timeout=$RUN_TIMEOUT web_protocol=$WEB_PROTOCOL live_only=$LIVE_ONLY ci_smoke=$CI_SMOKE redact=$REDACT_OUTPUT"
if [ -n "$VERIFY_HERRADURAKEX_DIR" ]; then
    note "herradurakex_dir=$VERIFY_HERRADURAKEX_DIR default_profile=${VERIFY_HERRADURAKEX_DEFAULT_PROFILE:-<unset>}"
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
    CONFIGURE_ARGS=(./configure --prefix="$PREFIX" --enable-DEBUG --enable-TESTDATABASE --enable-BYPASSTLSAUTHINHTTP)
    if [ -n "$VERIFY_HERRADURAKEX_DIR" ]; then
        CONFIGURE_ARGS+=(--enable-HERRADURAKEX "--with-herradurakex=$VERIFY_HERRADURAKEX_DIR")
    fi
    run_release_bypass_config_guard || exit 1
    run_step configure "${CONFIGURE_ARGS[@]}" || exit 1
    run_step make_clean make clean || exit 1
    run_step make make || exit 1
    run_step make_check make check || exit 1
    run_step make_install make install || exit 1
else
    if [ "$LIVE_ONLY" -eq 1 ]; then
        record_skip configure "requested --live-only"
        record_skip make_clean "requested --live-only"
        record_skip make "requested --live-only"
        record_skip make_check "requested --live-only"
        record_skip make_install "requested --live-only"
    else
        record_skip configure "requested --skip-build"
        record_skip make_clean "requested --skip-build"
        record_skip make "requested --skip-build"
        record_skip make_check "requested --skip-build"
        record_skip make_install "requested --skip-build"
    fi
fi

if [ "$SKIP_WEB" -eq 0 ]; then
    if ! resolve_webservice_ports; then
        record_fail webservice_ports "could not select alternate webservice ports from HTTP=$HTTP_PORT HTTPS=$HTTPS_PORT search_limit=$VERIFY_PORT_SEARCH_LIMIT"
        record_hint webservice_ports "increase CDSE_VERIFY_PORT_SEARCH_LIMIT, set explicit CDSE_DEBUG_TEST_HTTP_PORT/CDSE_DEBUG_TEST_HTTPS_PORT, or free occupied local ports"
        exit 1
    fi
    write_webservice_startup_preflight
    if protocol_enabled http && ! valid_tcp_port "$HTTP_PORT"; then
        record_fail webservice_ports "HTTP port '$HTTP_PORT' is not a valid TCP port"
        record_hint webservice_ports "set CDSE_DEBUG_TEST_HTTP_PORT to an integer between 1 and 65535"
        exit 1
    fi
    if protocol_enabled https && ! valid_tcp_port "$HTTPS_PORT"; then
        record_fail webservice_ports "HTTPS port '$HTTPS_PORT' is not a valid TCP port"
        record_hint webservice_ports "set CDSE_DEBUG_TEST_HTTPS_PORT to an integer between 1 and 65535"
        exit 1
    fi
    if [ "$WEB_PROTOCOL" = "both" ] && [ "$HTTP_PORT" -eq "$HTTPS_PORT" ]; then
        record_fail webservice_ports "HTTP and HTTPS ports must be different"
        record_hint webservice_ports "set different CDSE_DEBUG_TEST_HTTP_PORT and CDSE_DEBUG_TEST_HTTPS_PORT values"
        exit 1
    fi
    if protocol_enabled http && port_in_use "$HTTP_PORT"; then
        record_fail webservice_ports "HTTP port $HTTP_PORT is already in use"
        record_hint webservice_ports "explicit HTTP port is occupied; unset CDSE_DEBUG_TEST_HTTP_PORT to allow auto fallback or choose another port"
        exit 1
    fi
    if protocol_enabled https && port_in_use "$HTTPS_PORT"; then
        record_fail webservice_ports "HTTPS port $HTTPS_PORT is already in use"
        record_hint webservice_ports "explicit HTTPS port is occupied; unset CDSE_DEBUG_TEST_HTTPS_PORT to allow auto fallback or choose another port"
        exit 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        record_fail live_web_api_prerequisites "curl is required for live HTTP(S) API flow checks"
        record_hint live_web_api_prerequisites "install curl or run with --skip-web when live API checks are not required"
        exit 1
    fi
else
    record_skip webservice_ports "requested --skip-web"
    record_skip webservice_startup_preflight "requested --skip-web"
fi

if command -v python3 >/dev/null 2>&1; then
    run_delegated_token_broker_self_test
    run_agent_rag_connector_self_test
    run_review_workspace_self_test
    run_audit_dashboard_self_test
    run_mcp_write_guard_self_test
    run_policy_authz_tester_self_test
    run_backup_restore_self_test
else
    record_skip delegated_token_broker_self_test "python3 not available"
    record_skip agent_rag_connector_self_test "python3 not available"
    record_skip review_workspace_self_test "python3 not available"
    record_skip audit_dashboard_self_test "python3 not available"
    record_skip mcp_write_guard_self_test "python3 not available"
    record_skip policy_authz_tester_self_test "python3 not available"
    record_skip backup_restore_self_test "python3 not available"
fi
run_webservice_preflight_self_test

FULL_LOG="$LOG_ROOT/full-debug-run.log"
if [ "$LIVE_ONLY" -eq 0 ]; then
    DEBUG_ENGINE_START="$(date +%s)"
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
                CDSE_DEBUG_TEST_SKIP_WEB=1 \
                timeout "$RUN_TIMEOUT" "$PREFIX/cdse/bin/CaumeDSE-debug-tests"
        fi
    ) > "$FULL_LOG" 2>&1
    ENGINE_RC=$?

    if [ "$ENGINE_RC" -eq 0 ]; then
        record_pass "debug_engine ($(elapsed_seconds "$DEBUG_ENGINE_START"))"
    else
        record_fail debug_engine "exit=$ENGINE_RC elapsed=$(elapsed_seconds "$DEBUG_ENGINE_START") log=$FULL_LOG"
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

check_component json_response_formatting 'Testing JSON response formatting|testJSONResponses|JSON outputType' "$FULL_LOG" \
    '--- Testing JSON response formatting:' \
    'TESTS: testJSONResponses(), PASS: table response JSON outputType.' \
    'TESTS: testJSONResponses(), PASS: count response JSON outputType.' \
    'TESTS: testJSONResponses(), PASS: JSON response formatting verified.'

check_component crypto_streaming '---ctSize|---etSize|Decrypted text|Unprotected text' "$FULL_LOG" \
    'TESTS: testCryptoSymmetric(), PASS: default PBKDF profile v3 uses HMAC-SHA256 count=10000.' \
    'TESTS: testCryptoSymmetric(), PASS: legacy PBKDF profile v2 decrypt fallback preserved old data.' \
    'Unprotected text: This is cleartext This is cleartext This is cleartext This is cleartext.'

check_herradurakex_component "$FULL_LOG"
check_herradurakex_independent_component "$FULL_LOG"
check_key_rotation_component "$FULL_LOG"
check_key_rotation_herradurakex_component "$FULL_LOG"

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

check_component storage_document_tree_dispatch 'Testing storage document tree dispatcher routing|testStorageDocumentTree|documentTypes/documents dispatcher' "$FULL_LOG" \
    '--- Testing storage document tree dispatcher routing:' \
    'TESTS: testStorageDocumentTree(), PASS: documentTypes class dispatch GET responseCode=200' \
    'TESTS: testStorageDocumentTree(), PASS: documentType resource dispatch GET responseCode=200' \
    'TESTS: testStorageDocumentTree(), PASS: documents class dispatch OPTIONS responseCode=200' \
    'TESTS: testStorageDocumentTree(), PASS: document resource dispatch OPTIONS responseCode=200' \
    'TESTS: testStorageDocumentTree(), PASS: documentTypes/documents dispatcher routing verified.'

check_component parser_scripts_resource 'Testing parserScripts resource handlers|testParserScripts|parserScripts' "$FULL_LOG" \
    '--- Testing parserScripts resource handlers:' \
    'TESTS: testParserScripts(), PASS: parserScripts class OPTIONS responseCode=200' \
    'TESTS: testParserScripts(), PASS: parserScripts resource OPTIONS responseCode=200' \
    'TESTS: testParserScripts(), PASS: parserScripts missing script HEAD responseCode=404' \
    'TESTS: testParserScripts(), PASS: class options and missing script handling verified.'

check_component parser_temp_files 'Testing parser temporary file hardening|testParserTempFiles|parser temp' "$FULL_LOG" \
    '--- Testing parser temporary file hardening:' \
    'PASS: parser temp file created as 0600 regular file.' \
    'TESTS: testParserTempFiles(), PASS: parser temp directory is private.' \
    'TESTS: testParserTempFiles(), PASS: exclusive parser temp creation avoided collision.' \
    'TESTS: testParserTempFiles(), PASS: symlink temp directory was refused.' \
    'TESTS: testParserTempFiles(), PASS: cleanup, collision handling, and symlink refusal verified.'

check_component content_rows_resource 'Testing contentRows resource handlers|testContentRows|contentRows' "$FULL_LOG" \
    '--- Testing contentRows resource handlers:' \
    'TESTS: testContentRows(), PASS: contentRows class OPTIONS responseCode=200' \
    'TESTS: testContentRows(), PASS: contentRows row GET responseCode=200' \
    'TESTS: testContentRows(), PASS: contentRows append POST responseCode=201' \
    'TESTS: testContentRows(), PASS: contentRows appended DELETE responseCode=200' \
    'TESTS: testContentRows(), PASS: row get/append/update/delete/options verified.'

check_component content_columns_resource 'Testing contentColumns resource handlers|testContentColumns|contentColumns' "$FULL_LOG" \
    '--- Testing contentColumns resource handlers:' \
    'TESTS: testContentColumns(), PASS: column get/create/delete/options and edge cases verified.'

check_component db_browsing_resource 'Testing dbNames secure DB browsing resource handlers|testDBBrowsing|dbNames|dbTables|tableRows|tableColumns' "$FULL_LOG" \
    '--- Testing dbNames secure DB browsing resource handlers:' \
    'TESTS: testDBBrowsing(), PASS: dbNames class GET responseCode=200' \
    'TESTS: testDBBrowsing(), PASS: dbTables class GET responseCode=200' \
    'TESTS: testDBBrowsing(), PASS: tableRow resource GET responseCode=200' \
    'TESTS: testDBBrowsing(), PASS: dbNames/dbTables/tableRows/tableColumns browsing verified.'

if bash "$ROOT_DIR/TEST/validate_openapi_routes.sh" > "$LOG_ROOT/openapi-validation.log" 2>&1; then
    record_pass "openapi_route_reference"
else
    record_fail "openapi_route_reference" "see $LOG_ROOT/openapi-validation.log"
fi

check_component sqlite_thread_safety 'Testing thread safety|Thread safety test|test_thread_' "$FULL_LOG" \
    '--- Thread safety test: PASSED'

check_component csv_securedb_roundtrip 'CSV file to secure DB|AcmeIncPayroll.csv|Retrieved data from secure table|Omar|Pablo' "$FULL_LOG" \
    '--- Retrieved data from secure table (CSV file to secure DB):' \
    '[10][10][Pablo][Martinez][14000.5]' \
    'TESTS: testCSV(), PASS: secure DB replacement removed old column files from non-default storage path.'

check_component memtable_securedb_roundtrip 'Memory Table to secure DB|AcmeIncPayroll Tests.csv|Retrieved data from secure table' "$FULL_LOG" \
    '--- Retrieved data from secure table (Memory Table to secure DB):' \
    '[10][10][Pablo][Martinez][14000.5]'

check_component mac_macprotected 'MAC and MACProtected|MACProtected test|verified MACProtected|Retrieved data from secure table' "$FULL_LOG" \
    '--- Testing MAC and MACProtected column attributes:' \
    "--- Retrieved data from secure table (MAC+MACProtected test):" \
    "verified MACProtected for 'value' in row id 10."
else
    record_skip debug_engine "requested --live-only"
    record_skip component_markers "requested --live-only"
fi

if [ "$SKIP_WEB" -eq 0 ]; then
    if [ "$LIVE_ONLY" -eq 0 ]; then
        check_component webservice_startup 'Testing Web server|cmeLoadStrFromFile|server.key|server.pem|ca.pem|webservice' "$FULL_LOG" \
            "--- Testing Web server HTTP port $HTTP_PORT" \
            "--- Testing Web server HTTPS port $HTTPS_PORT" \
            "TESTS: testWebServices(), PASS: HTTP startup" \
            "TESTS: testWebServices(), PASS: HTTPS startup"
        for marker in "$PREFIX/cdse/server.key" "$PREFIX/cdse/server.pem" "$PREFIX/cdse/ca.pem"; do
            if certificate_read_marker_seen "$FULL_LOG" "$marker"; then
                :
            else
                record_fail webservice_certificate_loading "missing nonzero read marker for $marker"
            fi
        done
        run_https_startup_failure_redaction_check
    else
        record_skip webservice_startup "requested --live-only"
        record_skip webservice_certificate_loading "requested --live-only"
        record_skip https_startup_failure_redaction "requested --live-only"
    fi
    if protocol_enabled http; then
        run_live_web_flow http "$HTTP_PORT"
    else
        record_skip live_http_api_flow "not selected by --web-protocol=$WEB_PROTOCOL"
    fi
    if protocol_enabled https; then
        run_live_web_flow https "$HTTPS_PORT"
    else
        record_skip live_https_api_flow "not selected by --web-protocol=$WEB_PROTOCOL"
    fi
else
    record_skip webservice_startup "requested --skip-web"
    record_skip https_startup_failure_redaction "requested --skip-web"
    record_skip live_http_api_flow "requested --skip-web"
    record_skip live_https_api_flow "requested --skip-web"
fi

redact_file_in_place "$FULL_LOG"
append_live_coverage_summary
note "RESULT passed=$PASSED failed=$FAILED skipped=$SKIPPED"
note "summary=$SUMMARY_FILE"
note "full_log=$FULL_LOG"

if [ "$FAILED" -eq 0 ]; then
    exit 0
fi
exit 1
