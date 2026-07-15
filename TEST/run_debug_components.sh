#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${CDSE_VERIFY_PREFIX:-/tmp/cdse-verify}"
LOG_ROOT="${CDSE_VERIFY_LOG_DIR:-/tmp/cdse-debug-components-$(date +%Y%m%d-%H%M%S)}"
HTTP_PORT="${CDSE_DEBUG_TEST_HTTP_PORT:-18080}"
HTTPS_PORT="${CDSE_DEBUG_TEST_HTTPS_PORT:-18443}"
RUN_TIMEOUT="${CDSE_DEBUG_TEST_TIMEOUT:-120s}"
SKIP_BUILD=0
SKIP_WEB=0
LIVE_ONLY=0
WEB_PROTOCOL="both"
WEB_PROTOCOL_SET=0
CI_SMOKE=0
LIVE_FLOW_ID="liveflow$$"
REDACT_OUTPUT="${CDSE_VERIFY_REDACT:-0}"

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
    printf '  CDSE_VERIFY_REDACT         redact live verifier secrets from summaries and artifacts when set to 1/true/on\n'
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

check_required() {
    local log="$1"
    local marker="$2"
    grep -Fq -- "$marker" "$log"
}

check_forbidden() {
    local log="$1"
    grep -Eq 'CaumeDSE Error|FAILED|FAIL:|Segmentation fault|Assertion .*failed|assertion .*failed|core dumped|timeout: the monitored command dumped core' "$log"
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
    local column_doc_name="${LIVE_FLOW_ID}_${protocol}_columns.csv"
    local script_name="${LIVE_FLOW_ID}_${protocol}.pl"
    local python_script_name="${LIVE_FLOW_ID}_${protocol}.py"
    local python_timeout_script_name="${LIVE_FLOW_ID}_${protocol}_timeout.py"
    local python_oversize_script_name="${LIVE_FLOW_ID}_${protocol}_oversize.py"
    local user_id="User123"
    local role_user="${LIVE_FLOW_ID}_${protocol}_user"
    local auth="userId=$user_id&orgId=$org_name&orgKey=$org_key"
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
        env CDSE_DEBUG_TEST_SKIP_AUTHZ=1 \
            CDSE_DEBUG_TEST_HTTP_PORT="$HTTP_PORT" \
            CDSE_DEBUG_TEST_HTTPS_PORT="$HTTPS_PORT" \
            "$PREFIX/cdse/bin/CaumeDSE-debug-tests" --web-service "$protocol"
    ) > "$service_log" 2>&1 &
    service_pid=$!

    if ! wait_for_log_marker "$service_log" "CaumeDSE Debug: cmeWebServiceSetup(), $protocol_label server started on port $port." 20; then
        stop_live_service "$service_pid"
        redact_file_in_place "$service_log"
        record_fail "live_${protocol}_api_flow" "service did not start log=$service_log"
        return 1
    fi

    live_api_check "$protocol" auth_missing_all 401 "$base_url/organizations/$org_name" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" auth_missing_org_key 401 "$base_url/organizations/$org_name?userId=$user_id&orgId=$org_name" "" "${curl_tls_args[@]}"
    if [ "$protocol" = "https" ]; then
        live_api_check "$protocol" auth_missing_client_cert 401 "$base_url/organizations/$org_name?$auth" "" --cacert "$PREFIX/cdse/ca.pem"
        live_api_check "$protocol" auth_client_cert_user_mismatch 401 "$base_url/organizations/$org_name?userId=${user_id}_mismatch&orgId=$org_name&orgKey=$org_key" "" "${curl_tls_args[@]}"
    fi

    live_api_check "$protocol" create_org 201 "$base_url/organizations/$org_name?$auth&*resourceInfo=live%20$protocol%20organization&*certificate=undefined&*publicKey=undefined&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" create_storage 201 "$base_url/organizations/$org_name/storage/$storage_name?$auth&newOrgKey=$org_key&*resourceInfo=live%20$protocol%20storage&*location=localhost&*type=local&*accessPath=$storage_path&*accessUser=undefined&*accessPassword=undefined" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" create_user 201 "$base_url/organizations/$org_name/users/$role_user?$auth&newOrgKey=$org_key&*resourceInfo=live%20$protocol%20user&*certificate=undefined&*publicKey=undefined&*basicAuthPwdHash=undefined&*oauthConsumerKey=undefined&*oauthConsumerSecret=undefined" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" document_types_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes?$auth&newOrgKey=$org_key" "file.csv" "${curl_tls_args[@]}"
    live_api_check "$protocol" document_type_csv_head 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -I
    live_api_check "$protocol" document_type_unsupported 404 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/unsupported.type?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" role_table_post 201 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key&*_get=1&*_post=0&*_put=1&*_delete=0&*_head=1&*_options=1" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" role_table_get 200 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key" "$role_user" "${curl_tls_args[@]}"
    live_api_check "$protocol" filter_whitelist_post 201 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key&*_get=1&*_post=0&*_put=0&*_delete=0&*_head=1&*_options=1" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" filter_whitelist_get 200 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key" "$role_user" "${curl_tls_args[@]}"
    live_api_check "$protocol" filter_blacklist_post 201 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key&*_get=0&*_post=1&*_put=0&*_delete=0&*_head=0&*_options=0" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" filter_blacklist_get 200 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key" "$role_user" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_csv 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/live-api-small.csv" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol CSV"
    live_api_check "$protocol" documents_list 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents?$auth&newOrgKey=$org_key" "$csv_name" "${curl_tls_args[@]}"
    live_api_check "$protocol" document_head 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -I
    live_api_check "$protocol" content_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/content?$auth&newOrgKey=$org_key&outputType=csv" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" content_rows_options 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X OPTIONS
    live_api_check "$protocol" row_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentRows/1?$auth&newOrgKey=$org_key&outputType=csv" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" content_columns_options 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentColumns?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X OPTIONS
    live_api_check "$protocol" column_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/contentColumns/name?$auth&newOrgKey=$org_key&outputType=csv" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" column_create_empty_doc 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$column_doc_name/contentColumns/Col1?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X POST
    live_api_check "$protocol" column_delete_empty_doc 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$column_doc_name/contentColumns/Col1?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" db_names_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames?$auth&newOrgKey=$org_key" "$csv_name" "${curl_tls_args[@]}"
    live_api_check "$protocol" db_tables_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables?$auth&newOrgKey=$org_key" "data" "${curl_tls_args[@]}"
    live_api_check "$protocol" table_row_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableRows/1?$auth&newOrgKey=$org_key" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" table_column_get 200 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableColumns/name?$auth&newOrgKey=$org_key" "Jacob" "${curl_tls_args[@]}"
    live_api_check "$protocol" db_browse_bad_row 403 "$base_url/organizations/$org_name/storage/$storage_name/dbNames/$csv_name/dbTables/data/tableRows/0?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.perl/documents/$script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test.pl" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol Perl script"
    live_api_check "$protocol" parser_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$script_name?$auth&newOrgKey=$org_key&outputType=csv" "82400" "${curl_tls_args[@]}"
    live_api_check "$protocol" parser_missing_head 404 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/missing.pl?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}" -I
    live_api_check "$protocol" upload_python_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol Python script"
    live_api_check "$protocol" python_parser_get 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_script_name?$auth&newOrgKey=$org_key&outputType=csv" "82400" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_python_timeout_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_timeout_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_timeout.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol timeout Python script"
    live_api_check "$protocol" python_parser_timeout 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_timeout_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" upload_python_oversize_script 201 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/script.python/documents/$python_oversize_script_name" "" "${curl_tls_args[@]}" \
        -F "file=@$ROOT_DIR/TEST/testfiles/test_oversize.py" \
        -F "userId=$user_id" \
        -F "orgId=$org_name" \
        -F "orgKey=$org_key" \
        -F "newOrgKey=$org_key" \
        -F "*resourceInfo=live $protocol oversize Python script"
    live_api_check "$protocol" python_parser_oversize 500 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name/parserScripts/$python_oversize_script_name?$auth&newOrgKey=$org_key&outputType=csv" "" "${curl_tls_args[@]}"
    live_api_check "$protocol" document_delete 200 "$base_url/organizations/$org_name/storage/$storage_name/documentTypes/file.csv/documents/$csv_name?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" role_table_delete 200 "$base_url/organizations/$org_name/users/$role_user/roleTables/users?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" filter_whitelist_delete 200 "$base_url/organizations/$org_name/users/$role_user/filterWhitelist/$role_user?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" filter_blacklist_delete 200 "$base_url/organizations/$org_name/users/$role_user/filterBlacklist/$role_user?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE
    live_api_check "$protocol" delete_user 200 "$base_url/organizations/$org_name/users/$role_user?$auth&newOrgKey=$org_key" "" "${curl_tls_args[@]}" -X DELETE

    stop_live_service "$service_pid"
    redact_file_in_place "$service_log"

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

if [ "$SKIP_BUILD" -eq 0 ]; then
    run_step configure ./configure --prefix="$PREFIX" --enable-DEBUG --enable-TESTDATABASE --enable-BYPASSTLSAUTHINHTTP || exit 1
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
    if protocol_enabled http && ! valid_tcp_port "$HTTP_PORT"; then
        record_fail webservice_ports "HTTP port '$HTTP_PORT' is not a valid TCP port"
        exit 1
    fi
    if protocol_enabled https && ! valid_tcp_port "$HTTPS_PORT"; then
        record_fail webservice_ports "HTTPS port '$HTTPS_PORT' is not a valid TCP port"
        exit 1
    fi
    if [ "$WEB_PROTOCOL" = "both" ] && [ "$HTTP_PORT" -eq "$HTTPS_PORT" ]; then
        record_fail webservice_ports "HTTP and HTTPS ports must be different"
        exit 1
    fi
    if protocol_enabled http && port_in_use "$HTTP_PORT"; then
        record_fail webservice_ports "HTTP port $HTTP_PORT is already in use"
        exit 1
    fi
    if protocol_enabled https && port_in_use "$HTTPS_PORT"; then
        record_fail webservice_ports "HTTPS port $HTTPS_PORT is already in use"
        exit 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        record_fail live_web_api_prerequisites "curl is required for live HTTP(S) API flow checks"
        exit 1
    fi
else
    record_skip webservice_ports "requested --skip-web"
fi

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
            if grep -E "read [1-9][0-9]* bytes from file " "$FULL_LOG" | grep -Fq -- "$marker"; then
                :
            else
                record_fail webservice_certificate_loading "missing nonzero read marker for $marker"
            fi
        done
    else
        record_skip webservice_startup "requested --live-only"
        record_skip webservice_certificate_loading "requested --live-only"
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
