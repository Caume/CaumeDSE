#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
BUILD_DIR=${CDSE_FUZZ_BUILD_DIR:-/tmp/cdse-fuzz-build}
MAX_TOTAL_TIME=${CDSE_FUZZ_MAX_TOTAL_TIME:-5}
CC_BIN=${CC:-clang}

if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    printf 'SKIP: fuzz compiler %s is not available.\n' "$CC_BIN"
    exit 0
fi

if [ ! -f "$REPO_ROOT/config.h" ]; then
    printf 'SKIP: config.h is missing; run ./configure before fuzz smoke.\n'
    exit 0
fi

if [ ! -f "$REPO_ROOT/xs_init.c" ]; then
    make -C "$REPO_ROOT" xs_init.c >/dev/null
fi

mkdir -p "$BUILD_DIR"

PERL_CCOPTS=$("$REPO_ROOT/config.status" --config 2>/dev/null | sed -n "s/^'PERL_CCOPTS'='\\(.*\\)'$/\\1/p" || true)
if [ -z "$PERL_CCOPTS" ]; then
    PERL_CCOPTS=$(perl -MExtUtils::Embed -e ccopts)
fi
PERL_LDOPTS=$(perl -MExtUtils::Embed -e ldopts)

COMMON_SOURCES=(
    "$REPO_ROOT/config.c"
    "$REPO_ROOT/crypto.c"
    "$REPO_ROOT/db.c"
    "$REPO_ROOT/engine_admin.c"
    "$REPO_ROOT/engine_interface.c"
    "$REPO_ROOT/filehandling.c"
    "$REPO_ROOT/perl_interpreter.c"
    "$REPO_ROOT/runtime.c"
    "$REPO_ROOT/strhandling.c"
    "$REPO_ROOT/webservice_interface.c"
    "$REPO_ROOT/xs_init.c"
)

HARNESSES=(
    "url_request"
    "csv_rows"
    "response_format"
)

BASE_FLAGS=(
    -I"$REPO_ROOT"
    -DHAVE_CONFIG_H
    -DCDSE_FUZZING
    -DDEBUG
    -DPURIFY
    -DSQLITE_SECURE_DELETE
    -g
    -O1
    -fno-omit-frame-pointer
    -Wall
)

BASE_LIBS=(
    -lcrypto
    -ldl
    -lm
    -lmicrohttpd
    -lnsl
    -lpthread
    -lutil
    -lgnutls
    -lsqlite3
    -lcrypt
)

if printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s){return 0;}\n' |
   "$CC_BIN" -x c -fsanitize=fuzzer,address,undefined -o "$BUILD_DIR/libfuzzer-check" - >/dev/null 2>&1; then
    FUZZ_MODE=libfuzzer
    FUZZ_FLAGS=(-fsanitize=fuzzer,address,undefined)
else
    FUZZ_MODE=standalone
    FUZZ_FLAGS=(-fsanitize=address,undefined -DCDSE_FUZZ_STANDALONE)
fi

printf 'CaumeDSE fuzz smoke mode: %s\n' "$FUZZ_MODE"

export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}
export UBSAN_OPTIONS=${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}

OBJECTS=()
for src in "${COMMON_SOURCES[@]}"; do
    obj="$BUILD_DIR/$(basename "$src" .c).o"
    # shellcheck disable=SC2086
    "$CC_BIN" "${BASE_FLAGS[@]}" $PERL_CCOPTS -fsanitize=address,undefined \
        -c "$src" -o "$obj"
    OBJECTS+=("$obj")
done

for harness in "${HARNESSES[@]}"; do
    src="$SCRIPT_DIR/${harness}_fuzzer.c"
    bin="$BUILD_DIR/${harness}_fuzzer"
    corpus="$SCRIPT_DIR/corpus/$harness"
    run_corpus="$BUILD_DIR/corpus/$harness"

    rm -rf "$run_corpus"
    mkdir -p "$run_corpus"
    cp "$corpus"/* "$run_corpus"/

    # shellcheck disable=SC2086
    "$CC_BIN" "${BASE_FLAGS[@]}" $PERL_CCOPTS "${FUZZ_FLAGS[@]}" \
        -o "$bin" "$src" "${OBJECTS[@]}" $PERL_LDOPTS "${BASE_LIBS[@]}"

    if [ "$FUZZ_MODE" = "libfuzzer" ]; then
        if ! "$bin" -runs=0 "$run_corpus" >"$BUILD_DIR/${harness}-merge.log" 2>&1; then
            tail -n 80 "$BUILD_DIR/${harness}-merge.log"
            exit 1
        fi
        if ! "$bin" -max_total_time="$MAX_TOTAL_TIME" "$run_corpus" >"$BUILD_DIR/${harness}.log" 2>&1; then
            tail -n 120 "$BUILD_DIR/${harness}.log"
            exit 1
        fi
    else
        if ! "$bin" "$run_corpus"/* >"$BUILD_DIR/${harness}.log" 2>&1; then
            tail -n 120 "$BUILD_DIR/${harness}.log"
            exit 1
        fi
    fi
    printf 'PASS: %s fuzz smoke (%s)\n' "$harness" "$BUILD_DIR/${harness}.log"
done
