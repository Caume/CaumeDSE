# CaumeDSE Fuzz Harnesses

These harnesses exercise low-state parsing and formatting paths that are useful
to fuzz without starting a web service:

- `url_request_fuzzer.c`: URL tokenization, query/header pair parsing, and
  request unsafe-character validation.
- `csv_rows_fuzzer.c`: CSV row loading with and without column headers.
- `response_format_fuzzer.c`: table/count response formatting for HTML, CSV,
  JSON, and unsupported `outputType` values.

Run from a configured tree:

```sh
./configure --enable-DEBUG --enable-TESTDATABASE --enable-BYPASSTLSAUTHINHTTP
make
TEST/fuzz/run_fuzz_smoke.sh
```

`run_fuzz_smoke.sh` prefers `clang -fsanitize=fuzzer,address,undefined` and runs
each seed corpus for a bounded time. If libFuzzer is unavailable, it falls back
to AddressSanitizer/UndefinedBehaviorSanitizer standalone seed execution. Set
`CDSE_FUZZ_MAX_TOTAL_TIME=N` to adjust the per-harness libFuzzer smoke duration
and `CDSE_FUZZ_BUILD_DIR=/path` to choose the output directory.

Do not commit generated corpora, crash reproducers, or binaries from fuzz runs.
When a crash is found, minimize it, add a small regression seed or DEBUG test,
and keep the committed fixture free of real organization keys or private data.
