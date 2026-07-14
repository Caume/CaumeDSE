# Repository Guidelines

## Project Structure & Module Organization

CaumeDSE is a C/autotools project. Core source and headers live at the
repository root, including `main.c`, `crypto.c`, `db.c`, `filehandling.c`,
`engine_admin.c`, `engine_interface.c`, and `webservice_interface.c`. DEBUG and
component coverage lives in `debug_tests.c` and `function_tests.c`. Test assets,
certificates, fixtures, and verifier scripts are under `TEST/`; examples for
external clients are under `samples/`. User-facing documentation is in
`README.md`, `TUTORIAL.md`, `API_EXAMPLES.md`, and `TODO.md`.

## Build, Test, and Development Commands

- `./configure --enable-DEBUG --enable-TESTDATABASE --enable-BYPASSTLSAUTHINHTTP`
  configures a DEBUG build with committed test databases and HTTP TLS-auth
  bypass for local verification.
- `make` builds `CaumeDSE` and `CaumeDSE-debug-tests`.
- `make check` runs the autotools check target.
- `TEST/run_debug_components.sh` performs the full build/install/component/live
  verifier flow under `/tmp/cdse-verify`.
- `TEST/run_debug_components.sh --skip-build --skip-web` reruns component checks
  against an existing build without binding web ports.
- `TEST/run_debug_components.sh --live-only --web-protocol=http|https` reruns a
  focused live API flow and writes `live-api-coverage.csv`.
- `TEST/run_debug_components.sh --ci-smoke` runs the CI-friendly build,
  component-marker, startup, and single-protocol live profile.

## Coding Style & Naming Conventions

Follow the existing C style: four-space indentation, braces on their own lines
for functions and larger blocks, `cme`-prefixed functions, and explicit cleanup
paths. Prefer existing helpers such as `cmeMalloc`, `cmeFree`,
`cmeStrConstrAppend`, storage wrappers, and SQL helper functions. Keep comments
short and useful; avoid broad refactors in focused fixes.

## Testing Guidelines

Add or update DEBUG component checks for C behavior and live verifier checks for
HTTP(S) API behavior. Keep test fixtures in `TEST/testfiles/`. Validate shell
changes with `bash -n TEST/run_debug_components.sh`. For live API work, run at
least the focused HTTP and HTTPS verifier modes when practical.

## Commit & Pull Request Guidelines

Use concise, imperative commit messages matching recent history, for example
`Add live negative auth checks` or `Harden parser script limits`. Keep generated
build artifacts (`*.o`, `.deps/`, `config.log`, binaries) out of commits unless
explicitly required. Pull requests should summarize behavior changes, security
impact, touched routes/files, and exact validation commands with pass/fail
counts.

## Security & Configuration Tips

Do not commit real organization keys, private certificates, or production data.
Use the committed `TEST/testCertAuth/` fixtures only for DEBUG verification.
Production deployments should use HTTPS, restricted data directories, protected
key handling outside CaumeDSE, and no DEBUG authentication bypasses.
