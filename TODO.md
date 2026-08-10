# TODO

## Speed Optimizations That Preserve Security and Integrity

- [x] #1 Add deterministic protected lookup columns for searchable encrypted fields.
  - Target fields include `documentId`, `orgResourceId`, `storageId`, `type`, and user/organization identifiers used in filters.
  - Use a keyed blind index such as `HMAC(searchKey, fieldName || "\0" || plaintext)` and add SQLite indexes over those lookup columns.
  - Keep encrypted values, salts, and MAC verification unchanged.
  - Done: safer default lookup columns are applied only to `documentId`, `orgResourceId`, and `storageId` in ResourcesDB documents.

- [x] #2 Replace generated hot-loop INSERT/UPDATE SQL strings with prepared statements.
  - Use `sqlite3_prepare_v2`, `sqlite3_bind_*`, `sqlite3_step`, and `sqlite3_reset` in bulk insert/update loops.
  - Preserve existing transaction boundaries where immediate consistency requires them.
  - Done: `db.c` memory table insert and secure DB protect/unprotect update loops now use prepared statements.
  - Done: `filehandling.c` CSV and memory-table import insert builders for `meta` and `data` tables now use prepared statements.

- [x] #3 Replace request spin/yield waits with event-driven synchronization.
  - Current `sleep(cmeDefaultThreadWaitSeconds)` loops can become busy-yield loops when the wait value is zero.
  - Prefer libmicrohttpd request lifecycle handling or `pthread_cond_t` signaling.
  - Done: POST request status handoff now uses per-connection `pthread_cond_t` signaling instead of `sleep(0)` loops.

- [x] #4 Narrow the parser script Perl mutex.
  - Keep shared Perl interpreter calls serialized.
  - Move DB/file work, secure DB reconstruction, response construction, and cleanup outside the global Perl lock where possible.
  - Done: parser-script GET/HEAD now perform DB/file work before the lock, serialize only shared Perl interpreter parse/callback execution, and release the lock before response construction and cleanup.

- [x] #5 Avoid reapplying SQLite PRAGMAs on every DB open.
  - Split memory DB and file DB open setup.
  - Apply WAL/synchronous/cache settings only where they are useful and check PRAGMA errors.
  - Done: memory DB opens now bypass file-backed PRAGMAs, file create/open setup checks PRAGMA errors, and regular DB opens no longer reapply WAL mode.

- [x] #6 Cache logs table schema validation.
  - Validate/create the transactions table at startup or first use under a mutex.
  - Continue writing each log record immediately.
  - Done: logs transaction table validation now runs once per process under a mutex, recreates the table when the expected schema is missing, and leaves each log write as an immediate durable insert.

- [x] #7 Increase streaming and POST chunk sizes.
  - Raise POST processing buffer to reduce callback overhead.
  - Raise response callback page size for large responses.

- [x] #8 Batch only in-memory transformations before immediate durable saves.
  - Combine related temporary memory DB updates with prepared statements or a transaction.
  - Do not defer protected file/resources DB writes after a logical change.
  - Done: secure DB protection now batches initial data salt updates in one in-memory transaction; duplicate-column reintegration already copies rows with a prepared statement inside one in-memory transaction.

- [x] #9 Add an independent component verification script for DEBUG builds.
  - Create a script such as `TEST/run_debug_components.sh` that configures a DEBUG/TESTDATABASE install under `/tmp`, builds, installs, runs the engine non-interactively, and writes one log per component.
  - Split validation into explicit component checks instead of relying on one monolithic debug log: crypto GCM byte-string round trip, streaming symmetric crypto, digest, HMAC/PBKDF, Perl interpreter calls, engine/admin DB setup, SQLite thread safety, CSV-to-secure-DB round trip, memory-table-to-secure-DB round trip, MAC/MACProtected integrity verification, and HTTP/HTTPS web-service startup.
  - Treat each component as pass/fail by checking command exit codes plus required log markers and forbidden markers such as `CaumeDSE Error`, `FAILED`, `FAIL:`, `can't start`, crashes, assertion failures, and timeouts.
  - Run web-service checks through an approved/unsandboxed command path or a clearly documented mode because libmicrohttpd must bind local ports; fail early if the selected ports are occupied.
  - Produce a concise final summary with component names, status, log paths, elapsed time, and the first failing marker so regressions do not require manually reading the full DEBUG output.
  - Implemented in `TEST/run_debug_components.sh`.
  - Longer-term: move DEBUG tests out of `main.c` into a dedicated test executable or selectable test harness so each unit/component can run independently without starting unrelated subsystems.

- [x] #10 Migrate `ChangeLog` to GitHub-compatible Markdown.
  - Preserve the existing chronological history and author/date information.
  - Convert entries to Markdown headings and bullet lists that render cleanly on GitHub.
  - Keep GNU-style file/function references readable, using backticks for paths, symbols, commands, and literal values.
  - Add a short compatibility note if the canonical file name changes from `ChangeLog` to `CHANGELOG.md`, and update packaging or release references that still expect the old name.
  - Done: `CHANGELOG.md` is now the canonical Markdown changelog, `ChangeLog` remains as a compatibility pointer, and distribution metadata includes the Markdown file.

- [x] #11 Migrate `README` to GitHub-compatible Markdown.
  - Preserve the current installation, configuration, architecture, security, API, and examples content.
  - Convert plain-text section numbering to Markdown headings, lists, tables, and fenced code blocks where appropriate.
  - Keep command examples copy/paste-safe and annotate shell, SQL, C, JSON, Perl, or configuration snippets with fenced-code language tags when known.
  - Rename to `README.md` only after checking build, packaging, and distribution references that may still point to `README`.
  - Done: `README.md` is now the canonical Markdown README, `README` remains as a compatibility pointer, and distribution metadata includes the Markdown file.

- [x] #12 Finish and verify `/organizations/{organization}/users/{user}/roleTables` resources.
  - Review the existing `roleTables` URL routing and RolesDB table handling to identify whether the README marker is stale or the feature is only partially implemented.
  - Define the supported methods for the `roleTables` collection and `{roleTable}` resource, including exact-match filters, update parameters, and response formats.
  - Add or complete handlers for create, read, update, delete, head, and options behavior while preserving encrypted role-table storage and authorization checks.
  - Add DEBUG/component tests that create a role table, query it, update permissions, verify enforcement, and reject unauthorized access.
  - Update `README.md` to remove the `[not implemented]` marker once the behavior is verified.
  - Done: direct DEBUG coverage now verifies collection GET/OPTIONS plus resource POST/GET/PUT/HEAD/DELETE/OPTIONS, permission rejection/allowance, encrypted RolesDB access through the existing handlers, and README roleTables documentation.

- [x] #13 Implement `/organizations/{organization}/users/{user}/filterWhitelist` resources.
  - Define the whitelist data model on top of the existing ResourcesDB/AdminDB `filterWhitelist` tables, including filter attributes, allowed methods, and ownership fields.
  - Add request parsing and handlers for whitelist collection and item resources under the user resource hierarchy.
  - Enforce whitelist checks in request authorization or filtering paths before resource operations are executed.
  - Preserve encrypted internal database values, MAC verification, and existing role-table authorization semantics.
  - Add tests covering allowlisted filters, missing whitelist entries, malformed filters, and interaction with role-table permissions.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.
  - Done: added `filterWhitelist` collection/item routing, encrypted ResourcesDB CRUD handlers for method allow filters, opt-in whitelist enforcement after role-table authorization for user-resource requests, DEBUG component coverage, and README API documentation.

- [x] #14 Implement `/organizations/{organization}/users/{user}/filterBlacklist` resources.
  - Define the blacklist data model on top of the existing ResourcesDB/AdminDB `filterBlacklist` tables, mirroring whitelist ownership and filter attributes where appropriate.
  - Add request parsing and handlers for blacklist collection and item resources under the user resource hierarchy.
  - Enforce blacklist checks before resource operations, with deny behavior taking precedence over whitelist or role-table allows when both apply.
  - Preserve encrypted internal database values, MAC verification, and existing role-table authorization semantics.
  - Add tests covering denied filters, non-matching blacklist entries, whitelist/blacklist conflicts, malformed filters, and unauthorized updates.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.
  - Done: added `filterBlacklist` collection/item routing through the shared encrypted filter-list handler, deny-before-whitelist enforcement in permission checks, DEBUG component coverage for malformed entries and whitelist/blacklist conflicts, and README API documentation.

- [x] #15 Finish and verify `/organizations/{organization}/storage/{storage}/documentTypes` resources.
  - Review existing `documentTypes` routing and ResourcesDB table definitions to determine whether the README marker is stale or the feature is partial.
  - Define supported document type names, allowed methods, options responses, and validation rules for `{documentType}`.
  - Complete handlers so document type discovery and validation behave consistently for `file.raw`, `file.csv`, and `script.perl`.
  - Add tests for listing supported types, requesting a valid type, rejecting unsupported types, and preserving existing document upload/query behavior.
  - Update `README.md` to remove the `[not implemented]` marker once verified.
  - Done: verified documentTypes routing, documented class/resource behavior, added GET/HEAD/OPTIONS support for documentType resources, and added DEBUG/component coverage for supported and unsupported type validation.

- [x] #16 Finish and verify `/documents/{document}/parserScripts` resources.
  - Review existing `parserScripts` routing and script execution paths to determine whether the README marker is stale or the feature is partial.
  - Define the supported methods for parser script collections and `{parserScript}` resources, including script type restrictions and output formats.
  - Ensure script resources are loaded, decrypted, MAC-verified, and executed only after authorization succeeds.
  - Keep embedded Perl interpreter access serialized while moving file/DB work outside the Perl mutex where possible.
  - Add tests for valid script execution, missing scripts, unsupported script types, parser errors, and unauthorized access.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.
  - Done: enabled parserScripts collection OPTIONS routing, verified resource OPTIONS plus missing-script GET/HEAD behavior, documented existing secure script loading and serialized Perl execution path, and added DEBUG/component coverage.

- [x] #17 Finish and verify `/documents/{document}/contentRows` resources for `file.csv`.
  - Review existing `contentRows` routing and CSV row manipulation paths to determine whether the README marker is stale or the feature is partial.
  - Define row numbering, append behavior, update semantics, delete behavior, and error codes for out-of-range rows.
  - Implement or complete handlers using in-memory transformations followed by immediate durable secure-DB/file saves.
  - Preserve CSV column integrity, encrypted part MAC verification, and column-shuffling security behavior.
  - Add tests for get, append, update, delete, invalid row indexes, missing documents, non-CSV documents, and unauthorized access.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.
  - Done: enabled contentRows collection OPTIONS routing, verified row GET/HEAD, append-only POST, in-range PUT, DELETE persistence, invalid rows, missing documents, and non-CSV rejection, and added DEBUG/component coverage.

- [x] #18 Finish and verify `/documents/{document}/contentColumns` resources for `file.csv`.
  - Review existing `contentColumns` routing and CSV column manipulation paths to determine whether the README marker is stale or the feature is partial.
  - Define column creation, retrieval, deletion, empty-document creation, duplicate-column handling, and error behavior for missing columns.
  - Implement or complete handlers using in-memory transformations followed by immediate durable secure-DB/file saves.
  - Preserve encrypted part MAC verification and the security goal of column shuffling, including safe behavior when duplicate column names exist.
  - Add tests for get, create, delete, duplicate names, last-column deletion, missing documents, non-CSV documents, and unauthorized access.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.
  - Done: enabled contentColumns collection OPTIONS routing, corrected column HEAD and DELETE semantics, verified column get/create/delete, duplicate rejection, empty-document creation, last-column deletion, missing documents, non-CSV rejection, and missing-key rejection, and added DEBUG/component coverage.

- [x] #19 Implement direct encrypted DB browsing resources under `/dbNames`.
  - Define the scope and security model for `/dbNames`, `{dbName}`, `/dbTables`, `{dbTable}`, `/tableRows`, `{tableRow}`, `/tableColumns`, and `{tableColumn}`.
  - Decide whether this hierarchy exposes only internal/admin databases, user data databases, or a restricted diagnostics view, and document the decision.
  - Add route parsing and handlers that never expose decrypted protected values unless the caller is authorized and supplies the required organization key.
  - Use prepared statements and strict identifier validation for database/table/row/column selectors.
  - Add tests for listing databases, listing tables, reading rows/columns, rejecting invalid identifiers, authorization failures, and SQL injection attempts.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.
  - Done: implemented a read-only diagnostics scope for registered `file.csv` secure document databases under organization storage, with table names restricted to `data` and `meta`, positive-integer row selectors, in-memory column selection, normal secure-DB verification before reads, DEBUG/component coverage, and README documentation.

## Source Code TODO/FIXME Markers

- [x] #20 Replace `main` placeholders in Autoconf library checks with real function probes.
  - Source: `configure.ac:42`, `configure.ac:44`, `configure.ac:46`, `configure.ac:48`, `configure.ac:50`, `configure.ac:52`, `configure.ac:54`, `configure.ac:56`, `configure.ac:58`, `configure.ac:60`, `configure.ac:62`, `configure.ac:64`.
  - Done: replaced placeholder `main` checks with representative symbols for libc, libcrypt, libcrypto, libdl, libm, libmicrohttpd, libnsl, libperl, pthread, libutil, GnuTLS, and SQLite; regenerated `configure` and verified `./configure` resolves all probes.

- [x] #21 Add cloud storage wrappers for file handling.
  - Source: `filehandling.c:53`.
  - Done: added storage-provider wrappers for directory checks, file open/close, and file removal. Local filesystem behavior is preserved for provider `0`, non-local providers now fail explicitly until provider clients are implemented, and the default provider macro can be overridden at compile time.

- [x] #22 Factor common in-memory DB creation for CSV and memory-table imports.
  - Source: `filehandling.c:649`, `filehandling.c:1687`.
  - Done: factored the shared ColumnFile memory DB allocation, random filename/salt initialization, and `data`/`meta` table creation into `cmeCreateSecureDBMemColumnFiles()`, preserving the existing CSV and memory-table import return codes.

- [x] #23 Add SQL DB filename collision handling.
  - Source: `filehandling.c:148`.
  - Done: ColumnFile SQL DB filenames are regenerated with a bounded retry loop when they collide with names already generated in the current batch or with existing files in the target storage path.

- [x] #24 Factor secure DB import insertion logic into a shared helper.
  - Source: `filehandling.c:960`, `filehandling.c:2053`.
  - Done: factored duplicated CSV and memory-table secure DB `data` row insertion loops into `cmeInsertSecureDBDataRows()`, preserving caller-specific source column offsets, row-order bases, and existing public error codes.

- [x] #25 Implement MAC and protected MAC calculation during secure DB import.
  - Source: `filehandling.c:350`, `db.c:809`.
  - Done: secure DB protection now uses shared `cmeMemSecureDBStoreValueHMAC()` logic to compute and store plaintext and protected value HMACs for `MAC`, `MACProtected`, `sign`, and `signProtected` attributes, preserving the existing import and verification behavior.

- [x] #26 Verify locale settings for `printf`, including UTF-8 behavior.
  - Source: `main.c:66`, `TEST/run_debug_components.sh:193`.
  - Done: startup now fails early when `LC_CTYPE` cannot be selected or is not multibyte-capable, logs the selected locale and `MB_CUR_MAX` in DEBUG builds, and the debug component script verifies that marker.

- [x] #27 Move DEBUG tests into a dedicated executable or test harness.
  - Source: `debug_tests.c:11`, `Makefile.am:15`, `TEST/run_debug_components.sh:180`.
  - Related roadmap item: `#9`.
  - Done: added the `CaumeDSE-debug-tests` harness, moved DEBUG component execution out of `main()`, shared runtime setup/cleanup through `runtime.c`, and updated the debug component script to execute the harness.

- [x] #28 Improve administrator key screen cleanup or use a sensitive terminal I/O library.
  - Source: `engine_admin.c:46`, `engine_admin.c:437`.
  - Done: after the first-run administrator organization key is acknowledged, interactive terminals now receive ANSI clear-screen, clear-scrollback, and cursor-home controls; redirected output gets an explicit warning because it cannot be cleared.

- [x] #29 Add basic error handling for certificate file loading.
  - Source: `engine_admin.c:64`, `engine_admin.c:842`.
  - Done: HTTPS setup now loads the key, certificate, and CA certificate through a required-file helper that rejects missing paths, load errors, empty files, and null buffers with per-file diagnostics before starting the daemon.

- [x] #30 Replace temporary web-service `getchar()` waits with an exception/stop handler.
  - Source: `engine_admin.c:102`, `engine_admin.c:137`, `engine_admin.c:1122`.
  - Done: web-service setup now installs SIGINT and SIGTERM stop handlers after daemon startup, waits with `pause()` until a stop signal arrives, restores the previous handlers during cleanup, and keeps debug noninteractive runs bounded for automated checks.

- [x] #31 Process whitelist and blacklist regex filter lists in ResourcesDB.
  - Source: `engine_admin.c:217`, `engine_admin.c:1396`, `function_tests.c:1187`, `function_tests.c:1355`.
  - Related roadmap items: `#13`, `#14`.
  - Done: permission checks now load method-enabled filterWhitelist/filterBlacklist rows from ResourcesDB, evaluate orgResourceId and userResourceId as full-string POSIX extended regex filters, preserve blacklist deny precedence and whitelist opt-in enforcement, and cover regex allow/deny behavior in DEBUG component tests.

- [x] #32 Sanitize variables used in string handling and generated queries.
  - Source: `strhandling.c:292`, `strhandling.c:309`, `db.c:66`, `webservice_interface.c:544`.
  - Done: added shared SQL identifier and unsafe input checks, sanitized legacy INSERT/UPDATE builder values, and rejected unsafe web-service route/query tokens before DB processing.

- [x] #33 Verify `WHERE` usage that may not match `userId`.
  - Source: `strhandling.c:308`.
  - Done: `cmeStrSqlUPDATEConstruct()` has no current call sites and builds its `WHERE` clause from the explicit `matchColumn`/`matchValue` arguments, with identifier validation and value sanitization from item `#32`; documented that it must not assume `userId`.

- [x] #34 Add response formatting support for HTML, CSV, and other requested output types.
  - Source: `strhandling.c:376`, `webservice_interface.c:2444`, `webservice_interface.c:4113`, `webservice_interface.c:5343`.
  - Done: added a shared count response formatter for DELETE results that honors `outputType=csv` and the default/explicit HTML format, and routed existing DELETE count responses through it.

- [x] #35 Add OAuth authentication or document the required external manager layer.
  - Source: `webservice_interface.c:885`, `README.md:2182`, `common.h:64`.
  - Done: documented OAuth as an external engine-manager responsibility, clarified that CaumeDSE does not validate OAuth tokens internally, described the delegated organization/user/role/resource lifecycle, and updated source comments and OAuth field comments to match that boundary.

- [x] #36 Process storage `documentTypes` and `documents` resource tree requests.
  - Source: `webservice_interface.c:1421`, `webservice_interface.c:1438`, `webservice_interface.c:1455`, `webservice_interface.c:1472`, `function_tests.c:1487`, `TEST/run_debug_components.sh:267`.
  - Related roadmap item: `#15`.
  - Done: removed the stale dispatcher TODO, verified the main request dispatcher routes storage documentTypes class/resource and documents class/resource requests with a DEBUG noninteractive dispatcher fixture, added component-script marker coverage for those dispatcher paths, and documented the storage document-tree route roots.

- [x] #37 Move temporary POST attributes for `shuffle` and `protect` into API parameters.
  - Source: `webservice_interface.c:6256`, `webservice_interface.c:9605`, `webservice_interface.c:10686`.
  - Done: document, content-row and content-column CSV imports now derive `shuffle` and `protect` secure DB attributes from request parameters, with documented defaults and disable values.

- [x] #38 Ensure CSV upload parameters come from the API instead of predefined test values.
  - Source: `webservice_interface.c:6438`.
  - Done: CSV document uploads now take the remaining import option, `replaceDB`, from request parameters and document the accepted boolean values.

- [x] #39 Add handlers for additional file document types.
  - Source: `webservice_interface.c:6546`.
  - Done: added raw-compatible handlers for `file.txt`, `file.json`, `file.xml`, `file.html`, `file.pdf`, `file.png`, `file.jpg`, `file.gif`, `file.zip` and `file.bin`, while keeping `file.csv` and `script.perl` special.

- [x] #40 Add an optional multi-round secure overwrite scheme.
  - Source: `webservice_interface.c:7307`, `filehandling.h:83`.
  - Done: `cmeFileOverwriteAndDelete()` now supports compile-time multi-pass overwrites via `CDSE_SECURE_OVERWRITE_PASSES`, and POST temporary file cleanup uses that shared helper.

- [x] #41 Vacuum memory DBs before durable saves when requested.
  - Source: `db.c:201`.
  - Done: memory database saves can now request a pre-save `VACUUM`; CSV upload and content row/column writes expose this through the `vacuumDB` request parameter while preserving mandatory vacuuming for protected imports.

- [x] #42 Implement signing and protected signing for protected DB values.
  - Source: `db.c:1253`, `db.c:1259`, `db.c:2225`, `db.c:2231`.
  - Done: `sign` and `signProtected` now compute and verify keyed signatures for plaintext and protected data values, respectively, using the existing HMAC-backed integrity primitive. The CSV integrity component test now exercises both signing attributes together with `MAC` and `MACProtected`.

- [x] #43 Replace direct DB protect/unprotect call sites with wrapper functions.
  - Source: `db.c:2355`, `db.c:2383`.
  - Done: verified plain DB text protect/unprotect paths use `cmeProtectDBValue()` and `cmeUnprotectDBValue()` wrappers; removed the stale wrapper TODO markers. Salted protect/unprotect wrapper cleanup remains tracked separately in `#44`.

- [x] #44 Replace direct salt/protect and unprotect/unsalt call sites with wrapper functions.
  - Source: `db.c:2420`, `db.c:2461`.
  - Done: `cmeProtectDBSaltedValue()` and `cmeUnprotectDBSaltedValue()` now delegate encryption/decryption to `cmeProtectDBValue()` and `cmeUnprotectDBValue()` after adding or before removing the value salt.

- [x] #45 Replace direct `malloc` calls with an audited allocation wrapper.
  - Source: `common.h:50`.
  - Done: project allocation calls are now routed through `cmeMalloc()` and `cmeRealloc()` wrappers that log failed non-zero-size allocations with source file and line information.

- [x] #46 Read globals from a configuration file.
  - Source: `common.h:51`.
  - Done: startup now loads runtime globals from `caumedse.conf` (or `CDSE_CONFIG_FILE`) and applies the existing `CDSE_DEFAULT_ENC_ALG` environment override after validating cipher names.

- [x] #47 Standardize IDD usage and avoid direct use of numeric IDs and column names.
  - Source: `common.h:132`.
  - Done: added central IDD table-name and URL-parameter-name helpers, and replaced hard-coded internal DB column/table names in admin bootstrap, ColumnFile DB creation, and LogsDB transaction handling with IDD constants.

- [x] #48 Research secure memory clearing and memory locking for sensitive data.
  - Source: `engine_interface.c:310`, `engine_interface.c:1583`.
  - Done: added `OPENSSL_cleanse()`-based secure memory clearing helpers plus best-effort `mlock()`/`munlock()` wrappers, then replaced optimizer-sensitive manual `memset()` wipes for decrypted document IDs.

- [x] #49 Verify salt requirements and fail on invalid salts.
  - Source: `engine_interface.c:1053`.
  - Done: `cmePostProtectDBRegister()` now rejects caller-supplied protected DB salts unless they are exactly `evpSaltBufferSize * 2` hex characters; omitted salts still use the existing generated-salt path.

- [x] #50 Evaluate whether another random source is needed for systems without `/dev/random` or `/dev/urandom`.
  - Source: `crypto.c:436`.
  - Done: `cmeSeedPrng()` now uses OpenSSL platform seeding via `RAND_poll()`/`RAND_status()` and treats `/dev/random` and `/dev/urandom` as optional extra entropy sources when present.

- [x] #51 Add full webservice startup HTTP(S) component coverage without `--skip-web`.
  - Source: `TEST/run_debug_components.sh:20`, `TEST/run_debug_components.sh:164`, `TEST/run_debug_components.sh:322`.
  - Goal: make the default `TEST/run_debug_components.sh` path reliable for routine full HTTP and HTTPS startup verification, including port availability, generated certificate/key loading, webservice startup markers, bounded noninteractive shutdown, and failure diagnostics when either protocol cannot start.
  - Done: default component verification now runs full web startup coverage with a 120s executable timeout, validates HTTP/HTTPS ports before launch, checks explicit HTTP/HTTPS startup-and-shutdown PASS markers, verifies nonzero certificate/key file reads without hard-coded byte counts, and reports startup failures with protocol and port diagnostics.

- [x] #52 Verify and document the test database default password.
  - Source: `TEST/testDB_opt_cdse/ResourcesDB`, `README.md`, `function_tests.c`.
  - Goal: use repository history and HTTPS fixture checks to identify the actual default password/key for the committed test databases, update documentation and tests that still reference stale values, and explain why `password1` is not accepted when it is not the fixture key.
  - Done: documented that the current committed fixture uses `0CDBB9AF76AF43BDB72E095989E612CC` for `EngineAdmin` / `EngineOrg`, that older history used `6DA74D788E0A33A0272252796EF0748A`, and that `password1` is only a generated document/resource fixture key. Verified current component coverage with `TEST/run_debug_components.sh --skip-build --skip-web` and `CDSE_DEBUG_TEST_TIMEOUT=120s`.

- [x] #53 Add live HTTP(S) API flow coverage to the DEBUG verifier.
  - Source: `TEST/run_debug_components.sh`, `debug_tests.c`, `README.md`.
  - Goal: verify more than socket startup by driving authenticated web requests through both HTTP and HTTPS, including organization creation, CSV upload, content row and column queries, Perl script upload, and parser script execution.
  - Done: `CaumeDSE-debug-tests --web-service http|https` now holds a selected DEBUG web service open until SIGTERM, and `TEST/run_debug_components.sh` uses `curl` to run the live API flow over both protocols with temporary organization/storage resources, CSV/Perl fixtures, and a per-run HTTPS client certificate chain signed by the committed test CA fixture.

- [x] #54 Clean up generated verification artifact stash.
  - Source: `stash@{0}` (`codex-generated-verification-artifacts`), local build outputs.
  - Goal: remove stale local generated artifacts from the post-verification workflow without losing source changes or useful diagnostics.
  - Plan:
    - Batch 1: inspect the stash metadata and file list, separating tracked generated files from untracked build products.
    - Batch 2: confirm the stash contains no source, documentation, test fixture, or configuration changes worth preserving.
    - Batch 3: drop only the generated-artifact stash, leave unrelated older stashes untouched, and verify the worktree remains clean.
  - Done: inspected `codex-generated-verification-artifacts`, confirmed it contained only generated build/dependency outputs (`.Po`, `.o`, generated binaries, `Makefile`, `config.*`), dropped that stash, and left unrelated older stashes untouched.

- [x] #55 Use document storage paths when deleting secure DB column files.
  - Source: `engine_interface.c:566`.
  - Goal: make `cmeDeleteSecureDB()` delete column files from the storage path associated with the secure document instead of assuming `cmeDefaultFilePath`.
  - Plan:
    - Batch 1: trace `cmeDeleteSecureDB()` callers and ResourcesDB document metadata to identify the authoritative storage path available during deletion.
    - Batch 2: update deletion path construction to use the provided or document-defined storage path, preserving existing local filesystem behavior and secure cleanup semantics.
    - Batch 3: add DEBUG/component coverage that creates a secure document under a non-default storage path, deletes it, and verifies ResourcesDB rows and column files are both removed.
  - Done: `cmeDeleteSecureDB()` now builds secure column file delete paths from the supplied storage path with the previous default path as a fallback, and DEBUG component coverage verifies replacement removes old column files created under a non-default storage directory.

- [x] #56 Add Python parser script support.
  - Source: `webservice_interface.c:8771`, `webservice_interface.c:9002`.
  - Goal: support `script.python` parser scripts alongside `script.perl` for parser script resources while preserving encrypted script loading, authorization, and secure temporary-file cleanup.
  - Plan:
    - Batch 1: define the `script.python` document type behavior, accepted URL/resource semantics, output contract, and interpreter/runtime dependency expectations.
    - Batch 2: add type validation, upload/storage handling, and parser dispatch so `script.perl` continues through the existing Perl path while `script.python` uses a Python execution path with bounded inputs and sanitized temporary files.
    - Batch 3: add DEBUG/component and live HTTP(S) coverage for Python script upload and parser execution, including missing-script, unsupported-type, parser-error, and unauthorized-access cases.
  - Done: added `script.python` as a supported raw script document type, dispatch parserScripts requests to `python3` with secure temporary input/output CSV files, documented the Python parser contract, added a Python parser fixture, and extended live HTTP(S) verifier coverage for upload and parser execution.

- [x] #57 Add live web verification coverage for all API features.
  - Source: `TEST/run_debug_components.sh`, DEBUG web-service harness, API resource handlers.
  - Goal: provide an unsandboxed live HTTP(S) verification mode that exercises every documented API feature end-to-end, not only startup and a representative document/parser flow.
  - Plan:
    - Batch 1: inventory documented API resources, methods, required parameters, output formats, and existing DEBUG/component coverage to define the live coverage matrix.
    - Batch 2: extend the live verifier to run only under explicit unsandboxed execution, allocate isolated ports/storage, create disposable organizations/users/resources, and clean up after each scenario.
    - Batch 3: add live HTTP and HTTPS scenarios for organizations, users, storage, documentTypes, documents, content rows/columns, parser scripts, roleTables, filterWhitelist/filterBlacklist, DB browsing, and negative authorization/error cases.
    - Batch 4: report per-feature PASS/FAIL markers and request/response log paths so failures are diagnosable without reading the full DEBUG log.
  - Done: `TEST/run_debug_components.sh` now reports per-feature live HTTP/HTTPS PASS/FAIL markers with body/meta log paths, creates disposable organizations, users, storage, documents, role/filter rules and scripts, and verifies documentTypes, document metadata, content, contentRows/contentColumns, parserScripts, DB browsing, roleTables, filterWhitelist/filterBlacklist, cleanup, and representative negative routes over both protocols.

- [x] #58 Improve DEBUG verifier runtime and focused rerun ergonomics.
  - Source: `TEST/run_debug_components.sh`.
  - Goal: keep full DEBUG/live API coverage available while making routine iteration faster and easier to diagnose after failures.
  - Plan:
    - Batch 1: add explicit TODO tracking and inspect where the verifier spends time after live API coverage expansion.
    - Batch 2: add focused execution switches for live-only reruns and protocol selection without weakening the default full verifier path.
    - Batch 3: report elapsed time for major steps and live API feature checks so slow regressions are visible in the summary.
    - Batch 4: validate syntax plus focused and full-compatible verifier modes, then document the completed workflow in this TODO item.
  - Done: `TEST/run_debug_components.sh` now supports `--live-only` focused reruns, `--web-protocol=http|https|both` live protocol selection, elapsed-time reporting for build/debug-engine steps and live API feature checks, and protocol-aware port validation. Focused runs showed secure CSV reads, DB browsing, and parser execution as the slow live checks under DEBUG logging, while HTTP-only and HTTPS-only live reruns now avoid rebuilding, component extraction, and the unselected protocol.

- [x] #59 Reduce slow live verifier secure CSV checks.
  - Source: `TEST/run_debug_components.sh`, `TEST/testfiles/randomdata-620_A.csv`, `TEST/testfiles/CSVtest.csv`.
  - Goal: keep live route coverage broad while reducing the slow secure CSV read, DB browsing, and parser checks identified by #58.
  - Plan:
    - Batch 1: compare live verifier fixture size and route markers to determine whether the broad live flow needs the large CSV fixture.
    - Batch 2: switch the live verifier to a smaller fixture when coverage only needs representative secure CSV rows, preserving document/content/parser/DB browsing assertions.
    - Batch 3: validate focused HTTP and HTTPS live-only modes and compare elapsed timings against the #58 baseline.
    - Batch 4: update this TODO with the measured impact and any remaining bottlenecks.
  - Done: added `TEST/testfiles/live-api-small.csv` with the same `name,lastName,employeeId,salary` schema and representative first-row/parser values, and switched the live API upload to that fixture. Focused HTTP and HTTPS live runs still verify document/content/parser/DB browsing markers, while the previously slow secure CSV upload/read/browse/parser checks dropped from roughly 16-17s each to mostly 1-2s under DEBUG logging.

- [x] #60 Create a comprehensive cryptography and data security tutorial.
  - Source: `TUTORIAL.md`, `README.md`, CaumeDSE cryptographic/data-security implementation and API examples.
  - Goal: create a tutorial that teaches core cryptographic and data security concepts through CaumeDSE as an applied example, explaining how its features use strong security concepts and where operational boundaries remain.
  - Plan:
    - Batch 1: outline the tutorial structure, covering threat models, encryption, authenticated encryption, hashing, HMAC, PBKDF/key derivation, salting, protected indexes, MAC/signature concepts, secure deletion, TLS/client certificates, authorization, audit logs, and secure parser execution.
    - Batch 2: map each concept to concrete CaumeDSE features, code paths, configuration, API examples, and verifier coverage so readers can connect theory to implementation.
    - Batch 3: write `TUTORIAL.md` with practical examples, diagrams or tables where useful, and explicit notes about what CaumeDSE protects, what it does not protect, and how to operate it safely.
    - Batch 4: cross-link the tutorial from `README.md`, validate examples against current fixtures/API routes, and run documentation/spell checks or targeted verifier commands as appropriate.
  - Done: added `TUTORIAL.md` covering threat models, key handling, salts, PBKDF2, AES-GCM encryption, HMAC/MACProtected integrity, secure CSV/raw-file storage, protected lookup indexes, TLS client certificates, role/filter authorization, parser execution, secure deletion, audit logs, verifier usage, and operational boundaries. Linked the tutorial from `README.md` and validated the documentation references plus `TEST/run_debug_components.sh --skip-build --skip-web`.

- [x] #61 Add live verifier API coverage matrix output.
  - Source: `TEST/run_debug_components.sh`, live HTTP(S) API checks, README API resource tree.
  - Goal: make live API coverage visible as a clear matrix instead of requiring maintainers to infer coverage from shell code.
  - Plan:
    - Batch 1: inventory current `live_api_check` calls and define matrix columns for protocol, feature, method, expected status, marker, elapsed time, and log paths.
    - Batch 2: have the verifier emit a stable coverage table or CSV artifact while preserving the current PASS/FAIL summary.
    - Batch 3: document how to compare coverage after route changes and validate HTTP-only, HTTPS-only, and both-protocol runs.
  - Done: `TEST/run_debug_components.sh` now writes `live-api-coverage.csv` and `live-api-coverage.txt` under the verifier log directory and appends the fixed-width matrix plus artifact paths to `summary.txt`. Each live request row records protocol, feature, inferred HTTP method, expected and actual status, curl result, marker status, pass/fail state, elapsed time, and body/meta log paths. Documented the artifacts in README and TUTORIAL, and validated `bash -n TEST/run_debug_components.sh`, `TEST/run_debug_components.sh --live-only --web-protocol=http`, and `TEST/run_debug_components.sh --live-only --web-protocol=https`; each focused live run produced 41 live request rows and passed with `42 passed, 0 failed, 10 skipped`.

- [x] #62 Harden parser script execution limits.
  - Source: `webservice_interface.c`, `TEST/run_debug_components.sh`, `TEST/testfiles/test.py`, `TEST/testfiles/test.pl`.
  - Goal: bound parser-script execution and output so scripts that process decrypted CSV data cannot hang a worker indefinitely or create unbounded response data.
  - Plan:
    - Batch 1: add explicit parser execution limits for child-process parser runtimes, starting with Python timeout and output-file byte caps.
    - Batch 2: add shared parser result-size validation for both Perl and Python results, with clear DEBUG/error diagnostics and secure temporary-file cleanup on timeout/error paths.
    - Batch 3: add focused DEBUG/live verifier fixtures for normal parser execution, timeout, oversized output, and temporary-file cleanup behavior.
    - Batch 4: document the limits and the remaining embedded-Perl boundary, then validate syntax, component markers, and focused live parser flows.
  - Done: added compile-time parser limits for Python child-process timeout, Python output-file size, and shared parser result-table cells; Python parser temp files are still securely overwritten/deleted on timeout and oversized-output paths. Added live verifier fixtures for timeout and oversized output, extended HTTP/HTTPS live parser checks, documented the limits in README and TUTORIAL, and validated `bash -n TEST/run_debug_components.sh`, `make`, `TEST/run_debug_components.sh --skip-build --skip-web`, `TEST/run_debug_components.sh --web-protocol=http`, and `TEST/run_debug_components.sh --live-only --web-protocol=https`. Embedded Perl now shares the result-table cap; process-level Perl runtime isolation remains a future hardening step because it requires moving Perl execution out of the embedded interpreter path.

- [x] #63 Add live negative authorization scenarios.
  - Source: `TEST/run_debug_components.sh`, roleTables/filterWhitelist/filterBlacklist routes, TLS client certificate setup.
  - Goal: increase confidence that authorization failures are enforced over live HTTP(S), not only representative component tests.
  - Plan:
    - Batch 1: define negative cases for denied role/filter combinations, wrong user, missing org key, invalid client certificate, and forbidden document access.
    - Batch 2: add isolated live requests that assert the expected 401/403/404 responses without weakening cleanup.
    - Batch 3: validate both HTTP and HTTPS focused modes and document any protocol-specific authentication differences.
  - Done: added isolated live negative authentication checks before disposable resource setup: missing all credentials and missing `orgKey` over HTTP/HTTPS, plus missing client certificate and user/certificate CN mismatch over HTTPS. These rows are captured in the live API coverage matrix. Documented the negative live coverage in README and TUTORIAL, and validated `bash -n TEST/run_debug_components.sh`, `TEST/run_debug_components.sh --live-only --web-protocol=http` (`44 passed, 0 failed, 10 skipped`), and `TEST/run_debug_components.sh --live-only --web-protocol=https` (`46 passed, 0 failed, 10 skipped`). Role/filter deny behavior remains covered by DEBUG component tests because the disposable live setup intentionally starts with `CDSE_DEBUG_TEST_SKIP_AUTHZ=1` to bootstrap per-run organizations and storage.

- [x] #64 Create API reference examples from live verifier fixtures.
  - Source: `README.md`, `TEST/run_debug_components.sh`, live API fixture data.
  - Goal: provide tested, minimal API examples without further expanding the main README.
  - Plan:
    - Batch 1: extract the current live verifier flow into a concise examples outline for organization, storage, user, document, parser, and DB browsing operations.
    - Batch 2: add `API_EXAMPLES.md` with curl examples aligned to the live verifier fixtures and documented authentication parameters.
    - Batch 3: cross-link the examples from README and validate example routes against live verifier behavior.
  - Done: added `API_EXAMPLES.md` with curl examples derived from the live verifier flow, covering authentication negatives, organization/storage/user setup, documentTypes, role/filter resources, secure CSV upload/content, rows/columns, secure DB browsing, parser scripts, cleanup, and verifier commands. Linked it from README and validated the examples against the current live verifier route names and committed fixtures.

- [x] #65 Add CI-friendly verifier profile.
  - Source: `TEST/run_debug_components.sh`, build/test workflow.
  - Goal: keep full local verification available while providing a practical PR/CI smoke profile.
  - Plan:
    - Batch 1: define the minimum CI smoke set: syntax/build, component markers, and one selected live protocol.
    - Batch 2: add a verifier switch such as `--ci-smoke` that selects the bounded profile without changing the default full run.
    - Batch 3: document expected runtime, prerequisites, exit behavior, and failure artifacts.
  - Done: added `--ci-smoke` to `TEST/run_debug_components.sh`. The profile keeps the normal configure/build/check/install path, component marker extraction, and DEBUG web startup checks, then runs one live API protocol instead of both. It defaults to HTTP live coverage and accepts `--ci-smoke --web-protocol=https` to select HTTPS. Documented the command in README, TUTORIAL, API_EXAMPLES, and AGENTS, and validated `bash -n TEST/run_debug_components.sh` plus `TEST/run_debug_components.sh --ci-smoke` (`73 passed, 0 failed, 1 skipped`).

- [x] #66 Add AI-safe API usage examples.
  - Source: `AI_USAGE.md`, `API_EXAMPLES.md`, live verifier fixtures.
  - Goal: document safe patterns for LLM agents and automation that call CaumeDSE without leaking keys or over-broad access.
  - Plan:
    - Batch 1: outline safe agent workflows for scoped org keys, least-privilege users, parser-script restrictions, audit logs, and cleanup.
    - Batch 2: add `AI_USAGE.md` with concrete examples and explicit anti-patterns for prompts, logs, and generated scripts.
    - Batch 3: cross-link from README/API examples and validate examples against current verifier routes.
  - Done: added `AI_USAGE.md` with AI-agent boundaries, least-privilege
    workflow guidance, secret-safe shell setup, narrow request examples,
    parser-script review guardrails, redacted verifier usage, anti-patterns, and
    validation commands. Linked it from README and API_EXAMPLES.

- [x] #67 Add machine-readable OpenAPI spec.
  - Source: `README.md`, `API_EXAMPLES.md`, `TEST/run_debug_components.sh`.
  - Goal: make CaumeDSE easier for AI agents, SDK generators, docs tooling, and API validators to consume.
  - Plan:
    - Batch 1: inventory documented REST resources, methods, parameters, status codes, and response formats.
    - Batch 2: add `openapi.yaml` for the stable documented routes, starting with live-verifier-covered resources.
    - Batch 3: add a lightweight validation check that compares key examples or route names against the spec.
  - Done: added `openapi.yaml` for the stable README/API_EXAMPLES/live-verifier route surface, including organizations, users, storage, documentTypes, documents, content, contentRows/contentColumns, parserScripts, role/filter resources, and secure DB browsing. Added `TEST/validate_openapi_routes.sh`, wired it into the DEBUG verifier summary, and linked the spec from README/API_EXAMPLES.

- [x] #68 Add JSON output mode for key API resources.
  - Source: `webservice_interface.c`, response formatting helpers, README/API examples.
  - Goal: provide structured responses that are easier for AI agents and modern clients to parse than HTML or CSV.
  - Plan:
    - Batch 1: identify shared response-formatting helpers and the safest initial resources to support.
    - Batch 2: add `outputType=json` for documentTypes, documents, content rows/columns, dbNames/dbTables, parserScripts, and role/filter reads.
    - Batch 3: extend DEBUG/live verifier coverage and document JSON examples.
  - Done: added JSON table/count response formatting with escaping and `application/json` headers, added JSON handling for the special `documentTypes` collection route, documented `outputType=json`, updated OpenAPI response metadata, and extended DEBUG plus live HTTP verifier coverage for documentTypes, documents, content rows/columns, dbNames/dbTables/tableRows/tableColumns, parserScripts, and role/filter reads.

- [x] #69 Add AI agent integration sample.
  - Source: `samples/ai-agent/`, `API_EXAMPLES.md`, verifier fixtures.
  - Goal: show a guarded end-to-end Python agent workflow using CaumeDSE APIs.
  - Plan:
    - Batch 1: define a minimal scripted workflow for create org/storage, upload CSV, query rows/columns, run parser, and cleanup.
    - Batch 2: add a sample Python client with guardrails to avoid putting org keys or sensitive data in prompts/logs.
    - Batch 3: document setup, expected outputs, and validation against DEBUG/live verifier fixtures.
  - Done: added `samples/ai-agent/guarded_agent_workflow.py` and README documentation. The sample uses environment-based secrets, redacted request logging, reviewed verifier fixtures, narrow JSON row/column/parser queries, an LLM-safe prompt preview, and best-effort cleanup of uploaded documents, storage, and user resources. Linked the sample from README, AI_USAGE, and API_EXAMPLES.

- [x] #70 Add redaction mode for logs and verifier artifacts.
  - Source: DEBUG logging, `TEST/run_debug_components.sh`, live coverage artifacts.
  - Goal: reduce accidental disclosure of org keys, `newOrgKey`, certificate paths, and sensitive query values during AI-assisted debugging and CI runs.
  - Plan:
    - Batch 1: identify log and metadata paths that currently include secrets or sensitive request values.
    - Batch 2: add a config/env-controlled redaction mode for live verifier artifacts and selected DEBUG diagnostics.
    - Batch 3: validate that pass/fail diagnostics remain useful while secrets are masked.
  - Done: added opt-in `CDSE_VERIFY_REDACT=1` support to the DEBUG verifier.
    Redacted runs mask `orgKey`, `newOrgKey`, selected credential-style request
    parameters, and generated certificate/key paths in `summary.txt`, live
    request body/meta artifacts, the full DEBUG run log, component extract logs,
    and live service logs while preserving statuses, markers, elapsed times, and
    artifact names. Documented the mode in README, TUTORIAL, API_EXAMPLES, and
    AGENTS.

- [x] #71 Add MCP server prototype.
  - Source: new `samples/mcp-server/` or `samples/ai-agent/`, REST API examples.
  - Goal: expose safe CaumeDSE operations through Model Context Protocol tools for AI assistants.
  - Plan:
    - Batch 1: define a minimal tool surface such as list document types, upload CSV, query column, run parser, and cleanup workspace.
    - Batch 2: implement a prototype MCP wrapper that calls the REST API with scoped credentials.
    - Batch 3: document security boundaries and avoid exposing raw org keys or unrestricted parser execution.
  - Done: added `samples/mcp-server/`, a stdio JSON-RPC MCP prototype with an
    allow-listed tool surface for disposable workspace setup, document-type
    listing, reviewed CSV/parser uploads, bounded column/parser queries, and
    cleanup. The wrapper reads credentials from `CDSE_MCP_*` environment
    variables, redacts secret query parameters in request logs, avoids exposing
    org keys through tool schemas/results, and documents client configuration
    plus security boundaries for parser and CSV handling.

- [x] #72 Add prompt-injection resistant parser-script guidance.
  - Source: `TUTORIAL.md`, parser script docs, `TEST/testfiles/`.
  - Goal: help users treat CSV contents and generated parser scripts as untrusted inputs in LLM-connected systems.
  - Plan:
    - Batch 1: document prompt-injection and data-exfiltration risks specific to parser scripts and CSV content.
    - Batch 2: add safe parser-script patterns and review checklists for generated Perl/Python scripts.
    - Batch 3: link the guidance from parser documentation and AI usage examples.
  - Done: expanded `AI_USAGE.md`, `TUTORIAL.md`, README parser-script docs,
    and AI/MCP sample READMEs with prompt-injection guidance for CSV cells and
    parser output, generated-script review rules, safe deterministic parser
    patterns, and explicit data-exfiltration anti-patterns. Marked the Python
    parser fixture as a reviewed offline fixture.

- [x] #73 Move Perl parser execution out of the main process.
  - Source: `webservice_interface.c`, `perl_interpreter.c`, parser script docs, live verifier parser checks.
  - Goal: reduce the blast radius of malicious or buggy `script.perl` documents by running Perl parser code in a child process instead of the embedded interpreter inside the CaumeDSE server process.
  - Plan:
    - Batch 1: define a child-process Perl parser contract that preserves the current callback/output semantics or introduces a compatible CSV-in/CSV-out wrapper.
    - Batch 2: implement child-process Perl execution with secure temporary input/output files and remove request-time parser callbacks from the shared embedded interpreter path.
    - Batch 3: extend DEBUG/live verifier coverage for normal Perl parser execution, parser errors, timeout, oversized output, and cleanup.
  - Done: parserScripts now run `script.perl` documents through a child `perl`
    process with a generated compatibility runner that preserves
    `cmePERLProcessColumnNames` and `cmePERLProcessRow` behavior over secure
    temporary CSV input/output files. Perl requests now share the same timeout,
    output-size, result-table-size, and cleanup flow used for Python child
    parsers. Added live verifier fixtures/checks for Perl timeout and oversized
    output, and updated README/TUTORIAL parser isolation docs.

- [x] #74 Add common sandbox controls for child-process parsers.
  - Source: `webservice_interface.c`, parser script execution helpers, build configuration.
  - Goal: apply consistent process-level limits and containment to `script.python` and future child-process `script.perl` execution.
  - Plan:
    - Batch 1: introduce a shared parser-child launcher that uses absolute interpreter paths, a minimal environment, closed inherited file descriptors, and explicit working directories.
    - Batch 2: add OS resource limits for CPU time, address space, file size, process count, and open files where supported.
    - Batch 3: document platform support and add verifier cases that prove limits fail closed.
  - Done: added a shared parser child launcher used by both Perl and Python
    parserScripts. The launcher uses compile-time absolute interpreter paths,
    runs children from the secure temporary directory, supplies a minimal
    `PATH`/locale environment, redirects stdio to `/dev/null`, closes inherited
    file descriptors above stderr, and applies supported `setrlimit()` caps for
    CPU time, output file size, address space, open files, and process count
    before `execve()`. Updated
    README/TUTORIAL documentation; existing live timeout and oversized-output
    verifier cases now exercise the common child launcher for both runtimes.

- [x] #75 Harden parser temporary file creation.
  - Source: `webservice_interface.c`, `filehandling.c`, secure deletion helpers.
  - Goal: eliminate parser temp-file race and symlink risks by creating input/output files atomically with strict permissions in a private parser temp directory.
  - Plan:
    - Batch 1: replace random temp-path generation for parser files with exclusive creation such as `mkstemp` or `open(O_CREAT|O_EXCL)` plus restrictive modes.
    - Batch 2: ensure parser temp directories have strict ownership/permissions and are configurable separately from general storage.
    - Batch 3: add tests for cleanup, collision handling, and refusal to follow pre-existing symlinks.
  - Done: added `CDSE_PARSER_TMP_FILE_PATH` and shared filehandling helpers
    that create parser temp files atomically with `mkstemp()`, verify the
    parser temp directory is a service-owned `0700` real directory, verify
    created files are single-link regular files, and force `0600` file mode.
    Parser input/output, Perl runner, and decrypted script temp files now use
    the exclusive helper. Added DEBUG verifier coverage for cleanup, collision
    handling, strict modes, and refusal to use a symlink temp directory.

- [x] #76 Add optional network and filesystem isolation for parser child processes.
  - Source: parser child launcher, deployment docs, verifier environment.
  - Goal: enforce the existing guidance that parser scripts must not open network connections or read arbitrary host files.
  - Plan:
    - Batch 1: evaluate portable containment options and Linux-specific hardening such as unprivileged users, namespaces, chroot, seccomp, or container profiles.
    - Batch 2: add opt-in isolation settings that fail closed when requested isolation cannot be applied.
    - Batch 3: document operational requirements and add negative fixtures for network and outside-file access where the platform supports enforcement.
  - Done: added opt-in parser child isolation controls that can be set at
    compile time or through service environment variables. `no_new_privs` and
    private network namespace isolation are supported on Linux, and optional
    `chroot()` filesystem isolation is supported when deployments provide a
    prepared parser jail. Requested isolation fails closed when the OS or
    service privileges cannot apply it. Added optional live verifier fixtures
    for network access and outside-file access, plus deployment documentation
    for platform and jail requirements.

- [x] #77 Add parser execution audit and policy controls.
  - Source: `webservice_interface.c`, resources/roles DB handling, AI usage docs.
  - Goal: make parser execution decisions visible and policy-driven so deployments can restrict high-risk scripts before runtime.
  - Plan:
    - Batch 1: add parser policy metadata for allowed script types, reviewed status, interpreter path, timeout profile, and isolation profile.
    - Batch 2: record structured audit events for parser upload, execution, timeout, limit rejection, and cleanup failure without logging secrets or raw CSV contents.
    - Batch 3: document least-privilege parser roles and extend verifier checks for policy allow/deny behavior.
  - Done: parser execution now evaluates policy metadata from the script
    document `resourceInfo` before decrypting or running the script. Deployments
    can restrict allowed parser document types, require `parser.reviewed:true`,
    and require interpreter, timeout, and isolation profile metadata to match
    runtime settings. Parser upload, policy allow/deny, execution success,
    timeout, limit rejection, and decrypted-temp cleanup failure audit lines
    include IDs, script type, method, and result status without org keys, raw
    scripts, or CSV content. Live verifier uploads reviewed metadata, checks
    audit markers, and can run a reviewed-policy deny case for unreviewed
    scripts.

- [x] #78 Stop HTTPS startup failures from logging TLS private keys.
  - Source: `engine_admin.c`, DEBUG verifier startup checks.
  - Goal: ensure web-service startup failures never print PEM certificate/key contents or other TLS key material.
  - Done:
    - Replaced PEM-body error logging with file path/context-only diagnostics.
    - Added a verifier check that forces an HTTPS startup failure and asserts no private-key PEM markers are emitted.

- [x] #79 Redact DEBUG logs that expose org keys and decrypted values.
  - Source: `engine_interface.c`, `crypto.c`, shared redaction helpers.
  - Goal: make DEBUG/ERROR diagnostics safe to retain by default.
  - Done:
    - Replaced plaintext `orgKey` and `newOrgKey` DEBUG parameter prints with redacted markers.
    - Replaced protected-value, decrypted-value, and key diagnostics in crypto and secure DB helpers with length-only context.
    - Added live verifier checks that fail on secret-bearing DEBUG diagnostics.

- [x] #80 Redact request URLs and cap logged request values.
  - Source: `webservice_interface.c`, transaction logging, live verifier redaction.
  - Goal: prevent request logs from storing credentials or unbounded user-controlled strings.
  - Done:
    - Redacted credential-like query parameters and HTTP headers before constructing transaction log entries.
    - Added per-value and whole-field caps for logged request URLs, request headers, and response headers.
    - Added a live unauthenticated LogsDB probe that verifies secret redaction and long-value truncation.

- [x] #81 Modernize password-based key derivation defaults.
  - Source: `common.h`, `crypto.c`, storage metadata/version handling.
  - Goal: replace outdated KDF settings with migration-safe modern defaults.
  - Done:
    - Added KDF profile constants and changed the default PBKDF2 profile for new protected data to HMAC-SHA256 with 10,000 iterations.
    - Preserved read compatibility by retrying decrypt operations with the legacy PBKDF2-HMAC-SHA1/2,000 profile when the default profile fails.
    - Added DEBUG verifier coverage for the new default profile and legacy decrypt fallback, and updated PBKDF documentation.

- [x] #82 Harden HTTP TLS-auth bypass controls.
  - Source: `configure.ac`, `common.h`, `webservice_interface.c`, verifier profiles.
  - Goal: prevent test-only HTTP TLS-auth bypass from being accidentally enabled in deployable builds.
  - Done:
    - Added configure and compile-time guards so `--enable-BYPASSTLSAUTHINHTTP` is accepted only with DEBUG/test builds.
    - Made HTTP TLS-auth bypass state visible in DEBUG startup and request diagnostics without logging secrets.
    - Added verifier checks for release-profile bypass rejection and DEBUG HTTP bypass diagnostics.

- [x] #83 Add a machine-readable AI agent capability manifest.
  - Source: `webservice_interface.c`, `openapi.yaml`, AI/MCP docs, live verifier.
  - Goal: let AI agents and MCP clients discover safe CaumeDSE capabilities before sending credentials or invoking data routes.
  - Done:
    - Added public `GET /agentCapabilities` and `OPTIONS /agentCapabilities` JSON responses with auth requirements, preferred formats, parser policy state, route summaries, and documentation links.
    - Documented the manifest in README/API examples and OpenAPI.
    - Added live verifier and OpenAPI route validation coverage for the manifest.

- [x] #84 Add delegated scoped agent tokens.
  - Source: auth boundary docs, external manager integration, roles/filter setup helpers.
  - Goal: let agents use short-lived least-privilege delegated credentials instead of full organization keys.
  - Plan:
    - Batch 1: define delegated-token semantics, scope claims, expiry, revocation, and how external managers map tokens to CaumeDSE delegated users.
    - Batch 2: add a sample token broker workflow that creates narrow user/role/filter resources and never exposes `orgKey` to the model.
    - Batch 3: add verifier coverage for allowed and denied delegated scopes.
  - Done: documented delegated tokens as an external-manager concern rather
    than an in-engine bearer-token validator, added
    `samples/delegated-token-broker/` with a standard-library Python broker
    sample that mints signed opaque tokens, validates scopes/expiry/revocation,
    maps them to broker-held delegated CaumeDSE user/org credentials, and can
    provision read-only role/filter rows. Added verifier coverage through the
    broker offline self-test for allowed scope, denied scope, expiry, and
    revocation, and linked the sample from README, AI usage, AI-agent, and MCP
    docs.

- [x] #85 Add JSON error envelopes and request IDs.
  - Source: `webservice_interface.c`, transaction logging, OpenAPI.
  - Goal: make API failures easy for agents to parse and correlate with audit logs.
  - Plan:
    - Batch 1: define stable `error.code`, `error.message`, `httpStatus`, `requestId`, and `safeForAgent` fields.
    - Batch 2: add request-id generation/propagation to response headers and transaction logs.
    - Batch 3: convert common authentication, authorization, not-found, and method errors to JSON when `outputType=json`.
  - Done: added per-connection `X-Request-Id` generation in the web-service
    response path and included the header in the same response-header list
    logged to LogsDB. Added centralized JSON error envelopes for non-HEAD
    failures when `outputType=json` is requested, mapping common status codes
    to stable `error.code`, `error.message`, `httpStatus`, `requestId`, and
    `safeForAgent` fields. Extended live verifier coverage for JSON
    authentication, not-found, method-not-allowed, forbidden, and request-id
    markers, and documented the contract in README, API examples, AI usage,
    and OpenAPI.

- [x] #86 Add agent-safe paginated read and schema metadata endpoints.
  - Source: resource handlers, `openapi.yaml`, AI/MCP samples.
  - Goal: reduce large unbounded responses and give agents stable schemas before reading data.
  - Plan:
    - Batch 1: document and validate pagination parameters for JSON reads.
    - Batch 2: add document/table schema metadata routes for columns, row counts, document types, and parser policy metadata.
    - Batch 3: extend MCP and AI-agent samples to use schema discovery before row/column reads.
  - Done: added validated JSON `limit`/`offset` handling with pagination
    metadata to shared table responses, added document and secure DB table
    schema JSON endpoints with column, row-count, pagination, and parser-policy
    metadata, extended live verifier coverage, updated OpenAPI/docs, and taught
    the AI-agent and MCP samples to discover schema before bounded reads.

- [x] #87 Add an AI-generated parser upload/review workflow.
  - Source: parser script resources, parser policy metadata, verifier fixtures.
  - Goal: keep generated parser scripts pending until reviewed and allow safe sample execution before full runs.
  - Done:
    - Batch 1: defined pending/reviewed parser metadata and provenance fields such as generator, prompt hash, reviewer, and review time.
    - Batch 2: added static checks and sample-row preview execution for parser candidates.
    - Batch 3: added live verifier coverage for pending deny, reviewed allow, and preview-only execution.

- [x] #88 Add structured JSON audit logs for agent activity.
  - Source: transaction logging, parser audit lines, docs.
  - Goal: make agent actions, policy decisions, and parser execution reviewable by machines without scraping text logs.
  - Done:
    - Batch 1: defined JSON audit event schemas for auth, authorization, request, parser policy, parser upload/execution, and cleanup.
    - Batch 2: emitted structured `CaumeDSE AuditJSON: ` events alongside existing text diagnostics without changing LogsDB storage.
    - Batch 3: added an agent-readable recent-audit sample and live verifier checks for JSON parsing, required categories, and redaction.

- [x] #89 Promote the MCP prototype into a supported read-only tool surface.
  - Source: `samples/mcp-server/`, `AI_USAGE.md`, live verifier.
  - Goal: provide a stable MCP interface for agents to inspect CaumeDSE data with narrow permissions.
  - Done:
    - Batch 1: aligned supported MCP tools with `/agentCapabilities` and OpenAPI route names.
    - Batch 2: added schema validation, pagination, and safer result truncation to read tools.
    - Batch 3: added a smoke test that runs MCP initialize/tools/list/tool calls against the live verifier service.

- [x] #90 Add an AI agent cookbook and operational checklist.
  - Source: `AI_USAGE.md`, `samples/`, README.
  - Goal: make safe agent deployments repeatable for integrators.
  - Done:
    - Batch 1: added recipes for read-only document inspection, parser review/upload, audit review, and cleanup.
    - Batch 2: added deployment checklist entries for HTTPS, scoped delegated users, parser isolation, log redaction, and model prompt boundaries.
    - Batch 3: cross-linked cookbook recipes from README, API examples, MCP docs, and OpenAPI/capability metadata.

- [x] #91 Add an agent RAG data connector sample.
  - Source: `samples/agent-rag-connector/`, `samples/mcp-server/`, `AI_USAGE.md`, `openapi.yaml`.
  - Goal: show how an AI agent can retrieve CaumeDSE CSV data as bounded, schema-aware, model-ready snippets without exposing organization keys or broad sensitive rows.
  - Plan:
    - Batch 1: define a document/column allowlist configuration format with per-column redaction rules, row limits, and request-id capture.
    - Batch 2: implement a Python connector that reads `/agentCapabilities`, fetches schema metadata, validates requested columns, applies pagination limits, and emits sanitized JSON for downstream model context.
    - Batch 3: add fixtures that include sensitive and prompt-injection-style CSV cells, plus offline/live smoke checks proving redaction, bounds, and prompt-boundary behavior.
    - Batch 4: document setup, threat boundaries, broker/MCP integration options, and validation commands; link the sample from README and AI usage docs.
  - Done: added `samples/agent-rag-connector/` with a dependency-free Python
    CLI, allowlisted config, per-column redaction rules, sensitive and
    prompt-injection-style fixture data, offline fixture mode, live CaumeDSE
    capability/schema/column reads, request-id capture, model-ready JSON
    output, README documentation, README/AI_USAGE links, an offline verifier
    self-test, and a live verifier smoke check against the existing uploaded
    CSV document.

- [x] #92 Add a secure document review workspace sample.
  - Source: `samples/review-workspace/`, parser script resources, delegated-token broker sample, `AI_USAGE.md`.
  - Goal: provide a human-in-the-loop application that uploads documents, previews schemas and rows, reviews generated parser scripts, approves or rejects parser metadata, and exports redacted audit summaries.
  - Plan:
    - Batch 1: define the workspace flow for disposable organization/storage setup, reviewer assignment, parser candidate upload as pending, preview-only execution, promotion to reviewed metadata, and cleanup.
    - Batch 2: implement a small local web application or Python service that keeps CaumeDSE credentials in the server environment and exposes only bounded review actions to the browser or bot.
    - Batch 3: integrate delegated-token authorization for bot-assisted suggestions while requiring human approval before full parser execution.
    - Batch 4: add README documentation, safe fixture data, and focused verifier coverage for approve, reject, preview, reviewed-run, and cleanup paths.
  - Done: added `samples/review-workspace/` with a dependency-free Python
    service/CLI, safe and unsafe parser fixtures, CSV preview fixture, local
    approve/reject state machine, static parser checks, reviewed/rejected
    parser metadata generation, redacted audit export, live CaumeDSE commands
    for workspace creation, CSV upload, pending parser upload, schema read,
    preview-only execution, approve/reject metadata update, reviewed execution,
    and cleanup. Added README/AI_USAGE links and verifier self-test coverage
    for preview, approval, rejection, unsafe approval denial, and redacted audit
    export.

- [x] #93 Add a compliance audit dashboard sample.
  - Source: `samples/audit-dashboard/`, structured `CaumeDSE AuditJSON` service logs, `live-api-coverage.csv`, `AI_USAGE.md`.
  - Goal: make CaumeDSE traceability easier for operators and AI-assisted incident review by summarizing auth, authorization, parser policy, parser execution, request, and cleanup events without exposing secrets or raw CSV content.
  - Plan:
    - Batch 1: extend the recent-audit parsing logic into a reusable parser that groups events by request ID, user, organization, route, decision, status, and parser policy outcome.
    - Batch 2: implement a lightweight local dashboard or static HTML report generator with filters for denied auth, parser-policy denials, cleanup failures, and broad-read indicators.
    - Batch 3: add redacted export output suitable for issue reports or model context, preserving diagnostic fields while masking credentials, certificate paths, and sensitive parameters.
    - Batch 4: document how to run against DEBUG verifier logs and add smoke tests using committed representative audit fixtures.
  - Done: added `samples/audit-dashboard/` with a dependency-free Python
    parser/report generator, representative `CaumeDSE AuditJSON` and
    `live-api-coverage.csv` fixtures, redacted JSON export, static HTML report
    rendering, grouping by request ID/user/category/outcome, findings for
    denied events, parser policy denials, parser execution issues, cleanup
    failures, failed verifier coverage, and broad-read indicators. Added
    README/AI_USAGE links and verifier self-test coverage.

- [x] #94 Define the HerraduraKEx at-rest crypto design and algorithm selection.
  - Source: `crypto.c`, `crypto.h`, `common.h`, `configure.ac`, `Makefile.am`, upstream `Caume/HerraduraKEx` `README.md`, `llms.txt`, `spec/herradura-protocol-spec.json`, `docs/INTRODUCTION.md`, `docs/TUTORIAL.md`, and `herradura.h`.
  - Goal: scope HerraduraKEx support to internal CaumeDSE encryption at rest for values stored in SQLite-backed databases, without changing TLS channel encryption or HTTP transport behavior.
  - Plan:
    - Document the current OpenSSL EVP path, PBKDF profile, salt handling, GCM tag handling, HMAC handling, and every call site that encrypts or verifies data before it reaches ResourcesDB, ColumnFile DBs, or related SQLite storage.
    - Define explicit non-goals: no TLS ciphersuite changes, no HTTPS certificate changes, no HKEX-GF transport handshake, no public-key document sharing, and no signature workflow in the initial implementation.
    - Select `herradura-hske-nla1-aead-256` as the first candidate profile for protected SQLite value encryption, using upstream `hske_nl_aead_encrypt()` and `hske_nl_aead_decrypt()` where arbitrary-length plaintext support is confirmed.
    - Evaluate `herradura-hske-duplex-256` as the preferred arbitrary-length AEAD profile if its C API is cleaner for variable-size database fields than the HSKE-NL-A1 AEAD wrapper.
    - Keep `herradura-hske-nla2-256` as an optional experimental profile only when a reversible permutation mode is specifically useful; do not make it the default storage profile.
    - Use `hfscx-256` or `hfscx-256-ds` only for Herradura-native MAC or domain-separated integrity experiments after AEAD storage framing is stable; preserve existing HMAC-SHA256 behavior for compatibility unless a migration plan exists.
    - Exclude `hske` from PQC recommendations because upstream marks it classical, and exclude `hpke-stern`, `hpke-stern-kem`, and `hpks-stern` from production storage use because upstream marks the Stern flows demo-only or dependent on missing production decoder/round settings.
    - Defer `hkex-rnl` to a future key-wrapping or offline key-establishment design; it is not needed for direct encryption of SQLite data at rest.
  - Done: added `HERRADURAKEX_AT_REST_PLAN.md` with the current CDSE storage
    crypto baseline, HerraduraKEx upstream findings, explicit non-goals for
    TLS and public-key workflows, recommended PQC-oriented at-rest algorithms,
    excluded algorithms, ciphertext framing direction, associated-data
    guidance, compatibility rules, verification requirements, and the proposed
    implementation order.

- [x] #95 Add optional HerraduraKEx build and dependency integration.
  - Source: `configure.ac`, `Makefile.am`, `crypto.c`, `crypto.h`, upstream `herradura.h`, and upstream `bindings/ffi/`.
  - Goal: make HerraduraKEx available as an opt-in internal crypto provider without affecting default OpenSSL builds.
  - Plan:
    - Add a configure option such as `--enable-HERRADURAKEX` or `--with-herradurakex=PATH` that defaults off and leaves current builds byte-for-byte behaviorally unchanged.
    - Decide whether to vendor a reviewed `herradura.h` snapshot or consume an installed header; complete a license compatibility review first because the GitHub repository reports a non-standard `Other` license.
    - Prefer direct C header integration over the current FFI shim for PQC storage profiles, because upstream documents the FFI as exposing only the classical HKEX-GF, HSKE, HPKS, and HPKE quartet and not the NL/PQC or Stern APIs.
    - Add compile checks for `herradura.h`, expected constants such as 256-bit keys, and the selected AEAD entry points.
    - Keep all HerraduraKEx code behind compile-time guards so unsupported builds reject Herradura algorithm names with a clear error instead of silently falling back to OpenSSL.
    - Add build documentation that names the exact upstream commit or release used for review.
  - Done: added an opt-in `--enable-HERRADURAKEX` configure path with
    `--with-herradurakex=DIR` include discovery, direct `herradura.h` checks,
    256-bit key constant checks, HSKE-NL AEAD entry point checks, a
    `CDSE_ENABLE_HERRADURAKEX` compile-time feature macro, Makefile include
    flag propagation, and build-status documentation tied to reviewed upstream
    commit `13e5fb0346ca5ec81202dee8bb3302633780ec35`. Runtime Herradura
    algorithm dispatch remains deferred to TODO #96 and TODO #97.

- [x] #96 Add a storage crypto profile abstraction for non-EVP algorithms.
  - Source: `crypto.c`, `crypto.h`, `common.h`, ResourcesDB metadata handling, ColumnFile metadata handling, and existing encryption algorithm configuration paths.
  - Goal: allow CaumeDSE to dispatch between existing OpenSSL EVP algorithms and HerraduraKEx storage profiles while preserving backward compatibility for existing encrypted databases.
  - Plan:
    - Introduce internal profile metadata for algorithm id, provider, key length, nonce length, salt length, tag length, AEAD support, and ciphertext framing version.
    - Keep existing OpenSSL EVP algorithm names mapped to the current `cmeCipherByteString()` behavior.
    - Add Herradura algorithm ids such as `herradura-hske-nla1-aead-256` and, if selected by TODO #94, `herradura-hske-duplex-256`.
    - Define a stable protected-value frame for Herradura ciphertexts, including magic/version, algorithm id or compact profile id, nonce, tag, and ciphertext bytes.
    - Define associated data inputs for SQLite at-rest encryption, favoring stable metadata such as algorithm id, salt, database role, table/field scope, and immutable document or storage identifiers; avoid mutable metadata that would break normal updates.
    - Ensure salt/PBKDF handling remains explicit and versioned so current key derivation can coexist with any future Herradura-specific KDF profile.
  - Done: added `cmeCryptoProfile` metadata and lookup helpers, dynamic
    OpenSSL EVP profile resolution, planned HerraduraKEx storage profile ids,
    provider/key/nonce/salt/tag/AEAD/frame metadata, provider-aware default
    algorithm validation, an OpenSSL-only guard in `cmeCipherByteString()`, and
    DEBUG component coverage proving existing EVP profiles still resolve while
    Herradura profiles remain metadata-only until TODO #97 implements wrappers.

- [x] #97 Implement HerraduraKEx at-rest encryption and decryption wrappers.
  - Source: `crypto.c`, `crypto.h`, selected upstream `herradura.h` APIs, and DEBUG crypto component tests.
  - Goal: add round-trip encryption support for HerraduraKEx-protected SQLite values through the same internal encryption interfaces CaumeDSE already uses.
  - Plan:
    - Convert CDSE byte keys, nonces, plaintext, ciphertext, and tags into the upstream HerraduraKEx C structures without leaking temporary material.
    - Implement encrypt and decrypt paths for the selected AEAD profile, returning authentication failure distinctly from parse, unsupported-algorithm, and allocation failures.
    - Preserve existing OpenSSL GCM tag behavior for current algorithms and keep Herradura framing separate to avoid ambiguous ciphertext parsing.
    - Cleanse or tightly scope derived keys, nonces, tags, and temporary buffers before returning from error paths.
    - Add negative tests for wrong key, wrong salt, modified nonce, modified tag, modified ciphertext, truncated frame, unsupported profile id, and malformed associated data.
    - Add mixed-profile tests proving old AES-protected values and new Herradura-protected values can be read in the same DEBUG environment.
  - Done: added guarded HerraduraKEx byte-string wrapper paths for
    `herradura-hske-nla1-aead-256` and `herradura-hske-duplex-256`, a
    versioned `CDSEHKX1` frame with profile id, flags, nonce, tag, and
    ciphertext, PBKDF2-HMAC-SHA256 key derivation into 32-byte Herradura keys,
    AAD binding for CDSE domain/profile/salt, authentication-failure handling,
    buffer cleansing on cleanup paths, and DEBUG coverage proving default
    builds reject Herradura encryption when the provider is not compiled in.
    Default-profile enablement and SQLite metadata migration remain deferred to
    TODO #98.

- [x] #98 Add SQLite metadata, configuration, and migration safeguards for Herradura profiles.
  - Source: ResourcesDB schema usage, ColumnFile DB metadata, organization/storage configuration flows, `README.md`, `TUTORIAL.md`, and live verifier setup.
  - Goal: make HerraduraKEx storage encryption opt-in, discoverable, and reversible without forcing automatic migration of existing encrypted data.
  - Plan:
    - Store the exact Herradura algorithm/profile id wherever CaumeDSE currently records encryption algorithm metadata.
    - Reject Herradura profile requests at configuration time when the binary was built without HerraduraKEx support.
    - Keep existing databases readable without metadata rewrites, and allow mixed old/new encrypted records during phased adoption.
    - Do not auto-migrate existing SQLite data; define a separate explicit re-protect or export/import workflow for later implementation.
    - Add diagnostics that distinguish unsupported algorithm, missing build support, failed authentication, and corrupted ciphertext frame.
    - Document rollback expectations: existing AES data remains usable, while Herradura-protected data requires a Herradura-enabled binary.
  - Done: Herradura-enabled builds now allow HSKE-NL-A1 AEAD and HSKE duplex
    as explicit default storage profiles while default builds reject those
    names. Herradura protected values carry the exact compact profile id in the
    `CDSEHKX1` frame, decrypt dispatch uses that embedded metadata, and
    unframed legacy protected values fall back to `aes-256-gcm` when a
    Herradura profile is configured for new writes. HMAC key derivation and
    engine-admin startup validation now use storage profile metadata instead of
    requiring the default profile to be an OpenSSL EVP cipher. No SQLite data is
    rewritten automatically; AES rows remain readable and Herradura rows require
    a Herradura-enabled binary.

- [x] #99 Add verifier and component coverage for Herradura at-rest encryption.
  - Source: `debug_tests.c`, `function_tests.c`, `TEST/run_debug_components.sh`, live verifier fixtures, and crypto DEBUG markers.
  - Goal: prove HerraduraKEx storage profiles protect SQLite data at rest and fail closed on tampering.
  - Plan:
    - Add DEBUG component tests for profile lookup, frame encode/decode, encryption/decryption, and all negative authentication cases from TODO #97.
    - Add live verifier coverage that creates a Herradura-enabled organization/storage profile, uploads CSV data, reads it back through normal APIs, and confirms protected storage bytes differ from plaintext.
    - Add tamper fixtures for nonce, tag, ciphertext, salt, and algorithm metadata where practical.
    - Add skip behavior when HerraduraKEx support is not compiled in, so default CI remains stable.
    - Include focused HTTP and HTTPS verifier modes only to prove normal API behavior still works; do not test or alter TLS channel algorithms.
    - Record performance smoke numbers for representative small and large field values without making throughput a pass/fail gate.
  - Batch 1 done: extended DEBUG crypto coverage for Herradura wrong-key,
    wrong-salt, tampered tag, tampered nonce, tampered ciphertext, unsupported
    profile id, truncated frame, embedded profile decrypt, legacy AES fallback,
    and duplex round trip. `TEST/run_debug_components.sh` now supports
    `CDSE_VERIFY_HERRADURAKEX_DIR` for opt-in Herradura builds, optional
    `CDSE_VERIFY_HERRADURAKEX_DEFAULT_PROFILE`, and a Herradura component marker
    group that skips cleanly when the provider is not requested.
  - Done: live verifier runs with `CDSE_VERIFY_HERRADURAKEX_DIR` now default to
    `herradura-hske-nla1-aead-256` unless another Herradura profile is supplied,
    upload and read back the normal CSV fixture through the existing HTTP/HTTPS
    API flow, upload a larger CSV for timing-only smoke data, scan the backing
    SQLite files for decoded `CDSEHKX1` frames/profile id `1`, and fail if
    representative plaintext values appear in the SQLite-backed storage. Default
    verifier runs skip the Herradura-specific live checks.

- [x] #100 Document HerraduraKEx PQC storage recommendations and operational boundaries.
  - Source: `README.md`, `TUTORIAL.md`, `API_EXAMPLES.md`, `AI_USAGE.md`, and upstream `Caume/HerraduraKEx` documentation.
  - Goal: give operators, developers, and AI agents clear guidance for when and how to use HerraduraKEx inside CaumeDSE.
  - Plan:
    - Recommend `herradura-hske-nla1-aead-256` as the initial PQC-oriented at-rest encryption candidate when upstream arbitrary-length AEAD behavior is validated in CDSE tests.
    - Recommend `herradura-hske-duplex-256` for evaluation when CDSE needs a direct arbitrary-length AEAD interface for variable-size SQLite fields.
    - Mark `herradura-hske-nla2-256` experimental for storage unless a specific reversible-permutation use case is documented.
    - Mark `hfscx-256` and `hfscx-256-ds` as candidate Herradura-native hash/MAC primitives, not replacements for existing compatibility MACs in the first implementation.
    - Explicitly state that `hkex-rnl` is a future key-wrapping or key-establishment candidate, not a direct SQLite field encryption algorithm.
    - Explicitly state that `hpke-stern`, `hpke-stern-kem`, and `hpks-stern` are not recommended for production CDSE storage until upstream production decoder and round requirements are satisfied.
    - Explain that HerraduraKEx support is opt-in, experimental until reviewed, and scoped to data encryption at rest; TLS channel encryption remains configured through the existing OpenSSL/HTTPS stack.
  - Done: added operator, tutorial, API-example, and AI-agent guidance for
    HerraduraKEx at-rest storage profiles. The docs recommend
    `herradura-hske-nla1-aead-256` as the initial PQC-oriented candidate,
    position `herradura-hske-duplex-256` for evaluation, keep
    `herradura-hske-nla2-256` experimental, defer `hkex-rnl` to key wrapping or
    key establishment, keep `hfscx-256`/`hfscx-256-ds` as future MAC/hash
    candidates, exclude Stern HPKE/HPKS profiles from production storage, and
    state that HerraduraKEx changes only SQLite-backed at-rest protection, not
    TLS channel encryption.

- [x] #101 Add independent tests for Herradura cryptographic algorithms.
  - Source: upstream `Caume/HerraduraKEx` reference tests or examples, `herradura.h`, `crypto.c`, `function_tests.c`, and `TEST/run_debug_components.sh`.
  - Goal: verify HerraduraKEx primitives independently from the CaumeDSE SQLite at-rest wrapper so CDSE can distinguish upstream algorithm behavior from CDSE framing, PBKDF, metadata, or storage bugs.
  - Plan:
    - Add deterministic known-answer tests for the Herradura algorithms CDSE exposes or plans to expose, starting with `herradura-hske-nla1-aead-256` and `herradura-hske-duplex-256`.
    - Cover fixed keys, nonces, associated data, plaintext sizes including empty, one-byte, block-boundary, multi-block, and multi-kilobyte inputs.
    - Add negative authentication tests that mutate key, nonce, tag, ciphertext, associated data, and algorithm/profile selection without involving SQLite storage.
    - Add independent tests for `hfscx-256` and `hfscx-256-ds` once CDSE evaluates them as future hash/MAC candidates.
    - Add skip behavior for default builds without `--enable-HERRADURAKEX`, while making Herradura-enabled verifier runs fail clearly on upstream API drift or changed test vectors.
    - Prefer upstream-reviewed vectors where available; if CDSE must generate vectors, record the HerraduraKEx commit, generator command, inputs, outputs, and review status in committed test fixtures.
  - Done: added `testHerraduraIndependent()` to call upstream `herradura.h`
    primitives directly, independent from CDSE SQLite storage, PBKDF, and
    `CDSEHKX1` framing. Coverage now includes hard-coded deterministic vectors
    for HSKE-NL-A1 AEAD, HSKE duplex, empty plaintext tags, HFSCX-256, and
    HFSCX-256-DS; fixed-size round trips for empty, one-byte, boundary,
    multi-block, and multi-kilobyte inputs; and negative direct API checks for
    mutated key, nonce, associated data, ciphertext, tag, and wrong profile
    selection. Vector provenance is recorded in
    `TEST/testfiles/herradurakex-independent-vectors.txt`. The DEBUG verifier now
    has a separate `herradurakex_independent` component that skips without a
    requested Herradura provider and fails Herradura-enabled runs on vector/API
    drift.

- [ ] #102 Add an explicit key rotation and re-protect service.
  - Source: `crypto.c`, `db.c`, `engine_interface.c`, `webservice_interface.c`, ResourcesDB/ColumnFile DB metadata, `README.md`, `TUTORIAL.md`, and `TEST/run_debug_components.sh`.
  - Goal: let operators rotate organization keys or migrate selected protected values between storage profiles, including AES-to-Herradura transitions, without automatic background migration.
  - Plan:
    - Define an explicit re-protect command/API workflow that requires current key material, new key material, target storage profile, and an operator-confirmed scope.
    - Support dry-run inventory reporting for affected organizations, storage resources, documents, tables, row counts, profile ids, and legacy unframed AES values.
    - Re-encrypt values through existing protect/unprotect wrappers so profile metadata, salts, `CDSEHKX1` frames, and legacy AES fallback behavior stay consistent.
    - Preserve rollback expectations by allowing staged migration and mixed AES/Herradura data until the operator commits the final scope.
    - Add failure-safe journaling or resumable checkpoints so interrupted migrations do not leave ambiguous key/profile state.
    - Add DEBUG and live verifier coverage for key rotation, profile migration, wrong-key rejection, partial-scope migration, dry-run output, and rollback/readback behavior.
  - Batch 1: added `cmeReprotectDBSaltedValue()` as a strict per-value re-protect primitive for explicit workflows, including dry-run length reporting, source-key rejection, target profile selection, new salt generation, AES key rotation, and AES/Herradura migration/rollback DEBUG component markers when the provider is enabled.
  - Batch 2: added `cmeInventoryMemSecureDBReprotect()` for read-only column-file dry-run inventory, reporting meta/data row counts, protect metadata rows, protected value scope, source/target profiles, and legacy AES versus Herradura-framed protected values without mutating the DB.
  - Batch 3: added `cmeReprotectMemSecureDB()` as an explicit DB-level re-protect service for protected column-file rows, with dry-run reporting, wrong source-key rejection, single-transaction mutation, target-profile metadata update, new row/meta salts, new-key readback coverage, and fail-closed rejection for MAC/sign metadata until the dedicated recomputation workflow is implemented.
  - Batch 4: documented the operator-held backup/journal/checkpoint workflow for explicit key/profile rotation, including dry-run inventory review, per-ColumnFile checkpoints before mutation/after transaction/after readback, secret-free journal records, mixed AES/Herradura staged migration, and restore-or-old-checkpoint rollback expectations.
  - Batch 5: added `samples/reprotect-workflow/` with a secret-free scope format, redacted journal/checkpoint planning, mixed AES/Herradura inventory preservation, MAC/sign fail-closed validation, README guidance, and an offline verifier self-test.
  - Batch 6: added re-protect journal resume/status reporting so saved plans can identify pending, resumable, complete, and blocked ColumnFile steps without exposing checkpoint paths or key material.

- [x] #103 Harden verifier web startup diagnostics and reliability.
  - Source: `engine_admin.c`, `debug_tests.c`, `TEST/run_debug_components.sh`, libmicrohttpd startup options, generated test certificates, and live verifier logs.
  - Goal: make HTTP/HTTPS verifier startup failures actionable and reduce false failures when local ports, daemon flags, certificates, or environment limits prevent `MHD_start_daemon()` from starting.
  - Plan:
    - Add preflight diagnostics for selected HTTP/HTTPS ports, bind address, process ownership, certificate/key/CA readability, libmicrohttpd version, and relevant daemon flags.
    - Improve `cmeWebServiceSetup()` error reporting with errno-adjacent context where available and distinct diagnostics for HTTP, HTTPS, certificate loading, signal-handler setup, and daemon startup.
    - Add fallback or configurable alternate port selection for verifier runs when the default ports are unavailable.
    - Capture startup diagnostics into dedicated verifier logs and include concise failure hints in `summary.txt`.
    - Add DEBUG component tests for expected startup failure redaction and verifier self-tests for port validation, timeout behavior, and skipped live-flow handling.
  - Batch 1: added webservice preflight self-tests for TCP port validation, a dedicated `webservice-startup-preflight.log` with selected protocol/ports, curl/libmicrohttpd availability, listener diagnostics, and certificate readability/size checks, plus richer `cmeWebServiceSetup()` HTTP/HTTPS daemon-start failure diagnostics with daemon flags, thread limits, connection limits, and errno context.
  - Batch 2: added verifier-side automatic alternate-port selection for occupied default HTTP/HTTPS ports, preserving explicit operator-selected ports as fail-fast choices, recording auto-port settings in the preflight log, and extending preflight helper self-tests for environment flag and avoid-port behavior.
  - Batch 3: added concise `HINT` lines to verifier summaries for web startup, port-selection, invalid-port, occupied-port, and missing-curl failures so operators can jump directly to preflight logs, selected ports, auto-port settings, and errno diagnostics.

- [x] #104 Add a guarded write-capable MCP service sample.
  - Source: `samples/mcp-server/`, `samples/delegated-token-broker/`, `AI_USAGE.md`, `openapi.yaml`, live verifier routes, and delegated-token patterns.
  - Goal: provide an MCP sample that can perform controlled writes while keeping organization keys out of model context and requiring explicit guardrails for mutations.
  - Plan:
    - Keep read-only MCP tools as the default and expose write tools only behind `CDSE_MCP_ENABLE_WRITE_TOOLS=1` plus delegated-token configuration.
    - Add guarded tools for CSV upload, parser candidate upload, parser preview, reviewed metadata update, narrow document deletion, and cleanup of disposable resources.
    - Require explicit tool arguments for organization, storage, document, user, scope, expected status, and idempotency key; reject broad or implicit writes.
    - Integrate with the delegated-token broker sample so MCP clients never receive raw `orgKey` or `newOrgKey`.
    - Add dry-run output, redacted audit correlation, and clear refusal messages for unsafe parser execution or broad data mutation.
    - Add sample README guidance and verifier self-tests that prove write tools are hidden by default and guarded when enabled.
  - Batch 1: tightened the MCP sample so write tools require both `CDSE_MCP_ENABLE_WRITE_TOOLS=1` and `CDSE_MCP_DELEGATED_TOKEN`, added per-call guard fields for exact organization/storage/user/scope, expected status, idempotency key, confirmation, and dry-run mode, documented the write boundary, and added an offline verifier self-test for hidden/default write tools and broad-scope rejection.
  - Batch 2: added guarded `promote_parser_review` and `delete_document` write tools with exact parser-review and document-delete scopes, reviewed metadata dry-run/update plans, request-id audit summaries, document-type limits for narrow deletion, README guidance, and offline self-test coverage for promotion, exact delete, broad delete rejection, and unsupported document-type rejection.
  - Batch 3: integrated broker-style delegated token verification into the MCP write guard when `CDSE_MCP_DELEGATED_TOKEN_SECRET` is configured, checking HMAC signature, expiry, CaumeDSE organization/user binding, and exact write scope before each mutation, with README guidance and offline self-test coverage for accepted and missing-scope tokens.

- [ ] #105 Add a policy-as-code authorization tester.
  - Source: roleTables, filterWhitelist/filterBlacklist handlers, `TEST/run_debug_components.sh`, `samples/`, `AI_USAGE.md`, and `API_EXAMPLES.md`.
  - Goal: let operators and AI-assisted workflows declare intended access policy and verify that CaumeDSE role/filter resources enforce it before deployment.
  - Plan:
    - Define a simple JSON or YAML policy format for users, roles, allowed routes, denied routes, methods, storage/document scopes, and expected status codes.
    - Build a CLI/sample runner that creates disposable organizations and resources, applies roleTables and whitelist/blacklist filters, and executes expected allow/deny probes.
    - Emit a redacted report that maps each policy rule to observed HTTP status, request id, route, and relevant audit category.
    - Add negative cases for overbroad roles, missing filters, conflicting whitelist/blacklist rows, unsupported methods, and cleanup failures.
    - Add documentation for AI-generated policy review, including prompt-boundary rules and human approval before applying generated policies to real deployments.
  - Batch 1: added `samples/policy-authz-tester/` with a JSON policy format, setup-plan rendering for roleTables/filterWhitelist/filterBlacklist intent, offline observed-status evaluation, redacted `safeForAgent` reports, documentation, and a verifier self-test for validation, mismatch detection, and secret redaction.
  - Batch 2: added a live-capable `probe` command for executing policy rules against a CaumeDSE base URL, with dry-run URL rendering, auth query redaction, observed status/request-id collection, README guidance, and expanded offline self-test coverage for probe planning.
  - Batch 3: added static policy-risk validation for overbroad role resources, unsupported methods, mutating roles without blacklist controls, and conflicting whitelist/blacklist method rules before probe execution.

- [x] #106 Add an encrypted backup and restore utility.
  - Source: storage path layout, ResourcesDB/ColumnFile DB handling, `filehandling.c`, `crypto.c`, `samples/`, `README.md`, and verifier fixtures.
  - Goal: provide a portable, integrity-checked backup/restore workflow for CaumeDSE data directories and metadata, including mixed AES/Herradura protected data.
  - Plan:
    - Define a backup manifest containing schema version, file list, sizes, hashes, storage profile metadata, creation time, and redacted organization/storage identifiers.
    - Encrypt backup payloads with the configured storage crypto profile while keeping key handling outside model-visible logs and command lines.
    - Support restore into a fresh prefix with dry-run validation, manifest verification, profile compatibility checks, and explicit overwrite controls.
    - Preserve mixed AES/Herradura data without rewriting protected values unless the operator separately invokes the re-protect workflow.
    - Add verifier coverage for backup creation, tamper detection, wrong-key rejection, restore readback, redaction, and cleanup of temporary archive material.
  - Batch 1: added `samples/encrypted-backup-restore/` with a portable manifest utility that inventories CaumeDSE data directories, records file sizes/SHA-256 hashes/classification, redacts identifier-like labels and paths, verifies tamper/missing-file status, renders dry-run restore plans, documents the workflow, and adds an offline verifier self-test.
  - Batch 2: finished the sample workflow with encrypted backup packages, OpenSSL/PBKDF2 payload encryption with passphrases read from environment or key files, outer HMAC-SHA256 authentication for wrong-key/tamper rejection, restore execution into fresh prefixes with overwrite gates, expected-profile compatibility checks, byte-preserving restore of mixed AES/Herradura data, README operator examples, and expanded offline self-test coverage for backup creation, wrong-key rejection, tamper detection, restore readback, and temporary archive cleanup.

- [ ] #107 Add an operational health and readiness service.
  - Source: `engine_admin.c`, `webservice_interface.c`, `config.c`, `runtime.c`, parser policy configuration, storage path checks, TLS/auth configuration, and `AI_USAGE.md`.
  - Goal: expose a safe readiness view for operators and automation without leaking secrets or protected data.
  - Plan:
    - Add a CLI command or authenticated endpoint that reports database accessibility, configured storage crypto profile, Herradura build availability, parser policy, temp-directory safety, TLS-auth state, build mode, storage path readability/writability, and verifier-relevant limits.
    - Redact secret values and avoid returning organization keys, certificate private keys, access passwords, OAuth secrets, or document contents.
    - Include machine-readable JSON output for monitoring and AI-agent preflight checks, plus concise human-readable output for operators.
    - Return distinct status codes or readiness states for healthy, degraded, misconfigured, and unsafe DEBUG-only configurations.
    - Add DEBUG and live verifier coverage for healthy readiness, missing storage path, unsafe parser temp directory, Herradura-disabled profile requests, and redacted output.
  - Batch 1: added `samples/operational-readiness/` with safe JSON/text readiness output, storage path and parser temp checks, storage-profile/Herradura availability checks, TLS-auth/build-mode/parser-policy state reporting, redaction, distinct readiness states, README guidance, and an offline verifier self-test.
