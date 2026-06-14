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

- [ ] #18 Finish and verify `/documents/{document}/contentColumns` resources for `file.csv`.
  - Review existing `contentColumns` routing and CSV column manipulation paths to determine whether the README marker is stale or the feature is partial.
  - Define column creation, retrieval, deletion, empty-document creation, duplicate-column handling, and error behavior for missing columns.
  - Implement or complete handlers using in-memory transformations followed by immediate durable secure-DB/file saves.
  - Preserve encrypted part MAC verification and the security goal of column shuffling, including safe behavior when duplicate column names exist.
  - Add tests for get, create, delete, duplicate names, last-column deletion, missing documents, non-CSV documents, and unauthorized access.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.

- [ ] #19 Implement direct encrypted DB browsing resources under `/dbNames`.
  - Define the scope and security model for `/dbNames`, `{dbName}`, `/dbTables`, `{dbTable}`, `/tableRows`, `{tableRow}`, `/tableColumns`, and `{tableColumn}`.
  - Decide whether this hierarchy exposes only internal/admin databases, user data databases, or a restricted diagnostics view, and document the decision.
  - Add route parsing and handlers that never expose decrypted protected values unless the caller is authorized and supplies the required organization key.
  - Use prepared statements and strict identifier validation for database/table/row/column selectors.
  - Add tests for listing databases, listing tables, reading rows/columns, rejecting invalid identifiers, authorization failures, and SQL injection attempts.
  - Document the API and remove the README hierarchy `[not implemented]` marker after verification.

## Source Code TODO/FIXME Markers

- [ ] #20 Replace `main` placeholders in Autoconf library checks with real function probes.
  - Source: `configure.ac:42`, `configure.ac:44`, `configure.ac:46`, `configure.ac:48`, `configure.ac:50`, `configure.ac:52`, `configure.ac:54`, `configure.ac:56`, `configure.ac:58`, `configure.ac:60`, `configure.ac:62`, `configure.ac:64`.

- [ ] #21 Add cloud storage wrappers for file handling.
  - Source: `filehandling.c:53`.

- [ ] #22 Factor common in-memory DB creation for CSV and memory-table imports.
  - Source: `filehandling.c:649`, `filehandling.c:1687`.

- [ ] #23 Add SQL DB filename collision handling.
  - Source: `filehandling.c:678`, `filehandling.c:1727`.

- [ ] #24 Factor secure DB import insertion logic into a shared helper.
  - Source: `filehandling.c:799`, `filehandling.c:1848`.

- [ ] #25 Implement MAC and protected MAC calculation during secure DB import.
  - Source: `filehandling.c:840`, `filehandling.c:1889`.

- [ ] #26 Verify locale settings for `printf`, including UTF-8 behavior.
  - Source: `main.c:66`.

- [ ] #27 Move DEBUG tests into a dedicated executable or test harness.
  - Source: `main.c:136`.
  - Related roadmap item: `#9`.

- [ ] #28 Improve administrator key screen cleanup or use a sensitive terminal I/O library.
  - Source: `engine_admin.c:424`.

- [ ] #29 Add basic error handling for certificate file loading.
  - Source: `engine_admin.c:803`.

- [ ] #30 Replace temporary web-service `getchar()` waits with an exception/stop handler.
  - Source: `engine_admin.c:872`.

- [ ] #31 Process whitelist and blacklist regex filter lists in ResourcesDB.
  - Source: `engine_admin.c:1126`.
  - Related roadmap items: `#13`, `#14`.

- [x] #32 Sanitize variables used in string handling and generated queries.
  - Source: `strhandling.c:292`, `strhandling.c:309`, `db.c:66`, `webservice_interface.c:544`.
  - Done: added shared SQL identifier and unsafe input checks, sanitized legacy INSERT/UPDATE builder values, and rejected unsafe web-service route/query tokens before DB processing.

- [x] #33 Verify `WHERE` usage that may not match `userId`.
  - Source: `strhandling.c:308`.
  - Done: `cmeStrSqlUPDATEConstruct()` has no current call sites and builds its `WHERE` clause from the explicit `matchColumn`/`matchValue` arguments, with identifier validation and value sanitization from item `#32`; documented that it must not assume `userId`.

- [x] #34 Add response formatting support for HTML, CSV, and other requested output types.
  - Source: `strhandling.c:376`, `webservice_interface.c:2444`, `webservice_interface.c:4113`, `webservice_interface.c:5343`.
  - Done: added a shared count response formatter for DELETE results that honors `outputType=csv` and the default/explicit HTML format, and routed existing DELETE count responses through it.

- [ ] #35 Add OAuth authentication or document the required external manager layer.
  - Source: `webservice_interface.c:615`.

- [ ] #36 Process storage `documentTypes` and `documents` resource tree requests.
  - Source: `webservice_interface.c:1015`.
  - Related roadmap item: `#15`.

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
