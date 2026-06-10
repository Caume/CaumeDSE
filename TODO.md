# TODO

## Speed Optimizations That Preserve Security and Integrity

- [ ] #1 Add deterministic protected lookup columns for searchable encrypted fields.
  - Target fields include `documentId`, `orgResourceId`, `storageId`, `type`, and user/organization identifiers used in filters.
  - Use a keyed blind index such as `HMAC(searchKey, fieldName || "\0" || plaintext)` and add SQLite indexes over those lookup columns.
  - Keep encrypted values, salts, and MAC verification unchanged.

- [x] #2 Replace generated hot-loop INSERT/UPDATE SQL strings with prepared statements.
  - Use `sqlite3_prepare_v2`, `sqlite3_bind_*`, `sqlite3_step`, and `sqlite3_reset` in bulk insert/update loops.
  - Preserve existing transaction boundaries where immediate consistency requires them.
  - Done: `db.c` memory table insert and secure DB protect/unprotect update loops now use prepared statements.
  - Done: `filehandling.c` CSV and memory-table import insert builders for `meta` and `data` tables now use prepared statements.

- [x] #3 Replace request spin/yield waits with event-driven synchronization.
  - Current `sleep(cmeDefaultThreadWaitSeconds)` loops can become busy-yield loops when the wait value is zero.
  - Prefer libmicrohttpd request lifecycle handling or `pthread_cond_t` signaling.
  - Done: POST request status handoff now uses per-connection `pthread_cond_t` signaling instead of `sleep(0)` loops.

- [ ] #4 Narrow the parser script Perl mutex.
  - Keep shared Perl interpreter calls serialized.
  - Move DB/file work, secure DB reconstruction, response construction, and cleanup outside the global Perl lock where possible.

- [ ] #5 Avoid reapplying SQLite PRAGMAs on every DB open.
  - Split memory DB and file DB open setup.
  - Apply WAL/synchronous/cache settings only where they are useful and check PRAGMA errors.

- [ ] #6 Cache logs table schema validation.
  - Validate/create the transactions table at startup or first use under a mutex.
  - Continue writing each log record immediately.

- [x] #7 Increase streaming and POST chunk sizes.
  - Raise POST processing buffer to reduce callback overhead.
  - Raise response callback page size for large responses.

- [ ] #8 Batch only in-memory transformations before immediate durable saves.
  - Combine related temporary memory DB updates with prepared statements or a transaction.
  - Do not defer protected file/resources DB writes after a logical change.

- [x] #9 Add an independent component verification script for DEBUG builds.
  - Create a script such as `TEST/run_debug_components.sh` that configures a DEBUG/TESTDATABASE install under `/tmp`, builds, installs, runs the engine non-interactively, and writes one log per component.
  - Split validation into explicit component checks instead of relying on one monolithic debug log: crypto GCM byte-string round trip, streaming symmetric crypto, digest, HMAC/PBKDF, Perl interpreter calls, engine/admin DB setup, SQLite thread safety, CSV-to-secure-DB round trip, memory-table-to-secure-DB round trip, MAC/MACProtected integrity verification, and HTTP/HTTPS web-service startup.
  - Treat each component as pass/fail by checking command exit codes plus required log markers and forbidden markers such as `CaumeDSE Error`, `FAILED`, `FAIL:`, `can't start`, crashes, assertion failures, and timeouts.
  - Run web-service checks through an approved/unsandboxed command path or a clearly documented mode because libmicrohttpd must bind local ports; fail early if the selected ports are occupied.
  - Produce a concise final summary with component names, status, log paths, elapsed time, and the first failing marker so regressions do not require manually reading the full DEBUG output.
  - Implemented in `TEST/run_debug_components.sh`.
  - Longer-term: move DEBUG tests out of `main.c` into a dedicated test executable or selectable test harness so each unit/component can run independently without starting unrelated subsystems.
