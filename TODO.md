# TODO

## Speed Optimizations That Preserve Security and Integrity

- [ ] Add deterministic protected lookup columns for searchable encrypted fields.
  - Target fields include `documentId`, `orgResourceId`, `storageId`, `type`, and user/organization identifiers used in filters.
  - Use a keyed blind index such as `HMAC(searchKey, fieldName || "\0" || plaintext)` and add SQLite indexes over those lookup columns.
  - Keep encrypted values, salts, and MAC verification unchanged.

- [ ] Replace generated hot-loop INSERT/UPDATE SQL strings with prepared statements.
  - Use `sqlite3_prepare_v2`, `sqlite3_bind_*`, `sqlite3_step`, and `sqlite3_reset` in bulk insert/update loops.
  - Preserve existing transaction boundaries where immediate consistency requires them.

- [ ] Replace request spin/yield waits with event-driven synchronization.
  - Current `sleep(cmeDefaultThreadWaitSeconds)` loops can become busy-yield loops when the wait value is zero.
  - Prefer libmicrohttpd request lifecycle handling or `pthread_cond_t` signaling.

- [ ] Narrow the parser script Perl mutex.
  - Keep shared Perl interpreter calls serialized.
  - Move DB/file work, secure DB reconstruction, response construction, and cleanup outside the global Perl lock where possible.

- [ ] Avoid reapplying SQLite PRAGMAs on every DB open.
  - Split memory DB and file DB open setup.
  - Apply WAL/synchronous/cache settings only where they are useful and check PRAGMA errors.

- [ ] Cache logs table schema validation.
  - Validate/create the transactions table at startup or first use under a mutex.
  - Continue writing each log record immediately.

- [x] Increase streaming and POST chunk sizes.
  - Raise POST processing buffer to reduce callback overhead.
  - Raise response callback page size for large responses.

- [ ] Batch only in-memory transformations before immediate durable saves.
  - Combine related temporary memory DB updates with prepared statements or a transaction.
  - Do not defer protected file/resources DB writes after a logical change.

