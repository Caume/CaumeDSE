# CaumeDSE Re-Protect Workflow Planner

This sample renders an operator-facing plan for explicit organization-key
rotation or storage-profile migration of protected ColumnFile databases.

It is intentionally secret-free: scope files name organizations, storage,
documents, row counts, and crypto profiles, but never contain `orgKey`,
`newOrgKey`, delegated tokens, TLS private keys, or backup passphrases. The
actual mutation remains inside CaumeDSE through `cmeReprotectMemSecureDB()`.

## Commands

`caumedse-admin` is installed by `make install`. Generated commands now invoke
the offline staging interface, not a registered-storage executor. Set
`CDSE_COLUMNFILE_ROOT` to the canonical absolute path of a trusted directory
containing offline exported SQLite ColumnFiles, and `CDSE_CHECKPOINT_ROOT` to
a private existing parent directory. Each scope `name` must be a basename.
Set `CDSE_SOURCE_ORG_KEY_FILE` and `CDSE_TARGET_ORG_KEY_FILE` to owner-only key
files. The organization/storage/document fields remain operator inventory,
not assertions verified by the command. Review that mapping before execution.

The command confirms the exact source realpath, leaves it unchanged, and
writes a new per-step directory containing `before.sqlite`, `after.sqlite`,
and `status`. A `verified` status means persisted target readback matched
source plaintext; it does not mean live ResourcesDB registration was updated.
An incomplete directory is not resumable automatically: inspect/retain it and
retry with a new output directory. Never substitute these artifacts into live
storage without its registration/MAC workflow. The root README's
`caumedse-admin reprotect-storage` command stages complete flat, single-key
exports including internal databases and registered payload MACs. This planner
still emits standalone ColumnFile commands; its completion report is not
whole-storage closeout and neither interface automatically publishes live data.

Dry-run actually performs migration and readback in memory without writing
checkpoints. MAC/sign tags are verified and recomputed transactionally; shuffle
and additional schemas fail closed. See the
root README's offline command section for restrictions and recovery guidance.

Render the committed example plan:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py plan
```

Include command templates that refer to key files by environment variable:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py plan --include-commands
```

Run offline validation, redaction, mixed AES/Herradura inventory, and MAC/sign
scope validation checks (native integrity tests run through `make check`):

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py self-test
```

Summarize a saved plan or journal before resuming:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py journal-status \
  --journal rotation-journal.json
```

Update a single journal step after a checkpoint, dry-run, mutation, or readback:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py journal-update \
  --journal rotation-journal.json \
  --step 2 \
  --state readyToResume \
  --next-action "verify readback with target key/profile" \
  --out rotation-journal.updated.json
```

Render a final closeout report after every journal step is complete:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py final-report \
  --journal rotation-journal.updated.json
```

Use a journal as a CI/operator gate:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py gate \
  --journal rotation-journal.updated.json
```

The gate exits non-zero until every selected ColumnFile step is marked
`complete`.

Render redacted audit events for a journal:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py audit-events \
  --journal rotation-journal.updated.json
```

Render required checkpoint IDs without exposing local paths:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py checkpoint-manifest \
  --journal rotation-journal.updated.json
```

Render an ordered operator runbook:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py runbook
```

Compare two scope files before migration:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py scope-diff \
  --current scope.updated.json \
  --baseline samples/reprotect-workflow/scope.example.json
```

Render incomplete journal steps as operator action items:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py action-items \
  --journal rotation-journal.updated.json
```

Render a handoff pack with journal status, action items, checkpoint IDs, and
audit event counts:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py handoff-pack \
  --journal rotation-journal.updated.json
```

Verify the final closeout criteria before old key material is destroyed:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py completion-check \
  --journal rotation-journal.updated.json
```

## Scope Shape

`scope.example.json` contains:

- `targetProfile`: the profile selected for the explicit migration.
- `operator.confirmedScope`: the exact storage/document-type scope approved by
  the operator.
- `databases`: ColumnFile database inventory from the dry-run phase, including
  source profile, protected value counts, and legacy AES versus Herradura rows.

Supported target names are `aes-256-gcm`, `aes-256-cbc`, and
`herradura-hske-nla1-aead-256`; NLA1 execution requires a compatible
Herradura-enabled binary. The example uses AES-GCM/NLA1 mixed inventory.
Legacy duplex is a compatibility-gated migration source only, never a target;
NLA2 is unimplemented/demo-only. Obsolete sample aliases are rejected as targets.

The planner accepts scopes with MAC/sign metadata. The native command verifies
source tags and recomputes all declared tags for the target key, salt and
ciphertext, then verifies persisted readback. Legacy sign fields use HMACs,
not asymmetric signatures. Tampered, undeclared and duplicate tags fail closed;
shuffle remains unsupported.
Generated command templates use `$CDSE_SOURCE_ORG_KEY_FILE` and
`$CDSE_TARGET_ORG_KEY_FILE`; do not replace those with raw keys in model-visible
logs.

## Journal Semantics

Each database step includes checkpoints before mutation, after the DB
transaction, and after readback. Operators should keep those checkpoint paths
outside model-visible context and retain the journal until the target key/profile
has been verified for every selected database.

Journal steps may include `state` values of `pending`, `readyToResume`,
`complete`, or `blocked`. `journal-status` reports the next resumable step
without exposing checkpoint paths or key material.

`completion-check` exits zero only after every selected ColumnFile step is
complete, post-readback checkpoint IDs exist, and the redacted audit stream
contains an allow closeout event. It still leaves old key destruction as an
operator-held action after external recovery checks.
