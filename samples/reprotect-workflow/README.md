# CaumeDSE Re-Protect Workflow Planner

This sample renders an operator-facing plan for explicit organization-key
rotation or storage-profile migration of protected ColumnFile databases.

It is intentionally secret-free: scope files name organizations, storage,
documents, row counts, and crypto profiles, but never contain `orgKey`,
`newOrgKey`, delegated tokens, TLS private keys, or backup passphrases. The
actual mutation remains inside CaumeDSE through `cmeReprotectMemSecureDB()`.

## Commands

Render the committed example plan:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py plan
```

Run offline validation, redaction, mixed AES/Herradura inventory, and MAC/sign
fail-closed checks:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py self-test
```

Summarize a saved plan or journal before resuming:

```sh
python3 samples/reprotect-workflow/reprotect_workflow.py journal-status \
  --journal rotation-journal.json
```

## Scope Shape

`scope.example.json` contains:

- `targetProfile`: the profile selected for the explicit migration.
- `operator.confirmedScope`: the exact storage/document-type scope approved by
  the operator.
- `databases`: ColumnFile database inventory from the dry-run phase, including
  source profile, protected value counts, and legacy AES versus Herradura rows.

The planner rejects scopes with MAC/sign metadata because those values require
the dedicated recomputation workflow before key/profile rotation can proceed.

## Journal Semantics

Each database step includes checkpoints before mutation, after the DB
transaction, and after readback. Operators should keep those checkpoint paths
outside model-visible context and retain the journal until the target key/profile
has been verified for every selected database.

Journal steps may include `state` values of `pending`, `readyToResume`,
`complete`, or `blocked`. `journal-status` reports the next resumable step
without exposing checkpoint paths or key material.
