# CaumeDSE Policy Authorization Tester

This sample defines a small JSON policy format for intended role/filter
authorization behavior and checks observed probe results against that policy.
It is dependency-free and keeps credentials out of policy files and reports.

Batch 1 is offline-oriented: it validates policy shape, renders the intended
`roleTables`, `filterWhitelist`, and `filterBlacklist` setup plan, and compares
recorded probe statuses to expected allow/deny outcomes. A later live workflow
can use the same policy file to provision disposable resources and execute HTTP
probes.

## Policy Shape

`policy.example.json` contains:

- `subject`: the organization and user under test.
- `resources`: storage, document, and document type names.
- `roles`: intended roleTables resources and allowed methods.
- `filterWhitelist`: positive method/resource patterns.
- `filterBlacklist`: deny method/resource patterns.
- `rules`: named HTTP probes with method, route, decision, and expected status.

Do not include `orgKey`, `newOrgKey`, TLS private keys, delegated tokens, or
authorization headers in policy files.

## Commands

Validate the committed example and render setup intent:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py validate
```

Compare observed probe results:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py report \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Run offline validation, evaluation, and redaction checks:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py self-test
```

Observation files are JSON arrays:

```json
[
  {
    "rule": "allow_document_schema",
    "status": 200,
    "requestId": "live-http-1",
    "auditCategory": "request"
  }
]
```

Reports are marked `safeForAgent:true`, include pass/fail counts, and redact
credential-style values from routes and structured fields.
