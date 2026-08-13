# CaumeDSE Policy Authorization Tester

This sample defines a small JSON policy format for intended role/filter
authorization behavior and checks observed probe results against that policy.
It is dependency-free and keeps credentials out of policy files and reports.

The tester validates policy shape, renders the intended `roleTables`,
`filterWhitelist`, and `filterBlacklist` setup plan, compares recorded probe
statuses to expected allow/deny outcomes, and can execute policy rules against a
live CaumeDSE base URL.

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

The validator rejects broad role resources, unsupported methods, mutating roles
without blacklist controls, and conflicting whitelist/blacklist method rules.

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

Fail a CI/operator gate when observed probes violate policy:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py gate \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Render JUnit XML for CI test reports:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py junit \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Render a Markdown report for reviews:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py markdown \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Render a CSV report for spreadsheets:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py csv \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Render action items for failed or missing policy observations:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py remediation-plan \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Render a policy evidence attestation for human approval records:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py attestation \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json
```

Verify the full policy tester workflow before deployment:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py completion-check \
  --policy samples/policy-authz-tester/policy.example.json \
  --observations observed-policy-results.json \
  --base-url http://127.0.0.1:8080
```

Render live probe URLs without sending requests:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py probe \
  --policy samples/policy-authz-tester/policy.example.json \
  --base-url http://127.0.0.1:8080 \
  --auth-query "$CDSE_POLICY_AUTH_QUERY" \
  --dry-run
```

Execute live probes by removing `--dry-run`. Keep `CDSE_POLICY_AUTH_QUERY`
outside policy files and logs; the tester redacts credential-style query
parameters from reports.

Render setup commands for the role/filter resources:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py setup-script \
  --policy samples/policy-authz-tester/policy.example.json \
  --base-url http://127.0.0.1:8080 \
  --auth-query "$CDSE_POLICY_AUTH_QUERY"
```

Render cleanup commands for disposable role/filter resources:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py cleanup-script \
  --policy samples/policy-authz-tester/policy.example.json \
  --base-url http://127.0.0.1:8080 \
  --auth-query "$CDSE_POLICY_AUTH_QUERY"
```

Render a human approval pack before applying generated policy resources:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py review-pack \
  --policy samples/policy-authz-tester/policy.example.json \
  --base-url http://127.0.0.1:8080
```

Render the full live authorization-test runbook:

```sh
python3 samples/policy-authz-tester/policy_authz_tester.py runbook \
  --policy samples/policy-authz-tester/policy.example.json \
  --base-url http://127.0.0.1:8080 \
  --auth-query "$CDSE_POLICY_AUTH_QUERY"
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

`completion-check` exits zero only when the policy validates, setup/probe and
cleanup coverage are present, observed statuses match expectations, and the
human approval boundary remains explicit.
