# CaumeDSE Compliance Audit Dashboard Sample

This sample turns structured `CaumeDSE AuditJSON` service-log events and
optional `live-api-coverage.csv` verifier output into a redacted JSON or static
HTML report. It uses only Python's standard library.

The dashboard highlights:

- denied authentication and authorization events;
- parser policy denials;
- parser execution issues;
- cleanup failures;
- failed verifier coverage rows;
- broad-read indicators from routes and verifier feature names;
- event grouping by `requestId`.

## Smoke Test

```sh
python3 samples/audit-dashboard/audit_dashboard.py self-test
```

The self-test uses committed fixtures and verifies parser-policy, parser
execution, cleanup, failed-coverage, HTML rendering, and redaction behavior.

## Generate Reports

From fixture data:

```sh
python3 samples/audit-dashboard/audit_dashboard.py json \
  samples/audit-dashboard/fixtures/audit.log \
  --coverage samples/audit-dashboard/fixtures/live-api-coverage.csv

python3 samples/audit-dashboard/audit_dashboard.py html \
  samples/audit-dashboard/fixtures/audit.log \
  --coverage samples/audit-dashboard/fixtures/live-api-coverage.csv \
  --output /tmp/caumedse-audit-dashboard.html
```

From a live verifier run:

```sh
CDSE_VERIFY_REDACT=1 TEST/run_debug_components.sh --ci-smoke

python3 samples/audit-dashboard/audit_dashboard.py html \
  /tmp/cdse-debug-components-*/live_http_service.log \
  --coverage /tmp/cdse-debug-components-*/live-api-coverage.csv \
  --output /tmp/caumedse-audit-dashboard.html
```

Use redacted verifier artifacts before sharing reports in issue trackers or
AI-assisted incident review.

## Boundaries

- The report includes identifiers, decisions, categories, request IDs, and
  status fields. It does not need raw CSV contents, parser source, org keys, or
  TLS private-key paths.
- Treat the dashboard as an operator aid, not an authorization oracle.
- Keep broad-read findings as review prompts. A broad read can be legitimate
  when explicitly approved by a human.
