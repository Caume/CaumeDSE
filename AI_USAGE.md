# AI-Safe CaumeDSE API Usage

This guide describes safe patterns for LLM agents and automation that call
CaumeDSE APIs. It complements `API_EXAMPLES.md` by focusing on credential
handling, least privilege, parser-script review, logging, and cleanup.

## Security Model for Agents

Treat an AI agent as an untrusted client. It can plan requests and inspect
non-secret responses, but it should not receive raw organization keys,
certificate private keys, access passwords, OAuth secrets, or sensitive CSV
rows unless a human has explicitly approved that disclosure.

Recommended boundaries:

- Store `orgKey`, `newOrgKey`, TLS key paths, and OAuth/client secrets in the
  calling process environment or a dedicated secret manager.
- Prefer an external delegated-token broker for agents. The broker should
  validate short-lived scoped tokens and forward requests with broker-held
  CaumeDSE delegated credentials.
- Give the agent opaque variable names such as `$ORG_KEY` instead of secret
  values.
- Run live verifier checks with `CDSE_VERIFY_REDACT=1` before sharing artifacts.
- Use disposable organizations, users, storage paths, and documents for agent
  trials.
- Prefer HTTPS and client certificates outside DEBUG-only local testing.

## Safe Workflow

Use the same shape as the live verifier:

1. Call `GET /agentCapabilities` to discover supported formats, auth
   requirements, parser policy, documentation links, and route templates.
2. Create a temporary organization, storage resource, and least-privilege user.
3. Add only the role/filter resources needed for the task.
4. For real agent sessions, mint a short-lived delegated token that names only
   the scopes needed for the task.
5. Have the broker validate each requested scope before forwarding to CaumeDSE
   with the delegated `userId`, `orgId`, and broker-held `orgKey`.
6. Upload test CSV or script fixtures from known local paths.
7. Read schema metadata for CSV documents or exposed secure DB tables before
   selecting rows, columns, or parser output.
8. Query narrow resources such as a specific row, column, table, or parser
   output.
9. Delete temporary documents, role/filter rows, users, and storage artifacts.
10. Review `summary.txt` and `live-api-coverage.csv` with redaction enabled.

For failures that an agent must parse, include `outputType=json`. Non-HEAD
error responses include `error.code`, `error.message`, `error.httpStatus`,
`error.requestId`, and `error.safeForAgent`; the same request ID is returned in
the `X-Request-Id` response header and recorded in LogsDB response headers.

Example shell setup:

```sh
export BASE_URL="https://localhost:18443"
export ORG="AgentTrialOrg"
export USER="AgentTrialUser"
export STORAGE="AgentTrialStorage"
export ORG_KEY="$(openssl rand -hex 32)"
export AUTH="userId=$USER&orgId=$ORG&orgKey=$ORG_KEY"
export TLS_ARGS="--cacert /tmp/cdse-verify/cdse/ca.pem --cert client_chain.pem --key client.key"
```

The agent may generate request templates that reference `$AUTH`, `$ORG_KEY`,
and `$TLS_ARGS`. Do not paste expanded command lines containing real secrets
into prompts, issue trackers, shared logs, or chat transcripts.

## Request Patterns

Prefer explicit, narrow API calls:

```sh
curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/schema?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentColumns/name?$AUTH&newOrgKey=$ORG_KEY&outputType=json&limit=10&offset=0"
```

Avoid broad or open-ended data dumps unless the agent has a clear need and the
data has been reviewed for sensitivity. JSON table reads default to
`limit=100&offset=0`, accept `limit` values from 1 to 1000, and return a
`pagination` object with `returnedRows`, `totalRows`, and `hasMore`. Upload
generated parser candidates as pending, run only preview execution, then
promote by updating review metadata after human review:

```sh
curl -i $TLS_ARGS \
  -F "file=@TEST/testfiles/test.py" \
  -F "userId=$USER" \
  -F "orgId=$ORG" \
  -F "orgKey=$ORG_KEY" \
  -F "newOrgKey=$ORG_KEY" \
  -F "*resourceInfo=generated parser parser.reviewStatus:pending parser.generated:true parser.generator:sample-agent parser.promptHash:sha256-demo parser.interpreter:/usr/bin/python3 parser.timeout:10 parser.isolation:none" \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/script.python/documents/$SCRIPT_PYTHON"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/parserScripts/$SCRIPT_PYTHON?$AUTH&newOrgKey=$ORG_KEY&outputType=json&previewOnly=1&previewRows=1&limit=1"
```

Pending/generated-unreviewed scripts are denied for full execution. Reviewed
metadata should include `parser.reviewStatus:reviewed`, `parser.reviewed:true`,
`parser.reviewer:<user>`, and `parser.reviewTime:<timestamp>`.

## Parser-Script Guardrails

Generated parser scripts are code, and CSV contents can contain prompt
injection text such as instructions to reveal secrets, fetch URLs, alter
policies, or change the requested output. Treat both the script and the CSV
data as untrusted until a human has reviewed them.

Review generated scripts before upload and reject scripts that:

- Read files outside the provided CSV input.
- Open network connections.
- Print secrets, environment variables, or raw credentials.
- Generate unbounded output or long-running loops.
- Depend on hidden state outside the uploaded document and script.
- Build shell commands from CSV values or parser parameters.
- Treat CSV cell text as instructions for the agent, host, or CaumeDSE.
- Change authorization, logging, redaction, cleanup, or TLS behavior.

Prefer scripts that:

- Use only standard CSV parsing libraries and deterministic transformations.
- Select required columns by exact header name and handle missing columns
  explicitly.
- Escape CSV output through a CSV writer instead of string concatenation.
- Emit only the minimum columns needed for the task.
- Keep all file access limited to the input and output paths supplied by
  CaumeDSE.

When an LLM helps draft a parser, ask it for code plus a short checklist of
the assumptions it made. Review the code, not the checklist, before upload.
Never let text inside the uploaded CSV modify the review criteria.

The DEBUG verifier covers normal parser execution plus timeout and oversized
output cases. Keep those checks in the workflow when changing parser behavior.

## Delegated Tokens

Use delegated scoped tokens at the manager layer when an agent needs repeated
access. Do not teach CaumeDSE to trust the token directly. The broker should:

- Mint opaque tokens with subject, scope list, expiry, revocation identifier,
  and delegated CaumeDSE user binding.
- Keep signing keys, revocation state, and organization keys outside prompts,
  transcripts, and tool arguments.
- Check the token scope before every forwarded operation.
- Configure CaumeDSE role-table and filter-list rows that match the broker
  scopes, so a broker bug still meets a narrow CaumeDSE authorization layer.
- Revoke tokens when the upstream OAuth grant, user session, or agent task
  ends.

See `samples/delegated-token-broker/` for a standard-library Python sample.
Its offline self-test covers allowed scope, denied scope, expiry, and
revocation behavior and is included in `TEST/run_debug_components.sh`.

## Logging and Artifact Handling

Use redacted verification for CI and AI-assisted debugging:

```sh
CDSE_VERIFY_REDACT=1 TEST/run_debug_components.sh --ci-smoke
CDSE_VERIFY_REDACT=1 TEST/run_debug_components.sh --live-only --web-protocol=https
```

Redaction masks `orgKey`, `newOrgKey`, selected credential-style request
parameters, and generated certificate/key paths in retained verifier artifacts.
It preserves status codes, markers, elapsed times, and artifact names so
failures remain diagnosable.

CaumeDSE DEBUG service logs also include structured audit lines prefixed with
`CaumeDSE AuditJSON: `. Version 1 events cover `auth`, `authorization`,
`request`, `parserPolicy`, `parserUpload`, `parserExecution`, and `cleanup`
categories. The JSON fields are limited to identifiers, routes, decisions,
status/result codes, and parser metadata labels; org keys, authorization
headers, script bodies, and CSV content are not emitted. For a bounded local
summary, run:

```sh
python3 samples/ai-agent/recent_audit_reader.py /tmp/cdse-debug-components-*/live_http_service.log --limit 20
```

## Anti-Patterns

Do not:

- Ask an LLM to remember or transform real organization keys.
- Paste expanded `curl` URLs containing `orgKey` or `newOrgKey`.
- Let an agent invent parser scripts and upload them without human review.
- Use a manager or admin user when a narrow test user is sufficient.
- Ignore `X-Request-Id` when reporting failures; keep it with status and route
  context so operators can find the matching LogsDB row.
- Keep temporary AI-created organizations, users, documents, or parser scripts
  after the task is complete.
- Share raw DEBUG logs or live request artifacts without redaction.

## Validation

Validate AI-facing examples against the live verifier routes:

```sh
bash -n TEST/run_debug_components.sh
CDSE_VERIFY_REDACT=1 TEST/run_debug_components.sh --help
CDSE_VERIFY_REDACT=1 TEST/run_debug_components.sh --ci-smoke
```

For quick documentation-only edits, compare route names against
`API_EXAMPLES.md` and `TEST/run_debug_components.sh` before running the full
live flow.

## Integration Sample

See `samples/ai-agent/` for a guarded Python workflow that creates disposable
resources, uploads verifier fixtures, queries row/column/parser results as
JSON, builds an LLM-safe prompt preview without secrets, and cleans up the
workspace.

See `samples/delegated-token-broker/` for an external-manager sample that
mints short-lived scoped tokens and maps them to broker-held delegated CaumeDSE
credentials.

See `samples/mcp-server/` for a prototype MCP stdio server that exposes a
small allow-listed tool surface for the same REST API operations while keeping
organization keys in environment variables.
