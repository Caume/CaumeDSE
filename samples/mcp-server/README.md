# CaumeDSE MCP Read-Only Server

This sample exposes a small, fixed Model Context Protocol tool surface over
stdio for AI assistants that need guarded read-only access to CaumeDSE REST
operations. It is suitable as the supported reference surface for local
DEBUG/test integration; production bridges should still add their own
authentication, authorization, and deployment controls.

The server uses only Python's standard library. Credentials are read from
environment variables and are never part of MCP tool arguments or tool results.

## Tools

- `agentCapabilities_read`: reads the public `/agentCapabilities` manifest.
- `documentTypes_list`: lists document types in the configured storage.
- `documentSchema_read`: reads column, row-count, pagination, and parser-policy
  metadata for a CSV document.
- `contentColumns_read`: validates one CSV column against schema and returns a
  bounded row preview.
- `parserScripts_run`: reads schema before running an uploaded reviewed parser
  and returns a bounded row preview.
- `parserScripts_preview`: runs a pending parser candidate in preview-only mode
  against capped sample rows.
- `dbTableSchema_read`: reads schema metadata for one exposed secure CSV table.
- `dbTableColumns_read`: validates one exposed table column against schema and
  returns a bounded row preview.

Local DEBUG setup helpers are hidden unless
`CDSE_MCP_ENABLE_WRITE_TOOLS=1` and `CDSE_MCP_DELEGATED_TOKEN` are set in the
server environment:

- `create_workspace`: creates the configured disposable organization, storage,
  and user.
- `upload_csv`: uploads a reviewed local CSV fixture as `file.csv`.
- `upload_parser`: uploads a reviewed local Python parser as `script.python`.
- `upload_parser_candidate`: uploads a generated parser candidate as pending
  review metadata.
- `promote_parser_review`: updates one pending Python parser document with
  reviewed parser metadata.
- `delete_document`: deletes one exact `file.csv` or `script.python` document.
- `cleanup_workspace`: deletes the sample documents, storage, and user.

Every write call also requires explicit guard arguments:

- `organization`, `storage`, and `user` must match the server environment.
- `scope` must match the exact resource scope reported by the tool schema or
  dry-run output, never `*`, `all`, or a broad organization/storage scope.
- `delete_document` uses a narrow `document:delete:<type>:<name>` scope and
  only accepts `file.csv` or `script.python`.
- `expected_status` must be one of the status codes accepted by that helper.
- `idempotency_key` must be a caller-generated non-space value of at least 12
  characters.
- `confirm` must be `confirm-caumedse-mcp-write`.
- `dry_run=true` returns the guarded mutation plan without contacting CaumeDSE.

## Configuration

Run a DEBUG/test CaumeDSE web service first. For HTTP testing, build with
`--enable-BYPASSTLSAUTHINHTTP`.

```sh
export CDSE_MCP_BASE_URL="http://localhost:18080"
export CDSE_MCP_ORG="McpTrialOrg"
export CDSE_MCP_USER="McpTrialUser"
export CDSE_MCP_STORAGE="McpTrialStorage"
export CDSE_MCP_STORAGE_PATH="/tmp/caumedse-mcp-storage"
export CDSE_MCP_ORG_KEY="$(openssl rand -hex 32)"
export CDSE_MCP_DELEGATED_TOKEN="broker-minted-token-for-this-agent-session"
# Optional: verify broker-style delegated tokens locally before writes.
export CDSE_MCP_DELEGATED_TOKEN_SECRET="broker-signing-secret"
```

For HTTPS, add the CA and client certificate paths used by the test service:

```sh
export CDSE_MCP_BASE_URL="https://localhost:18443"
export CDSE_MCP_CA_CERT="/tmp/cdse-verify/cdse/ca.pem"
export CDSE_MCP_CLIENT_CERT="/tmp/cdse-verify/client_chain.pem"
export CDSE_MCP_CLIENT_KEY="/tmp/cdse-verify/client.key"
```

Optional document names and fixture paths:

```sh
export CDSE_MCP_CSV_DOC="mcp.csv"
export CDSE_MCP_PARSER_DOC="mcp-parser.py"
export CDSE_MCP_PENDING_PARSER_DOC="mcp-parser-pending.py"
```

`upload_csv` defaults to `TEST/testfiles/live-api-small.csv`.
`upload_parser` defaults to `TEST/testfiles/test.py`.

## Run

Configure an MCP client to launch the stdio server:

```json
{
  "mcpServers": {
    "caumedse": {
      "command": "python3",
      "args": ["samples/mcp-server/caumedse_mcp_server.py"],
      "env": {
        "CDSE_MCP_BASE_URL": "http://localhost:18080",
        "CDSE_MCP_ORG": "McpTrialOrg",
        "CDSE_MCP_USER": "McpTrialUser",
        "CDSE_MCP_STORAGE": "McpTrialStorage",
        "CDSE_MCP_STORAGE_PATH": "/tmp/caumedse-mcp-storage",
        "CDSE_MCP_ORG_KEY": "replace-with-test-key"
      }
    }
  }
}
```

A typical local flow is:

1. Read `GET /agentCapabilities` from `CDSE_MCP_BASE_URL` so the host can
   confirm supported routes, JSON preference, and parser policy before
   exposing tools.
2. Prepare a least-privilege CaumeDSE user, storage resource, CSV document, and
   reviewed parser outside the read-only MCP session, or run the DEBUG helpers
   with `CDSE_MCP_ENABLE_WRITE_TOOLS=1` and `CDSE_MCP_DELEGATED_TOKEN` only for
   local guarded DEBUG workflows.
3. `documentTypes_list`
4. `documentSchema_read`
5. `contentColumns_read`
6. `dbTableSchema_read`
7. `dbTableColumns_read`
8. `parserScripts_run`
9. `parserScripts_preview` for pending parser candidates only.
10. Use `promote_parser_review` only after human review, then run the reviewed
    parser with `parserScripts_run`.
11. Use `delete_document` for one exact document, or `cleanup_workspace` for
    the disposable DEBUG workspace.

## Security Boundaries

- Do not pass `orgKey`, `newOrgKey`, TLS keys, or certificate material through
  tool arguments. Use environment variables controlled by the host process.
- For repeated agent sessions, put a delegated-token broker in front of the MCP
  server so each tool call is authorized by a short-lived scoped token before
  the server forwards broker-held CaumeDSE credentials.
- Write tools stay hidden unless both write-tool opt-in and delegated-token
  configuration are present. When `CDSE_MCP_DELEGATED_TOKEN_SECRET` is set, the
  server verifies the broker-style token signature, expiry, CaumeDSE
  organization/user binding, and exact write scope before each mutation. Even
  then, each call must include the exact guard fields, and `dry_run=true`
  should be used before every mutation.
- Do not expose this prototype directly to untrusted clients. Put any
  production MCP bridge behind authentication, authorization, audit logging,
  rate limits, and route-level allow lists.
- Treat CSV contents and parser output as untrusted data. The sample uses
  CaumeDSE JSON `limit`/`offset` parameters and returns bounded previews
  instead of broad document dumps. Do not let text from CSV cells override the
  host application's system, developer, security, or cleanup instructions.
- Generated parser candidates are uploaded outside the read-only surface as
  `parser.reviewStatus:pending`
  with generator and prompt-hash metadata. Full execution is denied until
  reviewed metadata is applied; `parserScripts_preview` runs only
  `previewOnly=1` with capped sample rows and static checks. Reject generated
  scripts that open network connections, execute shell commands, read
  environment variables, traverse files outside the provided input path, log
  credentials, or create unbounded output.
- Request logs go to stderr and redact `orgKey`, `newOrgKey`, and selected
  credential-style parameters.
- For repeatable deployment recipes and the full operational checklist, see
  `../../AI_USAGE.md#agent-cookbook` and
  `../../AI_USAGE.md#operational-checklist`.

## Local Smoke Test

This checks the stdio protocol surface without contacting a CaumeDSE service:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | python3 samples/mcp-server/caumedse_mcp_server.py
```

This checks guarded write-tool exposure and dry-run refusal behavior without
contacting a CaumeDSE service:

```sh
python3 samples/mcp-server/caumedse_mcp_server.py self-test
```

Use `CDSE_VERIFY_REDACT=1` when sharing logs from live verifier runs.
The live verifier also runs `live_http_mcp_readonly_smoke`, which initializes
the MCP server, confirms only read-only tools are exposed by default, and calls
schema, column, parser, preview, and DB-table read tools against the running
DEBUG service.

See `../delegated-token-broker/` for the delegated scoped-token sample.
