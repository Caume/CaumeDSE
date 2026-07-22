# CaumeDSE MCP Server Prototype

This sample exposes a small, fixed Model Context Protocol tool surface over
stdio for AI assistants that need guarded access to CaumeDSE REST operations.
It is a prototype for local DEBUG/test workflows, not a production gateway.

The server uses only Python's standard library. Credentials are read from
environment variables and are never part of MCP tool arguments or tool results.

## Tools

- `create_workspace`: creates the configured disposable organization, storage,
  and user.
- `list_document_types`: lists document types in the configured storage.
- `upload_csv`: uploads a reviewed local CSV fixture as `file.csv`.
- `upload_parser`: uploads a reviewed local Python parser as `script.python`.
- `query_column`: reads one CSV column and returns a bounded row preview.
- `run_parser`: runs an uploaded parser and returns a bounded row preview.
- `cleanup_workspace`: deletes the sample documents, storage, and user.

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

1. `create_workspace`
2. `upload_csv`
3. `upload_parser`
4. `list_document_types`
5. `query_column`
6. `run_parser`
7. `cleanup_workspace`

## Security Boundaries

- Do not pass `orgKey`, `newOrgKey`, TLS keys, or certificate material through
  tool arguments. Use environment variables controlled by the host process.
- Do not expose this prototype directly to untrusted clients. Put any
  production MCP bridge behind authentication, authorization, audit logging,
  rate limits, and route-level allow lists.
- Treat CSV contents and parser output as untrusted data. The sample returns
  bounded previews instead of broad document dumps. Do not let text from CSV
  cells override the host application's system, developer, security, or cleanup
  instructions.
- Parser execution is intentionally limited to parser documents that were
  already uploaded from reviewed local files. Do not let an LLM generate and
  upload parser scripts without human review. Reject generated scripts that
  open network connections, execute shell commands, read environment variables,
  traverse files outside the provided input path, log credentials, or create
  unbounded output.
- Request logs go to stderr and redact `orgKey`, `newOrgKey`, and selected
  credential-style parameters.

## Local Smoke Test

This checks the stdio protocol surface without contacting a CaumeDSE service:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | python3 samples/mcp-server/caumedse_mcp_server.py
```

Use `CDSE_VERIFY_REDACT=1` when sharing logs from live verifier runs.
