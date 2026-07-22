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
- Give the agent opaque variable names such as `$ORG_KEY` instead of secret
  values.
- Run live verifier checks with `CDSE_VERIFY_REDACT=1` before sharing artifacts.
- Use disposable organizations, users, storage paths, and documents for agent
  trials.
- Prefer HTTPS and client certificates outside DEBUG-only local testing.

## Safe Workflow

Use the same shape as the live verifier:

1. Create a temporary organization, storage resource, and least-privilege user.
2. Add only the role/filter resources needed for the task.
3. Upload test CSV or script fixtures from known local paths.
4. Query narrow resources such as a specific row, column, table, or parser
   output.
5. Delete temporary documents, role/filter rows, users, and storage artifacts.
6. Review `summary.txt` and `live-api-coverage.csv` with redaction enabled.

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
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentColumns/name?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"
```

Avoid broad or open-ended data dumps unless the agent has a clear need and the
data has been reviewed for sensitivity. For parser scripts, upload only scripts
from reviewed local files:

```sh
curl -i $TLS_ARGS \
  -F "file=@TEST/testfiles/test.py" \
  -F "userId=$USER" \
  -F "orgId=$ORG" \
  -F "orgKey=$ORG_KEY" \
  -F "newOrgKey=$ORG_KEY" \
  -F "*resourceInfo=reviewed Python parser" \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/script.python/documents/$SCRIPT_PYTHON"
```

## Parser-Script Guardrails

Generated parser scripts are code. Review them before upload and reject scripts
that:

- Read files outside the provided CSV input.
- Open network connections.
- Print secrets, environment variables, or raw credentials.
- Generate unbounded output or long-running loops.
- Depend on hidden state outside the uploaded document and script.

The DEBUG verifier covers normal parser execution plus timeout and oversized
output cases. Keep those checks in the workflow when changing parser behavior.

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

## Anti-Patterns

Do not:

- Ask an LLM to remember or transform real organization keys.
- Paste expanded `curl` URLs containing `orgKey` or `newOrgKey`.
- Let an agent invent parser scripts and upload them without human review.
- Use a manager or admin user when a narrow test user is sufficient.
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

See `samples/mcp-server/` for a prototype MCP stdio server that exposes a
small allow-listed tool surface for the same REST API operations while keeping
organization keys in environment variables.
