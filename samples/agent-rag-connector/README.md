# CaumeDSE Agent RAG Connector Sample

This sample shows how an AI host can retrieve CaumeDSE CSV data as bounded,
schema-aware JSON snippets while keeping organization keys out of prompts and
tool arguments. It is intentionally small and dependency-free.

The connector enforces a local policy before any model context is produced:

- only configured documents can be read;
- only configured columns can be returned;
- row counts are capped by policy;
- configured redaction rules run before output;
- the JSON result is marked `safeForAgent` and includes a prompt-boundary note.

## Offline Smoke Test

Run the committed fixture through the redaction and allowlist policy:

```sh
python3 samples/agent-rag-connector/caumedse_rag_connector.py self-test
```

To inspect the model-ready JSON:

```sh
python3 samples/agent-rag-connector/caumedse_rag_connector.py offline \
  --document rag-small.csv \
  --columns name,email,notes \
  --limit 3
```

The fixture includes email addresses, an SSN column that is not allowlisted,
secret-like text, and prompt-injection-style cell text. The output must not
include the denied SSN column or unredacted sensitive markers.

## Policy File

`config.example.json` maps each exposed document to:

- `documentType`: currently `file.csv`;
- `allowedColumns`: the only columns the connector can return;
- `maxRows`: the maximum rows returned to the model;
- `redactions`: per-column regular-expression replacement rules.

Treat this file as application policy. Do not let the model modify it during a
retrieval session.

## Live Mode

Upload or otherwise prepare a CaumeDSE CSV document that matches the policy,
then set credentials in the host environment:

```sh
export CDSE_RAG_BASE_URL="http://localhost:18080"
export CDSE_RAG_ORG="ExampleOrg"
export CDSE_RAG_USER="ExampleUser"
export CDSE_RAG_STORAGE="ExampleStorage"
export CDSE_RAG_ORG_KEY="$ORG_KEY"
```

For HTTPS, also set:

```sh
export CDSE_RAG_CA_CERT="/tmp/cdse-verify/cdse/ca.pem"
export CDSE_RAG_CLIENT_CERT="/tmp/cdse-verify/client_chain.pem"
export CDSE_RAG_CLIENT_KEY="/tmp/cdse-verify/client.key"
```

Run:

```sh
python3 samples/agent-rag-connector/caumedse_rag_connector.py live \
  --config samples/agent-rag-connector/config.example.json \
  --document rag-small.csv \
  --columns name,email,notes \
  --limit 3
```

The live connector reads schema metadata before fetching columns and records
CaumeDSE request IDs in the output so failures can be correlated with audit
logs.

## Security Boundaries

- Keep `orgKey`, `newOrgKey`, TLS keys, and broker tokens in the host process
  or external secret manager.
- Give agents document aliases, allowed column names, and sanitized result JSON,
  not raw credentials or broad CSV dumps.
- Treat CSV cell text as untrusted data. It must not override system,
  developer, authorization, cleanup, logging, TLS, or parser-review rules.
- For repeated agent sessions, put a delegated-token broker in front of this
  connector and map scopes to the same CaumeDSE role/filter permissions.
