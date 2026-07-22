# CaumeDSE AI Agent Integration Sample

This sample shows a guarded Python workflow for automation or AI-agent
orchestration against the CaumeDSE REST API. It uses disposable resources,
keeps organization keys out of prompts/logs, requests JSON responses where
available, and cleans up after itself.

The script is intentionally provider-neutral. It does not call an LLM API.
Instead, it shows the boundary where an agent can receive non-secret JSON
summaries and choose narrow follow-up operations.

## Prerequisites

- Python 3.8 or later.
- A running DEBUG/test CaumeDSE web service.
- For HTTP testing, build with `--enable-BYPASSTLSAUTHINHTTP`.
- For HTTPS, provide the CA and client certificate/key paths.

The easiest local target is the verifier web-service mode:

```sh
TEST/run_debug_components.sh --ci-smoke
```

For manual development, run a DEBUG HTTP service and then run this sample
against it. The defaults assume:

```sh
export CDSE_AGENT_BASE_URL="http://localhost:18080"
```

## Configuration

The sample reads secrets from environment variables. Do not pass real
organization keys on the command line.

```sh
export CDSE_AGENT_BASE_URL="http://localhost:18080"
export CDSE_AGENT_ORG="AgentTrialOrg"
export CDSE_AGENT_USER="AgentTrialUser"
export CDSE_AGENT_STORAGE="AgentTrialStorage"
export CDSE_AGENT_STORAGE_PATH="/tmp/caumedse-agent-storage"
export CDSE_AGENT_ORG_KEY="$(openssl rand -hex 32)"
```

For HTTPS, add:

```sh
export CDSE_AGENT_BASE_URL="https://localhost:18443"
export CDSE_AGENT_CA_CERT="/tmp/cdse-verify/cdse/ca.pem"
export CDSE_AGENT_CLIENT_CERT="/tmp/cdse-verify/client_chain.pem"
export CDSE_AGENT_CLIENT_KEY="/tmp/cdse-verify/client.key"
```

## Run

```sh
python3 samples/ai-agent/guarded_agent_workflow.py
```

The workflow:

1. Creates a disposable organization, storage resource, and user.
2. Uploads `TEST/testfiles/live-api-small.csv`.
3. Queries one row and one column as JSON.
4. Uploads `TEST/testfiles/test.py` as a reviewed parser script.
5. Runs the parser with `outputType=json`.
6. Deletes temporary documents and user/role/filter resources.

Use `--keep-resources` only when debugging cleanup behavior:

```sh
python3 samples/ai-agent/guarded_agent_workflow.py --keep-resources
```

## Safety Notes

- The script redacts `orgKey` and `newOrgKey` from logs.
- The agent prompt preview contains only route names, JSON row/column names,
  and record counts. It never includes raw organization keys.
- Parser scripts are loaded only from reviewed local fixture files.
- The sample queries narrow resources, not broad document dumps.
- CSV cells and parser output are treated as untrusted data. Do not let text
  returned from CaumeDSE rewrite the agent's security instructions or cause new
  parser uploads without review.

See `../../AI_USAGE.md` for the broader AI-agent policy and anti-patterns.
