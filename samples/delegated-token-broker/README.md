# CaumeDSE Delegated Token Broker Sample

CaumeDSE does not validate bearer tokens, OAuth grants, scopes, expiry, or
revocation internally. This sample demonstrates the external-manager pattern
for AI agents: a broker validates a short-lived opaque token and then calls
CaumeDSE with broker-held delegated `userId`, `orgId`, and `orgKey`
parameters.

The token is intentionally not a CaumeDSE credential. It is meaningful only to
the broker that signs it.

## Token Model

The sample token contains:

- `sub`: the external subject or agent session.
- `scope`: allowed broker actions such as `documents:read` or
  `parserScripts:run`.
- `exp`: expiry time as a Unix timestamp.
- `jti`: revocation identifier stored in a broker-owned deny list.
- `cdse`: the delegated CaumeDSE organization and user binding.

Production brokers should store signing keys and revocation state in a secret
manager or database, rotate signing keys, audit every authorization decision,
and rate-limit callers.

## Configure

```sh
export CDSE_BROKER_BASE_URL="http://localhost:18080"
export CDSE_BROKER_SIGNING_SECRET="$(openssl rand -hex 32)"
export CDSE_BROKER_ADMIN_ORG="AgentBrokerOrg"
export CDSE_BROKER_ADMIN_USER="AgentBrokerAdmin"
export CDSE_BROKER_ADMIN_ORG_KEY="$(openssl rand -hex 32)"
export CDSE_BROKER_DELEGATED_USER="AgentReader"
export CDSE_BROKER_STORAGE="AgentBrokerStorage"
export CDSE_BROKER_STORAGE_PATH="/tmp/caumedse-broker-storage"
```

For HTTPS, also set `CDSE_BROKER_CA_CERT`, `CDSE_BROKER_CLIENT_CERT`, and
`CDSE_BROKER_CLIENT_KEY`.

## Provision

Create the delegated CaumeDSE user and read-only role/filter rows:

```sh
python3 samples/delegated-token-broker/delegated_token_broker.py provision-readonly
```

The broker sends real `orgKey` and `newOrgKey` values only from its process
environment. Request logs redact those values.

## Mint and Authorize

Mint a short-lived token:

```sh
TOKEN="$(
  python3 samples/delegated-token-broker/delegated_token_broker.py mint \
    --subject agent-session-123 \
    --scopes documents:read,contentRows:read,contentColumns:read,parserScripts:run \
    --ttl 900
)"
```

Validate a requested action before forwarding it to CaumeDSE:

```sh
python3 samples/delegated-token-broker/delegated_token_broker.py authorize \
  --token "$TOKEN" \
  --scope contentRows:read
```

The authorize command prints only a redacted CaumeDSE credential preview. A
real broker would use the broker-held `orgKey` internally to make the REST
request and return a bounded, non-secret response to the agent.

Revoke the token:

```sh
python3 samples/delegated-token-broker/delegated_token_broker.py revoke \
  --token "$TOKEN"
```

## Offline Smoke Test

```sh
python3 samples/delegated-token-broker/delegated_token_broker.py self-test
```

The self-test verifies that a read scope is allowed, a write scope is denied,
an expired token is denied, and a revoked token is denied. It does not contact
a CaumeDSE service.

## Boundaries

- Do not pass delegated tokens, organization keys, TLS keys, or revocation
  stores to an LLM.
- Keep the `orgKey` in the broker or secret manager. The agent receives only
  opaque token handles and bounded results.
- Use short TTLs and revoke tokens immediately when the upstream OAuth grant,
  user session, or agent task ends.
- Use role-table and filter-list rows to make CaumeDSE enforce the same narrow
  permissions that the broker checks before forwarding.
