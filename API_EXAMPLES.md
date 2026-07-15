# CaumeDSE API Examples

This file contains compact `curl` examples aligned with the live verifier flow
in `TEST/run_debug_components.sh`. The examples are meant for development and
integration testing. They show the request shape for common resources without
expanding the main README API reference. For AI-agent and automation guardrails
around these examples, see `AI_USAGE.md`. For a machine-readable reference for
the stable documented routes, see `openapi.yaml`.

## Setup

Use HTTP only in DEBUG/test environments. For HTTPS, set `TLS_ARGS` to the CA,
client certificate chain, and client key used by your test or deployment.

```sh
BASE_URL="http://localhost:18080"
ORG="ExampleOrg"
ORG_KEY="example-org-key"
USER="User123"
STORAGE="ExampleStorage"
STORAGE_PATH="/tmp/caumedse-example-storage"
CSV_DOC="payroll.csv"
SCRIPT_PERL="sum_salary.pl"
SCRIPT_PYTHON="sum_salary.py"
AUTH="userId=$USER&orgId=$ORG&orgKey=$ORG_KEY"
TLS_ARGS=""

# HTTPS example:
# BASE_URL="https://localhost:18443"
# TLS_ARGS="--cacert /tmp/cdse-verify/cdse/ca.pem --cert client_chain.pem --key client.key"
```

The examples use committed verifier fixtures:

- `TEST/testfiles/live-api-small.csv`
- `TEST/testfiles/test.pl`
- `TEST/testfiles/test.py`

## Negative Authentication Checks

Missing credentials return `401`.

```sh
curl -i $TLS_ARGS "$BASE_URL/organizations/$ORG"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG?userId=$USER&orgId=$ORG"
```

On HTTPS, requests without a client certificate or with a certificate whose
user common name does not match `userId` also return `401`.

```sh
curl -i --cacert /tmp/cdse-verify/cdse/ca.pem \
  "$BASE_URL/organizations/$ORG?$AUTH"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG?userId=${USER}_mismatch&orgId=$ORG&orgKey=$ORG_KEY"
```

## Organizations, Storage, and Users

Create an organization, storage resource, and user.

```sh
curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG?$AUTH&newOrgKey=$ORG_KEY&*resourceInfo=example%20organization&*certificate=undefined&*publicKey=undefined"

curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE?$AUTH&newOrgKey=$ORG_KEY&*resourceInfo=example%20storage&*location=localhost&*type=local&*accessPath=$STORAGE_PATH&*accessUser=undefined&*accessPassword=undefined"

curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG/users/$USER?$AUTH&newOrgKey=$ORG_KEY&*resourceInfo=example%20user&*certificate=undefined&*publicKey=undefined&*basicAuthPwdHash=undefined&*oauthConsumerKey=undefined&*oauthConsumerSecret=undefined"
```

## Document Types

List document types, check `file.csv`, and verify an unsupported document type.

```sh
curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes?$AUTH&newOrgKey=$ORG_KEY&outputType=json"

curl -I $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/unsupported.type?$AUTH&newOrgKey=$ORG_KEY"
```

## Role and Filter Resources

Create and read role, whitelist, and blacklist resources. These examples mirror
the live verifier setup. Fine-grained deny behavior is covered in DEBUG
component tests.

```sh
curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG/users/$USER/roleTables/users?$AUTH&newOrgKey=$ORG_KEY&*_get=1&*_post=0&*_put=1&*_delete=0&*_head=1&*_options=1"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/users/$USER/roleTables/users?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/users/$USER/roleTables/users?$AUTH&newOrgKey=$ORG_KEY&outputType=json"

curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG/users/$USER/filterWhitelist/$USER?$AUTH&newOrgKey=$ORG_KEY&*_get=1&*_post=0&*_put=0&*_delete=0&*_head=1&*_options=1"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/users/$USER/filterWhitelist/$USER?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG/users/$USER/filterBlacklist/$USER?$AUTH&newOrgKey=$ORG_KEY&*_get=0&*_post=1&*_put=0&*_delete=0&*_head=0&*_options=0"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/users/$USER/filterBlacklist/$USER?$AUTH&newOrgKey=$ORG_KEY"
```

## Secure CSV Documents

Upload a CSV document, list documents, and retrieve content.

```sh
curl -i $TLS_ARGS \
  -F "file=@TEST/testfiles/live-api-small.csv" \
  -F "userId=$USER" \
  -F "orgId=$ORG" \
  -F "orgKey=$ORG_KEY" \
  -F "newOrgKey=$ORG_KEY" \
  -F "*resourceInfo=example CSV" \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents?$AUTH&newOrgKey=$ORG_KEY&outputType=json"

curl -I $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/content?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"
```

## Rows and Columns

Read a row, read a column, and create/delete a representative column in a
separate temporary document.

```sh
curl -i $TLS_ARGS -X OPTIONS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentRows?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentRows/1?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentRows/1?$AUTH&newOrgKey=$ORG_KEY&outputType=json"

curl -i $TLS_ARGS -X OPTIONS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentColumns?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/contentColumns/name?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"

COLUMN_DOC="columns.csv"

curl -i $TLS_ARGS -X POST \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$COLUMN_DOC/contentColumns/Col1?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS -X DELETE \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$COLUMN_DOC/contentColumns/Col1?$AUTH&newOrgKey=$ORG_KEY"
```

## Secure DB Browsing

Browse registered secure CSV databases, tables, rows, and columns.

```sh
curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/dbNames?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/dbNames/$CSV_DOC/dbTables?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/dbNames/$CSV_DOC/dbTables/data/tableRows/1?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/dbNames/$CSV_DOC/dbTables/data/tableRows/1?$AUTH&newOrgKey=$ORG_KEY&outputType=json"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/dbNames/$CSV_DOC/dbTables/data/tableColumns/name?$AUTH&newOrgKey=$ORG_KEY"

# Invalid row selectors return 403.
curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/dbNames/$CSV_DOC/dbTables/data/tableRows/0?$AUTH&newOrgKey=$ORG_KEY"
```

## Parser Scripts

Upload Perl and Python parser scripts and run them against the secure CSV
document.

```sh
curl -i $TLS_ARGS \
  -F "file=@TEST/testfiles/test.pl" \
  -F "userId=$USER" \
  -F "orgId=$ORG" \
  -F "orgKey=$ORG_KEY" \
  -F "newOrgKey=$ORG_KEY" \
  -F "*resourceInfo=example Perl script" \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/script.perl/documents/$SCRIPT_PERL"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/parserScripts/$SCRIPT_PERL?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/parserScripts/$SCRIPT_PERL?$AUTH&newOrgKey=$ORG_KEY&outputType=json"

curl -I $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/parserScripts/missing.pl?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"

curl -i $TLS_ARGS \
  -F "file=@TEST/testfiles/test.py" \
  -F "userId=$USER" \
  -F "orgId=$ORG" \
  -F "orgKey=$ORG_KEY" \
  -F "newOrgKey=$ORG_KEY" \
  -F "*resourceInfo=example Python script" \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/script.python/documents/$SCRIPT_PYTHON"

curl -i $TLS_ARGS \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC/parserScripts/$SCRIPT_PYTHON?$AUTH&newOrgKey=$ORG_KEY&outputType=csv"
```

Parser resource-limit failures are covered by the live verifier using
`TEST/testfiles/test_timeout.py` and `TEST/testfiles/test_oversize.py`.

## Cleanup

Delete the disposable resources created by these examples.

```sh
curl -i $TLS_ARGS -X DELETE \
  "$BASE_URL/organizations/$ORG/storage/$STORAGE/documentTypes/file.csv/documents/$CSV_DOC?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS -X DELETE \
  "$BASE_URL/organizations/$ORG/users/$USER/roleTables/users?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS -X DELETE \
  "$BASE_URL/organizations/$ORG/users/$USER/filterWhitelist/$USER?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS -X DELETE \
  "$BASE_URL/organizations/$ORG/users/$USER/filterBlacklist/$USER?$AUTH&newOrgKey=$ORG_KEY"

curl -i $TLS_ARGS -X DELETE \
  "$BASE_URL/organizations/$ORG/users/$USER?$AUTH&newOrgKey=$ORG_KEY"
```

## Verification

The examples are derived from the live verifier. To exercise the same flow and
produce a coverage matrix, run:

```sh
TEST/run_debug_components.sh --ci-smoke
TEST/run_debug_components.sh --live-only --web-protocol=http
TEST/run_debug_components.sh --live-only --web-protocol=https
TEST/validate_openapi_routes.sh
```

The verifier writes `live-api-coverage.csv` and `live-api-coverage.txt` under
its log directory.  Use `CDSE_VERIFY_REDACT=1 TEST/run_debug_components.sh ...`
when saving verifier artifacts in CI or AI-assisted debugging sessions; this
masks organization keys, `newOrgKey` values, selected credential-style request
parameters, and generated certificate/key paths in summaries and live request
artifacts.
