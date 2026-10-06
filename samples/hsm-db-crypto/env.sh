#!/usr/bin/env bash
# Manual sample defaults only. Supply your own CDSE_ORG_KEY before use.
# There is no universal key for installed or committed development databases.
# Never record production keys in this file. The automated test manager instead
# creates private fresh databases and uses an ephemeral first-run key.

export CDSE_SERVER="${CDSE_SERVER:-https://localhost:8443}"
export CDSE_USER_ID="${CDSE_USER_ID:-EngineAdmin}"
export CDSE_ORG_ID="${CDSE_ORG_ID:-EngineOrg}"
export CDSE_STORAGE="${CDSE_STORAGE:-EngineStorage}"
# Export an existing value without assigning a shared credential.
export CDSE_ORG_KEY
# HTTPS: also supply CDSE_CA_CERT, CDSE_CLIENT_CERT and CDSE_CLIENT_KEY paths.
