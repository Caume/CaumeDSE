#!/usr/bin/env bash
# CaumeDSE sample environment — source this file before running examples.
#
#   source env.sh
#   python3 b-python/cdse_client.py info --insecure
#
# CDSE generates a fresh random orgKey the first time it starts with empty
# databases.  The value below is the key for the local development installation
# at /opt/cdse/.  Update it whenever the databases are reset.

export CDSE_SERVER="https://localhost:8443"
export CDSE_USER_ID="EngineAdmin"
export CDSE_ORG_ID="EngineOrg"
export CDSE_ORG_KEY="187465950C5F9018D04F91E976CAC1D7FA19CBA5FE26D94038630B18BCBAAAB6"
export CDSE_STORAGE="EngineStorage"
