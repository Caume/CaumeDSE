#!/usr/bin/env bash
# CaumeDSE sample environment — source this file before running examples.
#
#   source env.sh
#   python3 b-python/cdse_client.py info --insecure
#
# CDSE_ORG_KEY is the organisation encryption key for the included development
# databases at /opt/cdse/.  This key was generated randomly when those
# databases were first initialised and is documented here so that the sample
# applications and automated tests can be run against them without interaction.
#
# If you reset the databases (delete /opt/cdse/ contents and restart CDSE),
# a new key will be printed to the console.  Update this file with that key.
#
# Security note: this file is for development use only.  Never commit
# production keys to version control.

export CDSE_SERVER="https://localhost:8443"
export CDSE_USER_ID="EngineAdmin"
export CDSE_ORG_ID="EngineOrg"
export CDSE_ORG_KEY="187465950C5F9018D04F91E976CAC1D7FA19CBA5FE26D94038630B18BCBAAAB6"
export CDSE_STORAGE="EngineStorage"
