#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 1.5: once pivoted, sweep what the flat FORWARD policy actually
# exposes -- app-tier (core-banking, transactions, supply-chain) and,
# since the router bridges every segment, mgmt-tier (prometheus, grafana)
# too. This is the "noisy neighbor" finding the lab's Postgres comment
# warns about, playing out at the network layer as well.
if ! have_pivot; then
  log "RECON-APP" "No app-tier route yet -- skipping (run pivot_apptier.sh first)"
  exit 0
fi

log "RECON-APP" "Sweeping app-tier and mgmt-tier now reachable via router"
nmap -sV -p 80,3000,9090,5432 -oN "$LOG_DIR/nmap-apptier-$(date +%s).txt" \
  "$CORE_BANKING_IP" "$TRANSACTIONS_IP" "$SUPPLY_CHAIN_IP" "$PROMETHEUS_IP" "$GRAFANA_IP" "$POSTGRES_IP" \
  2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"

for ip in "$CORE_BANKING_IP" "$TRANSACTIONS_IP" "$SUPPLY_CHAIN_IP"; do
  banner=$(curl -s -D - -o /dev/null --max-time 5 "http://${ip}:80/" | grep -i '^X-Powered-By' || true)
  log "RECON-APP" "${ip} banner: ${banner:-none/unreachable}"
done

log "RECON-APP" "app-tier/mgmt-tier sweep complete"
