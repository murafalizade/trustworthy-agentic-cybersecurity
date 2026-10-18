#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "CAMPAIGN" "Attacker campaign starting against $TARGET_HOST"

until curl -s -o /dev/null "${TARGET_HTTP}/"; do
  log "CAMPAIGN" "waiting for target to come up..."
  sleep 3
done

# Weighted so roughly a third of the traffic is benign, like a real network.
SCRIPTS=(
  "/scripts/benign_traffic.sh"
  "/scripts/benign_traffic.sh"
  "/scripts/benign_traffic.sh"
  "/scripts/recon_nmap.sh"
  "/scripts/sqli_sqlmap.sh"
  "/scripts/bruteforce_ssh_hydra.sh"
  "/scripts/bruteforce_http_hydra.sh"
  "/scripts/prompt_injection.sh"
  "/scripts/load_test_ddos_style.sh"
)

while true; do
  idx=$((RANDOM % ${#SCRIPTS[@]}))
  chosen="${SCRIPTS[$idx]}"
  log "CAMPAIGN" "Running $chosen"
  "$chosen" || log "CAMPAIGN" "$chosen exited with error"
  sleep_time=$((RANDOM % 60 + 20))
  log "CAMPAIGN" "Sleeping ${sleep_time}s before next action"
  sleep "$sleep_time"
done
