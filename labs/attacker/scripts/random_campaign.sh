#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "CAMPAIGN" "Attacker campaign starting against $TARGET_HOST"

until curl -s -o /dev/null "${TARGET_HTTP}/"; do
  log "CAMPAIGN" "waiting for target to come up..."
  sleep 3
done

# A real intrusion isn't a uniform-random pick every tick -- it's a
# sequence of stages (recon, foothold, pivot, harvest, lateral movement,
# abuse) with ordinary background traffic mixed in between. The stage
# scripts themselves are idempotent/cheap to re-run (pivot_apptier.sh
# no-ops once the route exists, etc.), so re-running the whole chain each
# lap is fine and gives recurring campaigns rather than a one-shot.
KILL_CHAIN=(
  "/scripts/recon_nmap.sh"
  "/scripts/pivot_apptier.sh"
  "/scripts/recon_apptier.sh"
  "/scripts/harvest_credentials.sh"
  "/scripts/abuse_debug_sql.sh"
  "/scripts/lateral_postgres.sh"
  "/scripts/credential_stuffing.sh"
)

NOISE=(
  "/scripts/benign_traffic.sh"
  "/scripts/benign_traffic.sh"
  "/scripts/prompt_injection.sh"
  "/scripts/load_test_ddos_style.sh"
)

run() {
  log "CAMPAIGN" "Running $1"
  "$1" || log "CAMPAIGN" "$1 exited with error"
  sleep "$((RANDOM % 60 + 20))"
}

while true; do
  log "CAMPAIGN" "=== starting kill-chain lap ==="
  for stage in "${KILL_CHAIN[@]}"; do
    run "$stage"
    # Odds of a benign/noise action between stages, like a real network
    # that isn't 100% attacker traffic even mid-campaign.
    if (( RANDOM % 3 == 0 )); then
      run "${NOISE[$((RANDOM % ${#NOISE[@]}))]}"
    fi
  done
  log "CAMPAIGN" "=== kill-chain lap complete, pausing before next lap ==="
  sleep "$((RANDOM % 120 + 60))"
done
