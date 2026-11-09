#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 0: DMZ recon. Only the customer-portal is actually reachable from
# here -- 22 is scanned deliberately so the closed port itself is signal
# (no sshd anywhere in this lab).
log "RECON" "Starting nmap scan against $TARGET_HOST (dmz)"
nmap -sV -p 22,80,443 -oN "$LOG_DIR/nmap-$(date +%s).txt" "$TARGET_HOST" 2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"

log "RECON" "Probing customer-portal for exposed paths"
for path in / /.git/config /nginx_status /api/health; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "${TARGET_HTTP}${path}")
  log "RECON" "GET ${path} -> ${code}"
done
banner=$(curl -s -D - -o /dev/null "${TARGET_HTTP}/" | grep -i '^X-Powered-By' || true)
log "RECON" "banner: ${banner:-none}"
log "RECON" "nmap scan complete"
