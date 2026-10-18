#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "RECON" "Starting nmap scan against $TARGET_HOST"
nmap -sV -p 22,80 -oN "$LOG_DIR/nmap-$(date +%s).txt" "$TARGET_HOST" 2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"
log "RECON" "nmap scan complete"
