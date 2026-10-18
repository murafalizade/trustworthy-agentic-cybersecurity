#!/bin/bash
TARGET_HOST="${TARGET_HOST:-target}"
TARGET_HTTP="http://${TARGET_HOST}:80"
TARGET_SSH_PORT="${TARGET_SSH_PORT:-22}"
LOG_DIR="${LOG_DIR:-/var/log/lab}"
mkdir -p "$LOG_DIR"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [$1] $2" | tee -a "$LOG_DIR/attacker-campaign.log"; }
