#!/bin/bash
TARGET_HOST="${TARGET_HOST:-target}"
TARGET_HTTP="http://${TARGET_HOST}:80"
TARGET_SSH_PORT="${TARGET_SSH_PORT:-22}"
LOG_DIR="${LOG_DIR:-/var/log/lab}"
mkdir -p "$LOG_DIR"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] [$1] $2" | tee -a "$LOG_DIR/attacker-campaign.log"; }

# --- Banking topology, as static IPs ---------------------------------
# The attacker container only has an interface on the dmz segment, so
# names outside it (app-tier/data-tier/mgmt) won't resolve via Docker's
# embedded DNS -- these are the same static addresses banking's own
# docker-compose.yml assigns each container.
ROUTER_DMZ_IP="10.10.1.250"
CORE_BANKING_IP="10.10.2.10"
TRANSACTIONS_IP="10.10.2.11"
SUPPLY_CHAIN_IP="10.10.2.12"
POSTGRES_IP="10.10.3.10"
PROMETHEUS_IP="10.10.4.10"
GRAFANA_IP="10.10.4.11"

# --- Campaign state, persisted across script invocations within this
# container's lifetime (random_campaign.sh re-execs a fresh script each
# iteration, so stage progress/harvested creds must live on disk). ----
STATE_DIR="${LOG_DIR}/.state"
mkdir -p "$STATE_DIR"
CREDS_FILE="$STATE_DIR/harvested_creds.env"
touch "$CREDS_FILE"

have_pivot() {
  ip route show | grep -q "10.10.0.0/16"
}

save_cred() {
  # save_cred KEY VALUE -- de-dupes by key, last write wins.
  local key="$1" value="$2"
  grep -v "^${key}=" "$CREDS_FILE" > "${CREDS_FILE}.tmp" 2>/dev/null || true
  mv "${CREDS_FILE}.tmp" "$CREDS_FILE"
  echo "${key}=${value}" >> "$CREDS_FILE"
}
