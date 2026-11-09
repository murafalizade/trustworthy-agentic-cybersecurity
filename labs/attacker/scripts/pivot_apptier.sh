#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 1: pivot. The dmz->app-tier/data-tier/mgmt path only exists if
# something actually routes through bank-router -- each banking service
# gets this for free via its own `*-route` sidecar, but the attacker has
# to do it itself. This mirrors a real post-foothold move (pointing
# default-gateway-less traffic at the known router) rather than an actual
# exploit; the interesting part is what it unlocks next.
if have_pivot; then
  log "PIVOT" "Route to 10.10.0.0/16 via ${ROUTER_DMZ_IP} already present"
  exit 0
fi

log "PIVOT" "Adding static route to 10.10.0.0/16 via router ${ROUTER_DMZ_IP} (exploiting flat FORWARD policy)"
if ip route add 10.10.0.0/16 via "$ROUTER_DMZ_IP" 2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"; then
  log "PIVOT" "Pivot successful -- app-tier/data-tier/mgmt now reachable"
else
  log "PIVOT" "Pivot failed"
fi
