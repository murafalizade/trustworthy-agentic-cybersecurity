#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Bounded, rate-limited internal stress test against the lab target only —
# not a real DDoS tool. Duration and concurrency are capped so it emulates
# an availability-attack *pattern* for the agent to detect, without ever
# leaving the private lab network.
DURATION="${DDOS_DURATION:-15}"
CONCURRENCY="${DDOS_CONCURRENCY:-20}"

log "STRESS-TEST" "Starting bounded load test against $TARGET_HOST (${CONCURRENCY}c / ${DURATION}s)"
ab -t "$DURATION" -c "$CONCURRENCY" "${TARGET_HTTP}/" > "$LOG_DIR/loadtest-$(date +%s).txt" 2>&1 || true
log "STRESS-TEST" "load test complete"
