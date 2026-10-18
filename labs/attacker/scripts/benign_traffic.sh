#!/bin/bash
set -uo pipefail
source "$(dirname "$0")/common.sh"

log "BENIGN" "Simulating normal user traffic"
for i in 1 2 3 4 5; do
  curl -s -A "Mozilla/5.0 (X11; Linux x86_64) NormalBrowser/1.0" "${TARGET_HTTP}/index.php" -o /dev/null
  curl -s "${TARGET_HTTP}/login.php?user=alice&pass=summer2024" -o /dev/null
  sleep "$((RANDOM % 3 + 1))"
done
log "BENIGN" "benign traffic simulation complete"
