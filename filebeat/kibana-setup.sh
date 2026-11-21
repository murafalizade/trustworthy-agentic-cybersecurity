#!/bin/sh
# Creates the Kibana data views for the banking log indices.
#
# Why this exists: filebeat ships logs into Elasticsearch under the
# banking-access-*/banking-error-*/banking-application-*/banking-network-*
# index patterns (see ../labs/docker-compose.yml filebeat output +
# setup.sh templates), but
# Kibana will not show anything in Discover until a *data view* points at
# those indices. Without this step the logs are in Elasticsearch yet
# invisible in Kibana -- the classic "my logs aren't in Kibana" symptom.
#
# The data views use wildcard titles (banking-access-*, not a single
# date like banking-access-2026.11.15) so they keep matching tomorrow's
# daily index, and @timestamp as the time field (set by every ingest
# pipeline) so the Discover time filter works.
set -eu

KB="http://kibana:5601"

echo "waiting for kibana to be available..."
# Poll /api/status until Kibana reports overall level "available".
i=0
until curl -s "$KB/api/status" 2>/dev/null | grep -q '"level":"available"'; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "kibana did not become available in time" >&2
    exit 1
  fi
  sleep 5
done
echo "kibana is available."

# title | name -- one data view per log_type index pattern.
create_data_view() {
  title="$1"
  name="$2"
  echo "creating data view: $title"
  code=$(curl -s -o /tmp/kb_resp -w "%{http_code}" -X POST "$KB/api/data_views/data_view" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    --data-binary "{\"data_view\":{\"title\":\"$title\",\"name\":\"$name\",\"timeFieldName\":\"@timestamp\"}}")
  if [ "$code" = "200" ]; then
    echo "  -> created ($code)"
  elif grep -q -i "duplicate\|already exists" /tmp/kb_resp 2>/dev/null; then
    echo "  -> already exists, skipping ($code)"
  else
    echo "  -> HTTP $code: $(cat /tmp/kb_resp 2>/dev/null)"
  fi
}

create_data_view "banking-access-*"      "banking-access"
create_data_view "banking-error-*"       "banking-error"
create_data_view "banking-application-*" "banking-application"
create_data_view "banking-network-*"     "banking-network"

echo "kibana setup complete."
