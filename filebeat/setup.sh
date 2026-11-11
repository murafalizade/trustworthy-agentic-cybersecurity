#!/bin/sh
set -eu

ES="http://elasticsearch:9200"

for f in /filebeat/pipelines/*.json; do
  name=$(basename "$f" .json)
  echo "installing ingest pipeline: $name"
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$ES/_ingest/pipeline/$name" \
    -H "Content-Type: application/json" --data-binary "@$f")
  echo "  -> HTTP $code"
done

for f in /filebeat/templates/*.json; do
  name=$(basename "$f" .json)
  echo "installing index template: $name"
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$ES/_index_template/$name" \
    -H "Content-Type: application/json" --data-binary "@$f")
  echo "  -> HTTP $code"
done

echo "filebeat setup complete."
