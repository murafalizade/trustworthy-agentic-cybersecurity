#!/bin/sh
set -e

ip route replace 10.10.0.0/16 via 10.10.2.250 2>/dev/null || true

cd /app
gunicorn --preload --bind 127.0.0.1:5000 --workers 2 app:app &

exec nginx -g 'daemon off;'
