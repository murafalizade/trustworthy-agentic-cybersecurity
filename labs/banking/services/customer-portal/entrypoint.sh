#!/bin/sh
set -e

# Static route to the other three segments via the router on this
# segment, applied on every container start (not just once via a
# one-shot sidecar) -- this container only has NET_ADMIN and a route
# table of its own, not a persistent one shared with a sidecar, so if the
# sidecar pattern is used instead, any restart/recreate of *this*
# container silently loses the route while the stale sidecar keeps
# holding open the old (discarded) network namespace. Baking it in here
# means the route always matches whichever netns is actually running.
ip route replace 10.10.0.0/16 via 10.10.1.250 2>/dev/null || true

cd /app
# --preload loads app.py (and its module-level bootstrap() schema/seed
# call) once in the master before forking workers -- without it, each of
# the 2 workers imports the module independently and races the other to
# run "CREATE TABLE IF NOT EXISTS" + the admin seed insert, which crashes
# both on a duplicate-key error and kills the gunicorn master (nginx
# stays up in front of it and just serves 502s).
gunicorn --preload --bind 127.0.0.1:5000 --workers 2 app:app &

exec nginx -g 'daemon off;'
