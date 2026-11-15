#!/bin/sh
set -e

# Same self-routing fix as every other banking service's entrypoint.sh:
# applied on every container start instead of once via a one-shot
# `*-route` sidecar, so a restart/recreate of this container can't leave
# it unreachable from the other segments.
ip route replace 10.10.0.0/16 via 10.10.3.250 2>/dev/null || true

exec docker-entrypoint.sh "$@"
