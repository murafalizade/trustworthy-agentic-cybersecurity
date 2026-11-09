#!/bin/sh
set -e

# Already applied at container creation via compose's `sysctls:` key;
# this call is redundant and fails with "permission denied" on some
# Docker setups (the namespaced sysctl is pre-set, not writable again
# from inside) -- must not be fatal under `set -e`.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Default posture is wide-open forwarding between every segment — an
# intentional flat-network misconfiguration so a foothold in the DMZ can
# pivot straight to the data tier. Tighten this to an explicit allow-list
# (DROP by default, ACCEPT specific src/dst/port triples) to practice
# against a hardened perimeter instead.
iptables -P FORWARD ACCEPT
iptables -t nat -F

/usr/lib/frr/frrinit.sh start

mkdir -p /var/log/frr
touch /var/log/frr/zebra.log /var/log/frr/ospfd.log
exec tail -F /var/log/frr/zebra.log /var/log/frr/ospfd.log
