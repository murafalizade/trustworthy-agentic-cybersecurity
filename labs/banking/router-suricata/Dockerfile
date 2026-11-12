# Separate image because Debian bookworm's apt repos dropped the
# `suricata` package entirely (confirmed: no candidate on either arch) --
# Alpine's community repo still ships it. Runs as a sidecar sharing the
# router container's network namespace (see docker-compose.yml
# `network_mode: "service:router"`) so it can sniff the same 4 interfaces
# (eth0=dmz, eth1=app-tier, eth2=data-tier, eth3=mgmt) the router itself
# routes between.
FROM alpine:3.19

RUN apk add --no-cache suricata

COPY suricata.yaml /etc/suricata/suricata.yaml
COPY local.rules /etc/suricata/rules/local.rules

CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "--af-packet", "-l", "/var/log/suricata"]
