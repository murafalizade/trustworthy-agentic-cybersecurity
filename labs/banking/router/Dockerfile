FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      frr iproute2 iptables procps \
    && rm -rf /var/lib/apt/lists/*

COPY daemons /etc/frr/daemons
COPY frr.conf /etc/frr/frr.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown frr:frr /etc/frr/frr.conf

EXPOSE 2601 2604
ENTRYPOINT ["/entrypoint.sh"]
