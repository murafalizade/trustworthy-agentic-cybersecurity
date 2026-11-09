FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
      hydra nmap sqlmap curl iputils-ping apache2-utils \
      iproute2 postgresql-client jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

CMD ["/scripts/random_campaign.sh"]
