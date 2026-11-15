FROM postgres:16

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/bank-entrypoint.sh
RUN chmod +x /usr/local/bin/bank-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/bank-entrypoint.sh"]
CMD ["postgres"]
