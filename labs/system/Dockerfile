FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server rsyslog nginx sudo php-cli php-sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# containers have no kernel log access, so remove imklog or rsyslog errors out
# also tee auth logs into the shared lab volume so every service's logs land in one place
RUN sed -i '/imklog/d' /etc/rsyslog.conf \
 && echo 'auth,authpriv.*    /var/log/lab/auth.log' >> /etc/rsyslog.conf \
 && mkdir -p /run/sshd /var/log/lab \
 && useradd -m -s /bin/bash alice && echo 'alice:summer2024' | chpasswd \
 && useradd -m -s /bin/bash admin && echo 'admin:admin123' | chpasswd

COPY nginx.conf /etc/nginx/sites-available/default
COPY www /var/www/app
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 22 80
VOLUME ["/var/log/lab"]
CMD ["/start.sh"]
