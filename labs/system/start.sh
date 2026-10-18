#!/bin/bash
mkdir -p /var/log/nginx /var/log/lab      # the volume hides the package's directory

php /var/www/app/init_db.php

rsyslogd
nginx
php -S 127.0.0.1:8080 -t /var/www/app >> /var/log/lab/php-app.log 2>&1 &
exec /usr/sbin/sshd -D -e
