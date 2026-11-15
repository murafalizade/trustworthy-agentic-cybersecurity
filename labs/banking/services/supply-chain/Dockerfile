FROM nginx:1.27-alpine

RUN apk add --no-cache python3 py3-flask py3-psycopg2 py3-gunicorn iproute2

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY app /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
