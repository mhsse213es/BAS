FROM alpine:3.20
RUN apk add --no-cache iptables ulogd
COPY ulogd.conf /etc/ulogd.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
