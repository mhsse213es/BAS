#!/bin/bash
# A stand-in for bas-agent, for testing the package's maintainer scripts. It does what the real agent's -install and
# -uninstall do to the filesystem (binary, config, unit, identity), without systemd or a server.
#FAKE_VERSION=@VERSION@
@CRASH@
set -eu
cmd="${1:-}"; shift || true
case "$cmd" in
  -preflight) cat >/dev/null; exit 0 ;;
  -install)
    server=""; port=""; env=""
    while [ $# -gt 0 ]; do
      case "$1" in -server) server="$2"; shift 2 ;; -enroll-port) port="$2"; shift 2 ;; -env) env="$2"; shift 2 ;; *) shift ;; esac
    done
    IFS= read -r secret
    install -d -m 0755 /usr/local/bin
    install -m 0755 "$0" /usr/local/bin/bas-agent
    install -d -m 0755 /etc/bas-agent
    printf 'BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\nBAS_ENROLL_PORT=%s\n' "$server" "$env" "$secret" "$port" > /etc/bas-agent/config
    chmod 600 /etc/bas-agent/config
    printf '[Service]\nExecStart=/usr/local/bin/bas-agent\n' > /etc/systemd/system/bas-agent.service
    install -d -m 0700 /etc/audspect/certs
    if [ ! -f /etc/audspect/certs/agent-cert.pem ]; then
      openssl req -new -newkey rsa:2048 -nodes -keyout /etc/audspect/certs/agent-key.pem -subj "/CN=agent" -out /tmp/agent.csr 2>/dev/null
      openssl x509 -req -in /tmp/agent.csr -CA /test/ca.pem -CAkey /test/ca.key -CAcreateserial -days 30 -out /etc/audspect/certs/agent-cert.pem 2>/dev/null
      echo enrolled > /etc/audspect/certs/enrollment-state
    fi
    systemctl enable --now bas-agent.service
    exit 0 ;;
  -uninstall)
    systemctl stop bas-agent 2>/dev/null || true
    rm -f /etc/systemd/system/bas-agent.service /usr/local/bin/bas-agent
    if [ "${BAS_UNINSTALL_KEEP_DATA:-}" != "1" ]; then rm -rf /etc/bas-agent /etc/audspect; fi
    exit 0 ;;
esac
exit 0
