#!/bin/sh
# usage: apply.sh <rule-file>
# Rule file lines: RULEID ACTION SRC_IP DST_IP DST_PORT PROTO
#   ACTION is ACCEPT, DROP or REJECT. Blank lines and lines starting with # are ignored.
# Every rule logs through NFLOG before its verdict, with prefix "RULEID|ACTION",
# so the log records which rule decided each flow.
set -eu
RULES="$1"
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
while read -r id action src dst port proto; do
  case "$id" in ''|\#*) continue ;; esac
  iptables -A FORWARD -s "$src" -d "$dst" -p "$proto" --dport "$port" \
    -j NFLOG --nflog-group 1 --nflog-prefix "$id|$action"
  iptables -A FORWARD -s "$src" -d "$dst" -p "$proto" --dport "$port" -j "$action"
done < "$RULES"
# NO_CATCHALL=1 is for tests that need an unlogged drop: the FORWARD policy
# (DROP, set above) then drops unmatched traffic without a log record. Never
# set in normal runs; the default catch-all logs every drop.
if [ "${NO_CATCHALL:-0}" != "1" ]; then
  iptables -A FORWARD -j NFLOG --nflog-group 1 --nflog-prefix "SEG-CATCHALL|DROP"
  iptables -A FORWARD -j DROP
fi
echo "applied $RULES"
