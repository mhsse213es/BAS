#!/bin/sh
# Fail closed: start with the default-deny rule set, then start the NFLOG
# collector. The lab bring-up applies the scenario rule set afterwards.
set -eu
mkdir -p /var/log/seg
ulogd -d -c /etc/ulogd.conf
/rules/apply.sh /rules/default.sh
exec sleep infinity
