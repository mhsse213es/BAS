#!/bin/bash
# Runs inside the test container: builds three package versions around a fake agent and walks the real maintainer
# scripts through install, upgrade, a failed upgrade, remove, re-install, purge, and replacing the old bas-agent package.
set -uo pipefail

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1  [$2]"; fi; }
section() { echo; echo "== $1"; }

export AUDSPECT_HEALTH_WAIT=8 AUDSPECT_HEALTH_STABLE=3
PK=/test/pkg; mkdir -p "$PK" /etc/audspect-agent
INSTALLER=/src/install-agent-linux.sh

# a deployment CA, and its fingerprint
openssl req -x509 -newkey rsa:2048 -nodes -keyout /test/ca.key -out /test/ca.pem -days 30 -subj "/CN=Test CA" 2>/dev/null
FP="$(openssl x509 -in /test/ca.pem -noout -fingerprint -sha256 | cut -d= -f2)"

build() { # version crash(0|1)
  sed -e "s/@VERSION@/$1/" -e "s/@CRASH@/$( [ "$2" = 1 ] && echo '#CRASH=1' || echo '#ok')/" /test/fake-agent.sh > "/test/agent-$1"
  BAS_VERSION="$1" bash /src/linux-deb/build-deb.sh amd64 "/test/agent-$1" "$INSTALLER" "$PK/audspect-agent_$1_amd64.deb" >/dev/null
}
build 1.0.0 0; build 1.1.0 0; build 1.2.0 1

write_env() {
  install -d -m 0755 /etc/audspect-agent
  cat > /etc/audspect-agent/enroll.env <<EOF
BAS_SERVER_HOST=audspect.test
BAS_MTLS_PORT=9443
BAS_ENROLL_PORT=9445
BAS_ENV_LABEL=Lab
BAS_AGENT_SECRET=s3cret-value
BAS_CA_FINGERPRINT=$FP
BAS_CA_FILE_PATH=/test/ca.pem
EOF
  chmod 600 /etc/audspect-agent/enroll.env
}
version_of() { grep -m1 '^#FAKE_VERSION=' "$1" 2>/dev/null | cut -d= -f2; }
id_sum() { sha256sum /etc/audspect/certs/agent-cert.pem /etc/audspect/certs/agent-key.pem 2>/dev/null | cut -d' ' -f1 | tr -d '\n'; }

section "package contents"
check "control names the package and replaces bas-agent" "dpkg-deb -f $PK/audspect-agent_1.0.0_amd64.deb Package Conflicts Replaces | tr '\n' ' ' | grep -q 'audspect-agent.*bas-agent.*bas-agent'"
check "payload is under /usr/lib/audspect-agent, not /usr/local/bin" "dpkg-deb -c $PK/audspect-agent_1.0.0_amd64.deb | grep -q 'usr/lib/audspect-agent/bas-agent' && ! dpkg-deb -c $PK/audspect-agent_1.0.0_amd64.deb | grep -q 'usr/local/bin'"
check "no file under /etc is shipped (so dpkg never overwrites configuration)" "! dpkg-deb -c $PK/audspect-agent_1.0.0_amd64.deb | grep -q ' \./etc/'"
check "a version that is not a Debian version is refused" "! BAS_VERSION=dev bash /src/linux-deb/build-deb.sh amd64 /test/agent-1.0.0 $INSTALLER /tmp/x.deb 2>/dev/null"

section "install without enrolment details"
rm -rf /etc/audspect-agent/enroll.env
out=$(dpkg -i $PK/audspect-agent_1.0.0_amd64.deb 2>&1); rc=$?
check "installs cleanly" "[ $rc -eq 0 ]"
check "tells the administrator how to enrol" "echo \"\$out\" | grep -q 'not enrolled yet'"
check "no service was created" "[ ! -f /etc/systemd/system/bas-agent.service ]"

section "enrol from enroll.env"
write_env
chmod 644 /etc/audspect-agent/enroll.env
check "a world-readable enroll.env is refused" "! audspect-agent-setup >/dev/null 2>&1"
chmod 600 /etc/audspect-agent/enroll.env
out=$(audspect-agent-setup 2>&1); rc=$?
check "enrols" "[ $rc -eq 0 ]"
check "service installed and running" "[ -f /etc/systemd/system/bas-agent.service ] && systemctl is-active --quiet bas-agent"
check "binary installed is version 1.0.0" "[ \"\$(version_of /usr/local/bin/bas-agent)\" = 1.0.0 ]"
check "config carries the server and the secret" "grep -q 'BAS_SERVER_URL=https://audspect.test:9443' /etc/bas-agent/config && grep -q 'BAS_AGENT_SECRET=s3cret-value' /etc/bas-agent/config"
check "the secret was removed from enroll.env" "! grep -q 's3cret-value' /etc/audspect-agent/enroll.env"
check "the deployment CA was stored" "[ -s /etc/audspect-agent/deployment-ca.pem ]"
ID0="$(id_sum)"; CFG0="$(sha256sum /etc/bas-agent/config | cut -d' ' -f1)"

section "upgrade 1.0.0 -> 1.1.0"
out=$(dpkg -i $PK/audspect-agent_1.1.0_amd64.deb 2>&1); rc=$?
check "upgrade succeeds" "[ $rc -eq 0 ]"
check "binary is now 1.1.0" "[ \"\$(version_of /usr/local/bin/bas-agent)\" = 1.1.0 ]"
check "service is running" "systemctl is-active --quiet bas-agent"
check "identity (certificate and key) untouched" "[ \"\$(id_sum)\" = \"$ID0\" ]"
check "configuration untouched" "[ \"\$(sha256sum /etc/bas-agent/config | cut -d' ' -f1)\" = \"$CFG0\" ]"
check "the service was not disabled by the upgrade" "! grep -q '^disable' /run/fake-systemd/calls"

section "failed upgrade 1.1.0 -> 1.2.0 (new binary does not stay running)"
out=$(dpkg -i $PK/audspect-agent_1.2.0_amd64.deb 2>&1); rc=$?
check "dpkg reports the failure" "[ $rc -ne 0 ]"
check "the previous binary (1.1.0) was restored" "[ \"\$(version_of /usr/local/bin/bas-agent)\" = 1.1.0 ]"
check "the service is running again" "systemctl is-active --quiet bas-agent"
check "identity untouched" "[ \"\$(id_sum)\" = \"$ID0\" ]"
check "the failure is explained" "echo \"\$out\" | grep -q 'restoring the previous version'"
dpkg -i $PK/audspect-agent_1.1.0_amd64.deb >/dev/null 2>&1

section "remove keeps the customer's data"
dpkg -r audspect-agent >/dev/null 2>&1; rc=$?
check "remove succeeds" "[ $rc -eq 0 ]"
check "service, unit and binary are gone" "[ ! -f /etc/systemd/system/bas-agent.service ] && [ ! -e /usr/local/bin/bas-agent ] && [ ! -e /usr/lib/audspect-agent/bas-agent ]"
check "configuration kept" "[ -s /etc/bas-agent/config ]"
check "identity kept" "[ \"\$(id_sum)\" = \"$ID0\" ]"
check "stored CA kept" "[ -s /etc/audspect-agent/deployment-ca.pem ]"

section "re-install after remove re-uses the enrolment"
out=$(dpkg -i $PK/audspect-agent_1.1.0_amd64.deb 2>&1); rc=$?
check "installs" "[ $rc -eq 0 ]"
check "service installed and running again" "[ -f /etc/systemd/system/bas-agent.service ] && systemctl is-active --quiet bas-agent"
check "same identity (not re-enrolled as a new agent)" "[ \"\$(id_sum)\" = \"$ID0\" ]"

section "purge erases everything"
dpkg -P audspect-agent >/dev/null 2>&1; rc=$?
check "purge succeeds" "[ $rc -eq 0 ]"
check "nothing of the agent is left" "[ ! -e /etc/bas-agent ] && [ ! -e /etc/audspect ] && [ ! -e /etc/audspect-agent ] && [ ! -e /var/lib/audspect-agent ] && [ ! -e /usr/local/bin/bas-agent ] && [ ! -f /etc/systemd/system/bas-agent.service ]"

section "replacing the old bas-agent package"
# an old-style package: binary in /usr/local/bin, config under /etc/bas-agent, no service unit left after its prerm
OLD=/test/old; rm -rf $OLD; mkdir -p $OLD/DEBIAN $OLD/usr/local/bin $OLD/etc/bas-agent
cp /test/agent-1.0.0 $OLD/usr/local/bin/bas-agent
printf 'BAS_SERVER_URL=https://audspect.test:9443\nBAS_ENV_LABEL=Lab\nBAS_AGENT_SECRET=old-secret\nBAS_ENROLL_PORT=9445\n' > $OLD/etc/bas-agent/config
printf 'Package: bas-agent\nVersion: 1.6.0\nArchitecture: amd64\nMaintainer: x\nDescription: old\n' > $OLD/DEBIAN/control
printf '#!/bin/sh\nsystemctl stop bas-agent.service 2>/dev/null||true\nsystemctl disable bas-agent.service 2>/dev/null||true\n' > $OLD/DEBIAN/prerm; chmod 755 $OLD/DEBIAN/prerm
dpkg-deb --build --root-owner-group $OLD /test/old.deb >/dev/null
dpkg -i /test/old.deb >/dev/null 2>&1
# the old package kept the CA it fetched with the agent's certificates
install -d -m 0700 /etc/audspect/certs; install -m 0644 /test/ca.pem /etc/audspect/certs/deployment-ca.pem
out=$(dpkg -i $PK/audspect-agent_1.1.0_amd64.deb 2>&1); rc=$?
check "the new package replaces bas-agent" "[ $rc -eq 0 ] && ! dpkg -s bas-agent >/dev/null 2>&1 && dpkg -s audspect-agent >/dev/null 2>&1"
check "the old configuration was used to bring the agent up" "[ -f /etc/systemd/system/bas-agent.service ] && systemctl is-active --quiet bas-agent"
check "the new configuration carries the old server and secret" "grep -q 'BAS_AGENT_SECRET=old-secret' /etc/bas-agent/config"
check "the saved copy of the old configuration was removed" "[ ! -e /var/lib/audspect-agent/legacy ]"
dpkg -P audspect-agent >/dev/null 2>&1

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
