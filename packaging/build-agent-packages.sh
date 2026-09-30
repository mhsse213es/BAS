#!/usr/bin/env bash
# Builds .deb (amd64, arm64) and .rpm (x86_64) from pre-built agent binaries.
# Run inside the Docker packager stage.
# Env: BAS_VERSION
set -euo pipefail

VER="${BAS_VERSION:-1.6.0}"
mkdir -p /packages

# ── Shared systemd unit ───────────────────────────────────────────────────────
# ExecStartPre fetches the deployment CA root before every start, not just at
# install time -- BAS_SERVER_URL isn't known until the operator edits
# /etc/bas-agent/config after install, so a postinst-time fetch is
# impossible; this runs whenever that's actually known instead. The leading
# '-' means a failure here (curl missing, network down, server unreachable)
# never blocks the unit from starting -- the agent falls back to legacy
# transport as before, now visible via the dashboard's "Legacy transport"
# badge rather than silent. Skipped once a non-empty file already exists, so
# steady-state restarts do zero network I/O for this. On failure the partial
# file is removed so the next restart retries cleanly instead of treating a
# truncated download as "already fetched".
cat > /tmp/bas-agent.service <<'UNIT'
[Unit]
Description=BAS Agent (Audspect)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=-/bin/sh -c 'if [ -n "$BAS_SERVER_URL" ] && [ ! -s /etc/audspect/certs/deployment-ca.pem ]; then mkdir -p /etc/audspect/certs && (curl -sf -o /etc/audspect/certs/deployment-ca.pem "$BAS_SERVER_URL/api/config/ca-root" || rm -f /etc/audspect/certs/deployment-ca.pem); fi'
ExecStart=/usr/local/bin/bas-agent
EnvironmentFile=/etc/bas-agent/config
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bas-agent

[Install]
WantedBy=multi-user.target
UNIT

# ── .deb builder (amd64 and arm64) ───────────────────────────────────────────
build_deb() {
  local arch="$1" binary="$2"
  local D="/tmp/deb-${arch}"
  rm -rf "${D}"
  mkdir -p "${D}/DEBIAN" \
           "${D}/usr/local/bin" \
           "${D}/etc/bas-agent" \
           "${D}/lib/systemd/system"

  install -m 755 "$binary"              "${D}/usr/local/bin/bas-agent"
  install -m 644 /tmp/bas-agent.service "${D}/lib/systemd/system/bas-agent.service"

  printf 'BAS_SERVER_URL=\nBAS_ENV_LABEL=Production\nBAS_AGENT_SECRET=\n' \
    > "${D}/etc/bas-agent/config"
  chmod 600 "${D}/etc/bas-agent/config"

  cat > "${D}/DEBIAN/control" <<CTRL
Package: bas-agent
Version: ${VER}
Architecture: ${arch}
Maintainer: Audspect <support@audspect.com>
Section: utils
Priority: optional
Depends: systemd, curl
Description: BAS Platform Agent (Audspect)
 Breach & Attack Simulation endpoint agent.
 Edit /etc/bas-agent/config with BAS_SERVER_URL, then restart the service --
 the deployment CA root is fetched automatically on start once that URL is
 set (see bas-agent.service's ExecStartPre). If that fetch ever fails
 (server unreachable, no curl), the agent falls back to legacy transport and
 the dashboard's Agents page shows a "Legacy transport" warning badge until
 it's resolved and the service is restarted.
CTRL

  cat > "${D}/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e

# Write config only if it does not already exist (preserves reconfigure runs)
if [ ! -f /etc/bas-agent/config ] || ! grep -q "^BAS_SERVER_URL=.\+" /etc/bas-agent/config 2>/dev/null; then
  cat > /etc/bas-agent/config <<CFG
BAS_SERVER_URL=
BAS_ENV_LABEL=Production
BAS_AGENT_SECRET=
CFG
  chmod 600 /etc/bas-agent/config
fi

systemctl daemon-reload
systemctl enable bas-agent.service || true
systemctl start bas-agent.service  || true

echo ""
echo "  BAS Agent installed."
echo "  1. Configure /etc/bas-agent/config with your server URL and agent secret."
echo "  2. sudo systemctl restart bas-agent"
echo "     (the deployment CA root is fetched automatically on start now that"
echo "     BAS_SERVER_URL is set -- no manual step needed)"
echo "  View logs: journalctl -u bas-agent -f"
echo ""
POST
  chmod 755 "${D}/DEBIAN/postinst"

  cat > "${D}/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
systemctl stop bas-agent.service 2>/dev/null || true
systemctl disable bas-agent.service 2>/dev/null || true
PRERM
  chmod 755 "${D}/DEBIAN/prerm"

  dpkg-deb --build --root-owner-group "${D}" \
    "/packages/bas-agent-linux-${arch}.deb"
  echo "[+] bas-agent-linux-${arch}.deb"
}

build_deb amd64 /binaries/bas-agent-linux-amd64
build_deb arm64 /binaries/bas-agent-linux-arm64

# ── .rpm via alien from the amd64 .deb ───────────────────────────────────────
cd /packages
alien --to-rpm --scripts "bas-agent-linux-amd64.deb"
# alien produces bas-agent-<ver>-<rel>.x86_64.rpm — normalise the filename
rpm_src=$(ls bas-agent-*.x86_64.rpm 2>/dev/null | head -1)
if [[ -n "$rpm_src" ]]; then
  mv "$rpm_src" "bas-agent-linux-amd64.rpm"
  echo "[+] bas-agent-linux-amd64.rpm"
else
  echo "[!] RPM not produced by alien"
fi
