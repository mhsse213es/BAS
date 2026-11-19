#!/usr/bin/env bash
# build-deb.sh <arch> <agent-binary> <install-agent-linux.sh> <out.deb>   (env: BAS_VERSION)
#
# Builds the audspect-agent .deb. Needs dpkg-deb. Run inside the Docker packager stage.
#
# The package carries the agent as a payload under /usr/lib/audspect-agent together with the console's own installer
# script; the maintainer scripts call that installer, so the package and the console install command share one
# implementation of enrolment, identity handling and service creation.
set -euo pipefail

ARCH="$1"; BINARY="$2"; INSTALLER="$3"; OUT="$4"
VER="${BAS_VERSION:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

case "$ARCH" in amd64 | arm64) ;; *) echo "unsupported architecture: $ARCH" >&2; exit 2 ;; esac
# A Debian version starts with a digit; a build tagged "dev" would produce a package dpkg refuses.
if ! printf '%s' "$VER" | grep -Eq '^[0-9][A-Za-z0-9.+~-]*$'; then
  echo "BAS_VERSION '$VER' is not a valid Debian version (must start with a digit, e.g. 1.9.9)" >&2
  exit 2
fi
[ -f "$BINARY" ] && [ -f "$INSTALLER" ] || { echo "agent binary or installer script not found" >&2; exit 2; }

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
install -d -m 0755 "$D/DEBIAN" "$D/usr/lib/audspect-agent" "$D/usr/sbin" "$D/usr/share/doc/audspect-agent"

install -m 0755 "$BINARY"                  "$D/usr/lib/audspect-agent/bas-agent"
install -m 0755 "$INSTALLER"               "$D/usr/lib/audspect-agent/install-agent-linux.sh"
install -m 0755 "$HERE/audspect-agent-setup" "$D/usr/sbin/audspect-agent-setup"
install -m 0644 "$HERE/enroll.env.example" "$D/usr/share/doc/audspect-agent/enroll.env.example"

for s in preinst postinst prerm postrm; do
  install -m 0755 "$HERE/debian/$s" "$D/DEBIAN/$s"
done

SIZE_KB="$(du -sk "$D" | cut -f1)"
cat > "$D/DEBIAN/control" <<CTRL
Package: audspect-agent
Version: ${VER}
Architecture: ${ARCH}
Maintainer: Audspect <support@audspect.com>
Section: utils
Priority: optional
Installed-Size: ${SIZE_KB}
Depends: systemd, openssl, curl, ca-certificates
Conflicts: bas-agent
Replaces: bas-agent
Description: Audspect breach and attack simulation endpoint agent
 Runs as root (attack simulations need it) under systemd as bas-agent.service.
 Enrol the host by putting the deployment values in /etc/audspect-agent/enroll.env
 before installing, or run: sudo audspect-agent-setup
 .
 Upgrades keep the configuration, certificates and agent identity, and restore
 the previous version if the new one does not stay running. Removing the package
 keeps them; purging it erases them.
CTRL

dpkg-deb --build --root-owner-group "$D" "$OUT" >/dev/null
echo "[+] $(basename "$OUT")  (audspect-agent ${VER}, ${ARCH})"
