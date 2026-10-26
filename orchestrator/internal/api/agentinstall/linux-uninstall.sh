#!/bin/sh
# Audspect BAS agent uninstaller for Linux. Run as root:  sudo sh ./bas-agent-uninstall-linux.run
# It asks nothing. The agent for this CPU is inside this file (checked against a recorded hash before it is run) and
# removes the service, the program, the configuration, certificates and enrolment, logs and the event spool.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "run as root: sudo sh $0" >&2; exit 1; fi
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
OFFSET=$(awk '/^__ARCHIVE_BELOW__$/ { print NR + 1; exit 0 }' "$0")
tail -n +"$OFFSET" "$0" | tar -xz -C "$TMP"
NAME="bas-agent-linux-$ARCH"
AGENT="$TMP/$NAME"
WANT=$(awk -v f="$NAME" '$2 == f { print $1 }' "$TMP/agents.sha256" 2>/dev/null)
HAVE=$(sha256sum "$AGENT" 2>/dev/null | awk '{ print $1 }')
if [ -z "$WANT" ] || [ "$WANT" != "$HAVE" ]; then
  echo "ERROR: the agent in this download is damaged or was changed. Do not use it; download it again from the Audspect dashboard." >&2
  exit 1
fi
chmod +x "$AGENT"
echo "==> Removing the Audspect Agent from this host"
set +e
"$AGENT" --uninstall
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
  echo "ERROR: the uninstall did not complete (exit code $RC). See the messages above." >&2
  exit "$RC"
fi
echo "The Audspect Agent was removed from this host."
exit 0
__ARCHIVE_BELOW__
