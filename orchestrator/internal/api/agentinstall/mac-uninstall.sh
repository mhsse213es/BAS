#!/bin/sh
# Audspect Agent uninstaller for macOS: the program inside "Audspect Agent Uninstall.app".
# It asks to confirm, asks macOS for administrator rights, and runs the agent's own uninstall, which removes the
# launchd daemon, the program, the configuration, the certificates and enrolment, logs and the event spool. The agent
# for this Mac is inside the app and is checked against a recorded hash before it is run, so it also works when the
# installed agent is missing or damaged.
set -u

TITLE="Audspect Agent Uninstall"
SELF="$0"
RES="$(cd "$(dirname "$SELF")/../Resources" 2>/dev/null && pwd)"

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
ICON="$RES/AppIcon.icns"
ICONCLAUSE=""
[ -f "$ICON" ] && ICONCLAUSE=" with icon file ((POSIX file \"$(esc "$ICON")\") as text)"

# dialog <message> <fallback icon: stop|note>: an information box with the Audspect icon. If this macOS refuses the custom
# icon, the same box is shown with the standard one, so a cosmetic problem can never hide a message.
dialog() {
	if [ -n "$ICONCLAUSE" ]; then
		osascript -e "display dialog \"$(esc "$1")\" with title \"$TITLE\" buttons {\"OK\"} default button \"OK\"$ICONCLAUSE" >/dev/null 2>&1 && return 0
	fi
	osascript -e "display dialog \"$(esc "$1")\" with title \"$TITLE\" buttons {\"OK\"} default button \"OK\" with icon $2" >/dev/null 2>&1
	return 0
}

# confirm: returns 1 when the person chose Cancel.
confirm() {
	MSG="Remove the Audspect Agent and all of its data from this Mac? This stops the agent, deletes its certificates, configuration and logs, and tells your Audspect server it was decommissioned."
	BTN="buttons {\"Cancel\", \"Remove\"} default button \"Cancel\""
	if [ -n "$ICONCLAUSE" ]; then
		ERR="$(osascript -e "display dialog \"$(esc "$MSG")\" with title \"$TITLE\" $BTN$ICONCLAUSE" 2>&1 >/dev/null)" && return 0
		case "$ERR" in *"User canceled"* | *"(-128)"*) return 1 ;; esac
	fi
	osascript -e "display dialog \"$(esc "$MSG")\" with title \"$TITLE\" $BTN with icon caution" >/dev/null 2>&1
}

# ---- second phase: runs as root through the administrator prompt ----
if [ "${1:-}" = "--do-uninstall" ]; then
	AGENT="$2"
	RESULT="$3"
	"$AGENT" --uninstall >"$RESULT.log" 2>&1
	echo $? >"$RESULT"
	exit 0
fi

# ---- first phase: runs as the logged-in user ----
if [ -z "$RES" ] || [ ! -f "$RES/agents.sha256" ]; then
	dialog "This copy of the uninstaller is incomplete. Download it again from the Audspect dashboard." stop
	exit 1
fi

if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then NAME="bas-agent-arm64"; else NAME="bas-agent-x86_64"; fi
AGENT="$RES/$NAME"
WANT="$(awk -v f="$NAME" '$2 == f { print $1 }' "$RES/agents.sha256" 2>/dev/null)"
HAVE="$(shasum -a 256 "$AGENT" 2>/dev/null | awk '{print $1}')"
if [ -z "$WANT" ] || [ "$WANT" != "$HAVE" ]; then
	dialog "The agent in this download is damaged or was changed. Do not use it; download it again from the Audspect dashboard." stop
	exit 1
fi

confirm || exit 0

xattr -dr com.apple.quarantine "$RES" >/dev/null 2>&1

umask 077
WORK="$(mktemp -d "${TMPDIR:-/tmp}/audspect-uninstall.XXXXXX")" || { dialog "Could not create a private working folder." stop; exit 1; }
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

CMD="/bin/sh $(quote "$SELF") --do-uninstall $(quote "$AGENT") $(quote "$WORK/result")"
OUT="$(osascript -e 'on run argv' \
	-e 'do shell script (item 1 of argv) with administrator privileges with prompt "The Audspect Agent needs administrator access to remove itself."' \
	-e 'end run' "$CMD" 2>&1)"
ORC=$?
if [ "$ORC" -ne 0 ]; then
	case "$OUT" in
	*"User canceled"* | *"(-128)"*) exit 0 ;;
	esac
	dialog "Administrator access was not granted, so nothing was removed." stop
	exit 1
fi

RC="$(cat "$WORK/result" 2>/dev/null)"
if [ "$RC" = "0" ]; then
	dialog "The Audspect Agent and its data were removed from this Mac." note
	exit 0
fi
dialog "The Audspect Agent could not be fully removed (exit code ${RC:-unknown}). Run the uninstaller again; if it keeps failing, contact your administrator." stop
exit 1
