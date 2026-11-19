#!/bin/sh
# Audspect Agent setup for macOS. This is the program inside "Audspect Agent Setup.app".
# It asks for the agent secret (and, when the server issues them, an enrolment token) and nothing else: the
# server address, the deployment CA and the agent are inside the app, and the signed deployment configuration
# is verified by the agent itself against the fingerprint stored next to it.
#
# Two phases in one file. The first runs as the logged-in user: it checks the app, asks for the secret, checks the
# secret against the server, and then asks macOS for administrator rights. The second (--do-install) runs as root
# through that prompt and installs the agent. The secret travels in a private temporary file read on stdin, never on
# a command line.
set -u

TITLE="Audspect Agent Setup"
SELF="$0"
RES="$(cd "$(dirname "$SELF")/../Resources" 2>/dev/null && pwd)"
AGENT="$RES/bas-agent"
PLIST="${BAS_SETUP_PLIST:-/Library/LaunchDaemons/com.audspect.bas-agent.plist}"

# AppleScript string literal: backslash and double quote are the only characters that need escaping.
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Shell-quote one word for the command the administrator prompt runs.
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

ICON="$RES/AppIcon.icns"

# dialog <message> <fallback icon: stop|note>: an information box with the Audspect icon. If this macOS refuses the custom
# icon, the same box is shown with the standard one, so a cosmetic problem can never hide a message.
dialog() {
	if [ -f "$ICON" ]; then
		osascript -e "display dialog \"$(esc "$1")\" with title \"$TITLE\" buttons {\"OK\"} default button \"OK\" with icon file ((POSIX file \"$(esc "$ICON")\") as text)" >/dev/null 2>&1 && return 0
	fi
	osascript -e "display dialog \"$(esc "$1")\" with title \"$TITLE\" buttons {\"OK\"} default button \"OK\" with icon $2" >/dev/null 2>&1
	return 0
}

# Exit codes of the agent's --preflight and --install, in plain words.
describe() {
	case "$1" in
	20) echo "The agent rejected its inputs as invalid." ;;
	21) echo "The Audspect server could not be reached. Check the network, the firewall and the server address, then try again." ;;
	22) echo "The server rejected the agent secret. Check the secret and try again." ;;
	23) echo "The server's certificate is not trusted by the deployment CA. Nothing was installed." ;;
	24) echo "The deployment CA is invalid. Download a new copy of this app from the dashboard." ;;
	25) echo "The deployment configuration was rejected: it was not signed by this server's key. Do not install; ask an administrator for a new copy." ;;
	26) echo "The server refused the enrollment token (invalid, expired, already used, or issued for a different computer). Ask the administrator for a new token." ;;
	27) echo "The server could not be reached to enroll (this is a connection problem, not a token problem). Check the network, the firewall and the enrollment port." ;;
	28) echo "The server already has an active agent for this computer and will not replace it on the shared secret alone. Ask the administrator to use Force Remove Agent for this computer in the console, or to issue an enrollment token for it, then install again." ;;
	*) echo "The agent installer failed (exit code $1)." ;;
	esac
}

# ask <prompt>: a masked dialog. Prints the answer; returns 1 when the person cancelled.
ask() { # prompt, confirm button label
	_ask() { # extra icon clause
		osascript -e "text returned of (display dialog \"$(esc "$1")\" default answer \"\" with hidden answer with title \"$TITLE\" buttons {\"Cancel\", \"$2\"} default button \"$2\"$3)" 2>"$ASKERR"
	}
	ASKERR="${WORK:-/tmp}/ask.err"
	if [ -f "$ICON" ]; then
		ANS="$(_ask "$1" "$2" " with icon file ((POSIX file \"$(esc "$ICON")\") as text)")"
		RC=$?
		[ "$RC" -eq 0 ] && { printf '%s' "$ANS"; return 0; }
		# cancelling is an answer; anything else is the icon being refused, so ask again without it
		case "$(cat "$ASKERR" 2>/dev/null)" in *"User canceled"* | *"(-128)"*) return 1 ;; esac
	fi
	ANS="$(_ask "$1" "$2" "")" || return 1
	printf '%s' "$ANS"
}

# ---- second phase: runs as root through the administrator prompt ------------------------------------------------
if [ "${1:-}" = "--do-install" ]; then
	SECRETFILE="$2"
	TOKENFILE="${3:-}"
	RESULT="$4"
	FP="$(tr -d ' \r\n' <"$RES/deployment.fingerprint")"
	if [ -n "$TOKENFILE" ]; then
		"$AGENT" --install --config "$RES/deployment.json" --config-fingerprint "$FP" --env Production \
			--enrollment-token-file "$TOKENFILE" --secret-stdin <"$SECRETFILE" >"$RESULT.log" 2>&1
	else
		"$AGENT" --install --config "$RES/deployment.json" --config-fingerprint "$FP" --env Production \
			--secret-stdin <"$SECRETFILE" >"$RESULT.log" 2>&1
	fi
	echo $? >"$RESULT"
	exit 0 # the outcome is reported through the result file; a non-zero exit here would hide it
fi

# ---- root phase: only look at the installed identity; changes nothing ----------------------------------------------
if [ "${1:-}" = "--do-check" ]; then
	FP="$(tr -d ' 
' <"$RES/deployment.fingerprint")"
	"$AGENT" --identity-status --config "$RES/deployment.json" --config-fingerprint "$FP" </dev/null >/dev/null 2>&1
	echo $? >"$2"
	exit 0
fi

# ---- root phase: re-enrol an installed agent whose identity belongs to a different CA ---------------------------------
if [ "${1:-}" = "--do-reset" ]; then
	SECRETFILE="$2"
	TOKENFILE="${3:-}"
	RESULT="$4"
	FP="$(tr -d ' 
' <"$RES/deployment.fingerprint")"
	if [ -n "$TOKENFILE" ]; then
		"$AGENT" --reset-identity --config "$RES/deployment.json" --config-fingerprint "$FP" 			--enrollment-token-file "$TOKENFILE" --secret-stdin <"$SECRETFILE" >"$RESULT.log" 2>&1
	else
		"$AGENT" --reset-identity --config "$RES/deployment.json" --config-fingerprint "$FP" 			--secret-stdin <"$SECRETFILE" >"$RESULT.log" 2>&1
	fi
	RC=$?
	echo $RC >"$RESULT"
	# the running agent still holds the old identity in memory: restart it so it connects with the new one
	if [ "$RC" -eq 0 ]; then launchctl kickstart -k system/com.audspect.bas-agent >/dev/null 2>&1; fi
	exit 0
fi

# ---- first phase: runs as the logged-in user --------------------------------------------------------------------
if [ -z "$RES" ] || [ ! -f "$AGENT" ] || [ ! -f "$RES/deployment.json" ] || [ ! -f "$RES/deployment.fingerprint" ]; then
	dialog "This copy of the setup is incomplete. Download it again from the Audspect dashboard." stop
	exit 1
fi

# The app is for one kind of Mac; running the other kind's agent would fail late and confusingly.
WANT="$(tr -d ' \r\n' <"$RES/arch" 2>/dev/null)"
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then HAVE=arm64; else HAVE="$(uname -m)"; fi
if [ "$WANT" != "$HAVE" ]; then
	if [ "$WANT" = "arm64" ]; then
		dialog "This copy is for Apple silicon Macs, but this Mac has an Intel processor. Download the Intel version from the Audspect dashboard." stop
	else
		dialog "This copy is for Intel Macs, but this Mac has Apple silicon. Download the Apple silicon version from the Audspect dashboard." stop
	fi
	exit 1
fi

# The agent must be exactly what the server packed.
WANTSUM="$(tr -d ' \r\n' <"$RES/agent.sha256" 2>/dev/null)"
HAVESUM="$(shasum -a 256 "$AGENT" 2>/dev/null | awk '{print $1}')"
if [ -z "$WANTSUM" ] || [ "$WANTSUM" != "$HAVESUM" ]; then
	dialog "The agent in this download is damaged or was changed. Do not install it; download it again from the Audspect dashboard." stop
	exit 1
fi

# The one-time Gatekeeper approval was given to this app; the files inside must not be blocked again.
xattr -dr com.apple.quarantine "$RES" >/dev/null 2>&1

umask 077
WORK="$(mktemp -d "${TMPDIR:-/tmp}/audspect-setup.XXXXXX")" || { dialog "Could not create a private working folder." stop; exit 1; }
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

# An agent is already installed. Keep it, unless it was enrolled under a different deployment CA than this app carries:
# such an identity can never connect, so re-enrol it. The identity is readable only by root, hence the prompt.
PHASE="--do-install"
if [ -e "$PLIST" ]; then
	CHK="/bin/sh $(quote "$SELF") --do-check $(quote "$WORK/check")"
	osascript -e 'on run argv' 		-e 'do shell script (item 1 of argv) with administrator privileges with prompt "The Audspect Agent needs administrator access to check the agent already installed on this Mac."' 		-e 'end run' "$CHK" >/dev/null 2>&1
	if [ "$(cat "$WORK/check" 2>/dev/null)" = "29" ]; then
		PHASE="--do-reset"
		dialog "The Audspect Agent on this Mac was set up for a different Audspect server certificate and cannot connect. This setup will enroll it again." note
	else
		dialog "The Audspect Agent is already installed on this Mac. Nothing was changed." note
		exit 0
	fi
fi

SECRET="$(ask "Enter the agent secret provided by your administrator. It is checked with your Audspect server and is never shown or stored in a command." "Install")" || exit 0
if [ -z "$SECRET" ]; then
	dialog "The agent secret is required." stop
	exit 1
fi
printf '%s\n' "$SECRET" >"$WORK/secret"
SECRET=""

TOKENFILE=""
if [ -f "$RES/enrollment-token.required" ]; then
	TOKEN="$(ask "Enter the enrollment token for this Mac. Each token works once, for one computer." "Continue")" || exit 0
	if [ -z "$TOKEN" ]; then
		dialog "The enrollment token is required." stop
		exit 1
	fi
	printf '%s\n' "$TOKEN" >"$WORK/token"
	TOKEN=""
	TOKENFILE="$WORK/token"
fi

FP="$(tr -d ' \r\n' <"$RES/deployment.fingerprint")"

# Check the server and the secret before asking for the administrator password.
"$AGENT" --preflight --config "$RES/deployment.json" --config-fingerprint "$FP" --secret-stdin <"$WORK/secret" >"$WORK/preflight.log" 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
	dialog "$(describe "$RC")" stop
	exit 1
fi

CMD="/bin/sh $(quote "$SELF") $PHASE $(quote "$WORK/secret") $(quote "$TOKENFILE") $(quote "$WORK/result")"
OUT="$(osascript -e 'on run argv' \
	-e 'do shell script (item 1 of argv) with administrator privileges with prompt "The Audspect Agent needs administrator access to install."' \
	-e 'end run' "$CMD" 2>&1)"
ORC=$?
if [ "$ORC" -ne 0 ]; then
	case "$OUT" in
	*"User canceled"* | *"(-128)"*) exit 0 ;;
	esac
	dialog "Administrator access was not granted, so nothing was installed." stop
	exit 1
fi

RC="$(cat "$WORK/result" 2>/dev/null)"
if [ "$RC" = "0" ]; then
	if [ "$PHASE" = "--do-reset" ]; then
		dialog "The Audspect Agent was enrolled again and restarted. It will reconnect within about a minute." note
	else
		dialog "The Audspect Agent is installed and running. It will appear in the dashboard within about a minute." note
	fi
	exit 0
fi
dialog "$(describe "${RC:-1}")" stop
exit 1
