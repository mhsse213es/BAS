#!/bin/bash
# A stand-in for systemctl (no systemd in a container). State lives in /run/fake-systemd.
S=/run/fake-systemd; mkdir -p "$S"
echo "$*" >> "$S/calls"
cmd="${1:-}"; shift || true
# drop options
args=(); for a in "$@"; do case "$a" in -*) ;; *) args+=("$a") ;; esac; done
case "$cmd" in
  start | enable)
    if [ "$cmd" = "enable" ] && ! printf '%s ' "$@" | grep -q -- '--now'; then exit 0; fi
    echo 0 > "$S/ticks"; echo active > "$S/state"; exit 0 ;;
  stop) echo inactive > "$S/state"; exit 0 ;;
  is-active)
    [ "$(cat "$S/state" 2>/dev/null)" = active ] || exit 3
    # a binary marked as crashing is active for one check, then dies
    if grep -q '^#CRASH=1' /usr/local/bin/bas-agent 2>/dev/null; then
      t=$(cat "$S/ticks" 2>/dev/null || echo 0); echo $((t + 1)) > "$S/ticks"
      [ "$t" -lt 1 ] || { echo inactive > "$S/state"; exit 3; }
    fi
    exit 0 ;;
  cat) [ -f /etc/systemd/system/bas-agent.service ] || exit 1; exit 0 ;;
  *) exit 0 ;;
esac
