#!/usr/bin/env bash
# Tests for uninstall.sh. Runs the real script against stand-ins for docker, systemctl, id and ss, inside a throwaway
# directory tree, so nothing on this machine is touched.   Usage: bash uninstall.test.sh
set -u
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/uninstall.sh"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS  $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/        /'; }
check() { if eval "$2"; then ok "$1"; else bad "$1" "${3:-}"; fi; }

# new_world: builds a fake server. Sets WORLD, DATA, SHIMS, STATE.
new_world() {
  WORLD="$(mktemp -d)"
  DATA="$WORLD/opt/audspect"
  SHIMS="$WORLD/shims"; STATE="$WORLD/state"; UNITS="$WORLD/etc/systemd/system"
  mkdir -p "$DATA"/{pki,signing,data/postgres,backups,logs} "$SHIMS" "$STATE" "$UNITS"
  echo "services:" > "$DATA/docker-compose.yml"
  printf 'BAS_PORT=9443\nBAS_ENROLL_PORT=9445\nBAS_LEGACY_PORT=9005\nAGENT_SECRET=s3cret\n' > "$DATA/.env"
  echo "CA" > "$DATA/pki/ca.pem"; echo "KEY" > "$DATA/signing/key.pem"; echo "16" > "$DATA/data/postgres/PG_VERSION"
  echo "b" > "$DATA/backups/b.tar"
  printf '[Service]\nWorkingDirectory=%s\n' "$DATA" > "$UNITS/audspect.service"
  for u in audspect-backup-worker.service audspect-backup-worker.timer audspect-backup-schedule.service audspect-backup-schedule.timer; do
    echo "[Unit]" > "$UNITS/$u"
  done
  printf 'audspect-orchestrator\naudspect-postgres\naudspect-caldera\naudspect-chrome\nother-app\n' > "$STATE/containers"
  printf 'audspect_postgres_data\nmyapp_postgres\n' > "$STATE/volumes"
  printf 'audspect_bas-internal\nother-net\n' > "$STATE/networks"
  printf 'bas-orchestrator:1.9.5\nunrelated:1\n' > "$STATE/images"
  : > "$STATE/listening"; : > "$STATE/systemctl.log"
  cat > "$SHIMS/id" <<'EOF'
#!/bin/sh
echo "${FAKE_UID:-0}"
EOF
  cat > "$SHIMS/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$STATE/systemctl.log"
exit 0
EOF
  cat > "$SHIMS/ss" <<'EOF'
#!/bin/sh
cat "$STATE/listening"
EOF
  cat > "$SHIMS/docker" <<'EOF'
#!/bin/sh
[ -n "${FAKE_DOCKER_DOWN:-}" ] && exit 1
case "$1" in
  info) exit 0 ;;
  ps) cat "$STATE/containers" ;;
  rm) [ -n "${FAKE_RM_FAIL:-}" ] && exit 1; shift; for a in "$@"; do [ "$a" = "-f" ] && continue; grep -vx "$a" "$STATE/containers" > "$STATE/c.tmp"; mv "$STATE/c.tmp" "$STATE/containers"; done ;;
  inspect)
    # docker inspect -f <template> <container>: the pki mount source of the orchestrator
    if [ "$4" = "audspect-orchestrator" ] || [ "$3" = "audspect-orchestrator" ]; then echo "${FAKE_PKI_SOURCE:-}"; fi ;;
  volume)
    case "$2" in
      ls) cat "$STATE/volumes" ;;
      rm) shift 2; for a in "$@"; do grep -vx "$a" "$STATE/volumes" > "$STATE/v.tmp"; mv "$STATE/v.tmp" "$STATE/volumes"; done ;;
    esac ;;
  network)
    case "$2" in
      ls) cat "$STATE/networks" ;;
      rm) shift 2; for a in "$@"; do grep -vx "$a" "$STATE/networks" > "$STATE/n.tmp"; mv "$STATE/n.tmp" "$STATE/networks"; done ;;
    esac ;;
  compose) [ -n "${FAKE_RM_FAIL:-}" ] && exit 1; : > "$STATE/containers.audspect"; grep -v '^audspect-' "$STATE/containers" > "$STATE/c.tmp"; mv "$STATE/c.tmp" "$STATE/containers"
           grep -v '^audspect_' "$STATE/volumes" > "$STATE/v.tmp"; mv "$STATE/v.tmp" "$STATE/volumes"
           grep -v '^audspect_' "$STATE/networks" > "$STATE/n.tmp"; mv "$STATE/n.tmp" "$STATE/networks" ;;
  images) cat "$STATE/images" ;;
  rmi) shift; for a in "$@"; do [ "$a" = "-f" ] && continue; grep -vx "$a" "$STATE/images" > "$STATE/i.tmp"; mv "$STATE/i.tmp" "$STATE/images"; done ;;
  image) exit 0 ;;
esac
exit 0
EOF
  chmod +x "$SHIMS"/*
}

run() { # run <stdin> <args...>  -> sets OUT, RC
  local input="$1"; shift
  OUT="$(printf '%s' "$input" | PATH="$SHIMS:$PATH" STATE="$STATE" BAS_SYSTEMD_DIR="$UNITS" FAKE_PKI_SOURCE="${FAKE_PKI_SOURCE:-}" \
        FAKE_UID="${FAKE_UID:-0}" FAKE_DOCKER_DOWN="${FAKE_DOCKER_DOWN:-}" FAKE_RM_FAIL="${FAKE_RM_FAIL:-}" \
        bash "$SCRIPT" "$@" 2>&1)"
  RC=$?
}

echo "uninstall.sh"

# 1. a full removal leaves nothing, including the backup timers, and touches nothing that is not BAS
new_world; run "" --yes
check "exit 0 and says it is completely removed" '[ $RC -eq 0 ] && echo "$OUT" | grep -q "completely removed"' "$OUT"
check "install directory is gone (CA, signing key, database, secrets, backups with it)" '[ ! -e "$DATA" ]'
check "the main unit and all four backup units are removed" 'ls "$UNITS" | grep -c . | grep -qx 0' "$(ls "$UNITS")"
check "BAS containers, volumes and network are removed" '! grep -q audspect "$STATE/containers" "$STATE/volumes" "$STATE/networks"'
check "other applications' containers, volumes, networks and images are untouched" 'grep -qx other-app "$STATE/containers" && grep -qx myapp_postgres "$STATE/volumes" && grep -qx other-net "$STATE/networks" && grep -qx unrelated:1 "$STATE/images"'
check "images are kept unless asked" 'grep -qx bas-orchestrator:1.9.5 "$STATE/images"'

# 2. running it again is harmless
run "" --yes
check "a second run says there is nothing to remove and exits 0" '[ $RC -eq 0 ] && echo "$OUT" | grep -qi "nothing to remove"' "$OUT"

# 3. finds a non-default install directory even when the systemd unit is already gone
new_world; CUSTOM="$WORLD/srv/bas-prod"; mv "$DATA" "$WORLD/srv_tmp"; mkdir -p "$WORLD/srv"; mv "$WORLD/srv_tmp" "$CUSTOM"; rm -f "$UNITS/audspect.service"
FAKE_PKI_SOURCE="$CUSTOM/pki" run "" --yes
check "finds the install directory from the running container when the unit is gone" '[ $RC -eq 0 ] && [ ! -e "$CUSTOM" ]' "$OUT"
FAKE_PKI_SOURCE=""

# 4. never deletes a dangerous or unrelated directory
new_world
for d in / /opt /usr /etc /var /home /root "$WORLD" "$WORLD/opt"; do
  run "" --yes --data-dir "$d"
  check "refuses --data-dir $d" '[ $RC -ne 0 ] && [ -e "$DATA/pki/ca.pem" ]' "$OUT"
done
mkdir -p "$WORLD/random"; echo x > "$WORLD/random/file"
run "" --yes --data-dir "$WORLD/random"
check "refuses a directory that does not look like a BAS install" '[ $RC -ne 0 ] && [ -e "$WORLD/random/file" ]' "$OUT"

# 5. needs a deliberate yes
new_world; run ""
check "with no input and no --yes it aborts and deletes nothing" '[ $RC -ne 0 ] && [ -e "$DATA/pki/ca.pem" ] && echo "$OUT" | grep -q -- "--yes"' "$OUT"
run "no
"
check "typing no aborts and deletes nothing" '[ -e "$DATA/pki/ca.pem" ] && echo "$OUT" | grep -qi aborted' "$OUT"
run "yes
"
check "typing yes removes everything" '[ $RC -eq 0 ] && [ ! -e "$DATA" ]' "$OUT"

# 6. dry run
new_world; run "" --dry-run
check "--dry-run removes nothing and says what it would remove" '[ $RC -eq 0 ] && [ -e "$DATA/pki/ca.pem" ] && [ -e "$UNITS/audspect.service" ] && grep -q audspect-postgres "$STATE/containers" && echo "$OUT" | grep -qi "dry run"' "$OUT"

# 7. backup of the irreplaceable parts before removal
new_world; mkdir -p "$WORLD/keep"; run "" --yes --backup-to "$WORLD/keep"
ARCH="$(ls "$WORLD"/keep/audspect-final-backup-*.tar.gz 2>/dev/null | head -1)"
check "--backup-to saves the CA, signing key and .env first" '[ $RC -eq 0 ] && [ -n "$ARCH" ] && tar -tzf "$ARCH" | grep -q pki/ca.pem && tar -tzf "$ARCH" | grep -q signing/key.pem && tar -tzf "$ARCH" | grep -q "\.env" && [ ! -e "$DATA" ]' "$OUT"
probe="$WORLD/modeprobe"; : > "$probe"; chmod 600 "$probe"
if [ "$(stat -c %a "$probe")" = "600" ]; then
  check "the backup is readable only by its owner" '[ -n "$ARCH" ] && [ "$(stat -c %a "$ARCH")" = "600" ]'
else
  echo "  SKIP  the backup is readable only by its owner (this filesystem does not keep file modes)"
fi
new_world; run "" --yes --backup-to "$WORLD/does/not/exist/deeper/file.txt/x"
mkdir -p "$WORLD/blocker"; echo f > "$WORLD/blocker/afile"
run "" --yes --backup-to "$WORLD/blocker/afile"
check "if the backup cannot be written nothing is deleted" '[ $RC -ne 0 ] && [ -e "$DATA/pki/ca.pem" ]' "$OUT"

# 8. docker missing or stopped: the files and units are still removed
new_world; FAKE_DOCKER_DOWN=1 run "" --yes
check "with docker unavailable the directory and units are still removed, with a warning" '[ ! -e "$DATA" ] && [ ! -e "$UNITS/audspect.service" ] && echo "$OUT" | grep -qi docker' "$OUT"
FAKE_DOCKER_DOWN=""

# 9. an unrelated program on a port is a warning, not a failure; a BAS proxy still holding it is a failure
new_world; echo 'LISTEN 0 4096 *:9443 users:(("postgres",pid=7,fd=5))' > "$STATE/listening"; run "" --yes
check "another program using a BAS port is reported but does not fail the uninstall" '[ $RC -eq 0 ] && echo "$OUT" | grep -qi "another program"' "$OUT"

# 10. a container that cannot be removed is reported as an incomplete uninstall
new_world; FAKE_RM_FAIL=1 run "" --yes
check "a failure is reported and exits non-zero" '[ $RC -ne 0 ] && echo "$OUT" | grep -qi incomplete' "$OUT"
FAKE_RM_FAIL=""

# 11. needs root
new_world; FAKE_UID=1000 run "" --yes
check "refuses to run without root" '[ $RC -ne 0 ] && [ -e "$DATA/pki/ca.pem" ]' "$OUT"
FAKE_UID=0

# 11b. run from inside the directory it is about to delete (setup.sh points people at <install dir>/uninstall.sh)
new_world; cp "$SCRIPT" "$DATA/uninstall.sh"
OUT="$(cd "$DATA" && printf '' | PATH="$SHIMS:$PATH" STATE="$STATE" BAS_SYSTEMD_DIR="$UNITS" bash "$DATA/uninstall.sh" --yes 2>&1)"; RC=$?
check "works when run from inside the install directory it removes" '[ $RC -eq 0 ] && [ ! -e "$DATA" ]' "$OUT"

# 12. --purge-images removes BAS images only
new_world; run "" --yes --purge-images
check "--purge-images removes BAS images and nothing else" '! grep -q bas-orchestrator "$STATE/images" && grep -qx unrelated:1 "$STATE/images"' "$(cat "$STATE/images")"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
