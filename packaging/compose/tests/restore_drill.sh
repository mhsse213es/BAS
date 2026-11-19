#!/usr/bin/env bash
# packaging/compose/tests/restore_drill.sh
# Restore drill (REQ-039 P0.3/P0.4): populated source host -> backup -> total loss -> clean host restore -> verification.
# Run inside a Linux container with the packaging tree mounted, for example:
#   docker run --rm -v "$PWD/packaging:/src:ro" -v "$PWD/packaging/compose/tests:/script:ro" postgres:16 \
#     (in the container: copy /src to /w, strip CRLF from the .sh files, then run: bash /script/restore_drill.sh)
# Restore drill: populated source host -> backup -> total loss -> clean host restore -> verification.
# Runs inside a Linux container (postgres:16 image). Uses the installer's own helpers, extracted from install.sh.
set -uo pipefail
export MSYS2_ARG_CONV_EXCL="*"
PKG="${PKG:-/w/compose}"
ROOT=/drill
PGBIN=/usr/lib/postgresql/16/bin
PGUSER_OS=postgres
PGPW=drillpw-not-a-secret-1234
RESULTS=$ROOT/results.txt
# results file created after ROOT exists
pass=0; fail=0
ok()  { echo "PASS  $1" | tee -a "$RESULTS"; pass=$((pass+1)); }
bad() { echo "FAIL  $1" | tee -a "$RESULTS"; fail=$((fail+1)); }
step(){ echo; echo "=== $1" | tee -a "$RESULTS"; }

rm -rf "$ROOT"; mkdir -p "$ROOT"
: > "$RESULTS"
chmod 755 "$ROOT"
PGID=$(id -u $PGUSER_OS); PGGID=$(id -g $PGUSER_OS)

# ── Source helpers from the real packaging files ──────────────────────────────
source "$PKG/db-tls.sh"
source "$PKG/ca-backup.sh"
source "$PKG/backup-key.sh"
sed -n '/^_package_config() {/,/^}/p' "$PKG/install.sh" > "$ROOT/package_config.sh"
source "$ROOT/package_config.sh"
_resolve_license_file() { :; }
LICENSE_FILE="none.lic"

pg_cmd() { runuser -u $PGUSER_OS -- "$@"; }
psql_at() { PGPASSWORD=$PGPW pg_cmd env PGPASSWORD=$PGPW "$PGBIN/psql" -h localhost -p "$1" -U postgres -tAq "${@:2}"; }

start_pg() { # name port datadir tlsdir
  local name=$1 port=$2 data=$3 tls=$4
  mkdir -p "$ROOT/$name-sock" "$(dirname "$data")"; chown $PGUSER_OS "$ROOT/$name-sock" "$(dirname "$data")"
  touch "$ROOT/$name.log"; chown $PGUSER_OS "$ROOT/$name.log"
  if [[ ! -d "$data" ]]; then
    echo "$PGPW" > "$ROOT/$name.pw"; chmod 644 "$ROOT/$name.pw"
    pg_cmd "$PGBIN/initdb" -D "$data" -U postgres --pwfile="$ROOT/$name.pw" >/dev/null 2>&1 || return 1
  fi
  pg_cmd "$PGBIN/pg_ctl" -D "$data" -l "$ROOT/$name.log" -w -o "-p $port -k $ROOT/$name-sock -c listen_addresses=localhost -c ssl=on -c ssl_cert_file=$tls/server.crt -c ssl_key_file=$tls/server.key" start >/dev/null 2>&1
}
stop_pg() { pg_cmd "$PGBIN/pg_ctl" -D "$1" -m fast -w stop >/dev/null 2>&1 || true; }

# ═════════ 1. SOURCE HOST: populated ═════════
step "1. Populate the source host"
SRC=$ROOT/src
DATA=$SRC/data; SECRETS=$SRC/secrets; OFFHOST=$ROOT/offhost
mkdir -p "$DATA/pki" "$DATA/certs" "$DATA/signing" "$SECRETS" "$OFFHOST" "$ROOT/backups"
export DATA_DIR=$DATA
export BACKUP_KEY_FILE=$SECRETS/backup-encryption.key
export BACKUP_KEY_LEGACY=$DATA/.backup_key
export BACKUP_KEY_MARKER=$DATA/.backup-key-recovery-verified
export CA_WRAP_KEY_FILE=$SECRETS/db-encryption.key
export DB_TLS_DIR=$DATA/dbtls DB_TLS_KEY_UID=$PGID DB_TLS_KEY_GID=$PGGID

DB_KEY_DIR=$SECRETS DB_KEY_UID=$(id -u) DB_KEY_GID=$(id -g)
source "$PKG/db-encryption-key.sh"
db_key_provision fresh >/dev/null 2>&1 && ok "source: database encryption key provisioned" || bad "db key provision"
sha256sum "$SECRETS/db-encryption.key" | cut -d" " -f1 > "$ROOT/dbkey.sha"
BAS_DB_KEY_PASSPHRASE="drill-passphrase-long-enough" db_key_export "$OFFHOST/db-key-recovery.enc" >/dev/null 2>&1 && ok "source: database key recovery copy written" || bad "db key export"

db_tls_ensure >/dev/null && ok "source: database TLS material created" || bad "source TLS"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$DATA/pki/ca-key.pem" \
  -out "$DATA/pki/ca-cert.pem" -days 3650 -subj "/CN=drill-ca" >/dev/null 2>&1
sha256sum "$DATA/pki/ca-key.pem" | cut -d' ' -f1 > "$ROOT/ca-key.sha"
sha256sum "$DATA/pki/ca-cert.pem" | cut -d' ' -f1 > "$ROOT/ca-cert.sha"
echo "fingerprint-marker" > "$DATA/pki/ca-fingerprint.txt"
echo "COMPOSE-SOURCE" > "$DATA/docker-compose.yml"
printf 'DB_PASSWORD=source-db\nJWT_SECRET=source-jwt\n' > "$DATA/.env"
echo "cert" > "$DATA/certs/bas.crt"; echo "key" > "$DATA/certs/bas.key"
echo "signing" > "$DATA/signing/x"
echo "legacy-co-located-key-material" > "$DATA/.backup_key"   # simulates a pre-change install's exposed file
chmod 600 "$DATA/.backup_key"

PGSRC=$ROOT/pg-src
start_pg srcpg 5501 "$PGSRC" "$DATA/dbtls" && ok "source: TLS PostgreSQL started" || bad "source: PostgreSQL did not start"
psql_at 5501 -d postgres -c "CREATE DATABASE drill" >/dev/null
psql_at 5501 -d drill -c "CREATE TABLE customers(id int primary key, name text, card_token text);
  INSERT INTO customers SELECT g, 'customer-'||g, md5(g::text) FROM generate_series(1,1000) g;" >/dev/null
SRC_SUM=$(psql_at 5501 -d drill -c "SELECT count(*)||':'||md5(string_agg(name||card_token, '' ORDER BY id)) FROM customers")
echo "source checksum: $SRC_SUM" | tee -a "$RESULTS"
psql_at 5501 -d postgres -c "SHOW ssl" | grep -q on && ok "source: database serves TLS" || bad "source TLS off"

# ═════════ 2. BACKUP (gate, then archive) ═════════
step "2. Backup with the installer's logic"
export BAS_BACKUP_KEY_RECOVERY_PATH=$OFFHOST/backup-key-recovery.enc
export BAS_BACKUP_KEY_PASSPHRASE="drill-passphrase-long-enough"
backup_key_provision && ok "backup key provisioned outside DATA_DIR" || bad "provision"
backup_key_recovery_confirm >/dev/null 2>&1 && ok "gate: verified recovery copy written off-host" || bad "gate"
[[ -f "$BACKUP_KEY_MARKER" ]] && ok "gate: confirmation marker recorded" || bad "marker"
sha256sum "$BACKUP_KEY_FILE" | cut -d' ' -f1 > "$ROOT/backup-key.sha"

BK=$ROOT/bk; mkdir -p "$BK"
_package_config "$BK/config.tar" && ok "config archive built (pki staged)" || bad "_package_config"
tar -tf "$BK/config.tar" | grep -q "pki/ca-key.pem$" && bad "archive contains plaintext CA key" || ok "archive has no plaintext CA key"
tar -tf "$BK/config.tar" | grep -q "pki/ca-key.pem.wrapped$" && ok "archive has the wrapped CA key" || bad "no wrapped CA key"
tar -tf "$BK/config.tar" | grep -q "\.backup_key" && bad "archive contains the legacy co-located key" || ok "archive excludes the legacy co-located key"
runuser -u $PGUSER_OS -- env PGPASSWORD=$PGPW "$PGBIN/pg_dump" -Fc -h localhost -p 5501 -U postgres drill > "$BK/drill.dump" \
  && ok "database dumped" || bad "pg_dump"
printf '{"basVersion":"drill-1.0"}\n' > "$BK/manifest.json"
tar -cf "$ROOT/archive.tar" -C "$BK" config.tar drill.dump manifest.json
backup_key_encrypt "$ROOT/archive.tar" "$ROOT/backups/audspect-backup-drill.tar.enc" && ok "archive encrypted with the new key" || bad "encrypt"
sha256sum "$ROOT/backups/audspect-backup-drill.tar.enc" | cut -d' ' -f1 > "$ROOT/backups/audspect-backup-drill.tar.enc.sha"
ARCH=$ROOT/backups/audspect-backup-drill.tar.enc
# the co-located legacy key must NOT open the new archive
if BACKUP_KEY_FILE=$ROOT/none.key BACKUP_KEY_LEGACY=$DATA/.backup_key backup_key_decrypt "$ARCH" "$ROOT/leak.tar" >/dev/null 2>&1; then
  bad "legacy co-located key opened the new archive"
else
  ok "legacy co-located key cannot open the new archive"
fi

# ═════════ 3. TOTAL LOSS ═════════
step "3. Total loss of the source host"
psql_at 5501 -d postgres -c "DROP DATABASE drill" >/dev/null && ok "source: database dropped" || bad "drop"
stop_pg "$PGSRC"
rm -rf "$DATA" "$SECRETS" "$PGSRC" && ok "source: data directory, secrets and database files destroyed" || bad "destroy"
[[ ! -e "$BACKUP_KEY_FILE" ]] && ok "source: backup key is gone from the host" || bad "key survived"

# ═════════ 4. CLEAN HOST RESTORE ═════════
step "4. Restore onto a clean host (fresh install, no key)"
CLEAN=$ROOT/clean
CDATA=$CLEAN/data; CSEC=$CLEAN/secrets
mkdir -p "$CDATA/pki" "$CSEC"
export DATA_DIR=$CDATA
export BACKUP_KEY_FILE=$CSEC/backup-encryption.key
DB_KEY_DIR=$CSEC; DB_KEY_UID=$(id -u); DB_KEY_GID=$(id -g)
source "$PKG/db-encryption-key.sh"
export BACKUP_KEY_LEGACY=$CDATA/.backup_key
export BACKUP_KEY_MARKER=$CDATA/.backup-key-recovery-verified
export DB_TLS_DIR=$CDATA/dbtls
# A fresh install has the DB encryption key too; the wrapped CA key needs it. Restored from its own recovery copy in
# production; here it is the same file for the drill's purposes, supplied as the fresh host's key.
export CA_WRAP_KEY_FILE=$CSEC/db-encryption.key
PGCLEAN=$ROOT/pg-clean
db_tls_ensure >/dev/null && ok "clean: fresh database TLS created" || bad "clean TLS"
db_key_provision fresh >/dev/null 2>&1 && ok "clean: fresh install generated its own database key" || bad "clean db key"
start_pg cleanpg 5502 "$PGCLEAN" "$CDATA/dbtls" && ok "clean: TLS PostgreSQL started (empty)" || bad "clean pg"

# 4a. negatives first: nothing may change
if backup_key_decrypt "$ARCH" "$ROOT/neg.tar" >/dev/null 2>&1; then bad "clean host opened the archive with no key"; else ok "no key: archive does not open"; fi
if backup_key_import "$OFFHOST/does-not-exist.enc" >/dev/null 2>&1; then bad "import accepted a missing recovery copy"; else ok "missing recovery copy: import refused"; fi
if BAS_BACKUP_KEY_PASSPHRASE="wrong-passphrase-value-1" backup_key_import "$OFFHOST/backup-key-recovery.enc" >/dev/null 2>&1; then
  bad "wrong passphrase imported a key"
else
  ok "wrong passphrase: import refused"
fi
[[ ! -e "$BACKUP_KEY_FILE" ]] && ok "failed imports wrote no key" || bad "a key was written by a failed import"
dbs=$(psql_at 5502 -d postgres -c "SELECT count(*) FROM pg_database WHERE datname='drill'")
[[ "$dbs" == "0" ]] && ok "failed imports left the clean database untouched" || bad "clean database changed"

# 4b. the real restore: import, decrypt, pre-check, install
rm -f "$CSEC/db-encryption.key"
BAS_DB_KEY_PASSPHRASE="drill-passphrase-long-enough" db_key_import "$OFFHOST/db-key-recovery.enc" >/dev/null 2>&1 && ok "import: original database key restored from its recovery copy" || bad "db key import"
[[ "$(sha256sum "$CSEC/db-encryption.key" | cut -d" " -f1)" == "$(cat "$ROOT/dbkey.sha")" ]] && ok "import: restored database key identical to the source" || bad "db key differs"
export BAS_BACKUP_KEY_PASSPHRASE="drill-passphrase-long-enough"
backup_key_import "$OFFHOST/backup-key-recovery.enc" >/dev/null && ok "import: key restored from the recovery copy" || bad "import"
[[ "$(sha256sum "$BACKUP_KEY_FILE" | cut -d' ' -f1)" == "$(cat "$ROOT/backup-key.sha")" ]] && ok "import: restored key is byte-identical to the original" || bad "key differs"
[[ "$(stat -c %a "$BACKUP_KEY_FILE")" == "600" ]] && ok "import: restored key mode 0600" || bad "mode"
backup_key_decrypt "$ARCH" "$ROOT/restore/archive.tar" 2>/dev/null || { mkdir -p "$ROOT/restore"; backup_key_decrypt "$ARCH" "$ROOT/restore/archive.tar"; } && ok "archive decrypts on the clean host" || bad "decrypt"
R=$ROOT/restore; mkdir -p "$R/cfg" "$R/pkicheck"
tar -xf "$R/archive.tar" -C "$R"
tar -xf "$R/config.tar" -C "$R/cfg" && ok "config extracted" || bad "config extract"
rm -rf "$R/pkicheck2"; mkdir -p "$R/pkicheck2"; cp "$R/cfg/pki/ca-key.pem.wrapped" "$R/pkicheck2/"
openssl rand -base64 32 > "$ROOT/fresh-db.key"; if CA_WRAP_KEY_FILE="$ROOT/fresh-db.key" ca_backup_unwrap "$R/pkicheck2" >/dev/null 2>&1; then bad "a freshly generated database key opened the archived CA key"; else ok "fresh database key cannot open the archived CA key (pre-check refuses)"; fi
[[ ! -e "$R/pkicheck2/ca-key.pem" ]] && ok "refused unwrap left no key" || bad "partial key written"
[[ -f "$R/cfg/pki/ca-key.pem.wrapped" ]] && cp "$R/cfg/pki/ca-key.pem.wrapped" "$R/pkicheck/" && ca_backup_unwrap "$R/pkicheck" \
  && ok "pre-check: archived CA key unwraps before any database change" || bad "CA pre-check"
# 4c. corrupted wrapped CA key must stop the restore before the database is touched
cp -r "$R/cfg" "$R/cfg-bad"; printf 'X' | dd of="$R/cfg-bad/pki/ca-key.pem.wrapped" bs=1 seek=40 conv=notrunc 2>/dev/null
mkdir -p "$R/badcheck"; cp "$R/cfg-bad/pki/ca-key.pem.wrapped" "$R/badcheck/"
if ca_backup_unwrap "$R/badcheck" >/dev/null 2>&1; then bad "corrupted CA key was accepted"; else ok "corrupted wrapped CA key refused by the pre-check"; fi
[[ ! -e "$R/badcheck/ca-key.pem" ]] && ok "corrupted key left no partial CA key" || bad "partial key written"

# 4d. database restore, as the installer does it
runuser -u $PGUSER_OS -- env PGPASSWORD=$PGPW "$PGBIN/createdb" -h localhost -p 5502 -U postgres drill && \
runuser -u $PGUSER_OS -- env PGPASSWORD=$PGPW "$PGBIN/pg_restore" -h localhost -p 5502 -U postgres -d drill --clean --if-exists "$R/drill.dump" 2>/dev/null
RST_SUM=$(psql_at 5502 -d drill -c "SELECT count(*)||':'||md5(string_agg(name||card_token, '' ORDER BY id)) FROM customers" 2>/dev/null)
echo "restored checksum: $RST_SUM" | tee -a "$RESULTS"
[[ -n "$RST_SUM" && "$RST_SUM" == "$SRC_SUM" ]] && ok "database: 1000 rows restored, checksum matches the source" || bad "database checksum mismatch ($RST_SUM vs $SRC_SUM)"
psql_at 5502 -d postgres -c "SHOW ssl" | grep -q on && ok "database: restored instance serves TLS" || bad "TLS"

# 4e. CA: live key installed from the archive, identical to the source
mkdir -p "$CDATA/pki"; cp -a "$R/cfg/pki/." "$CDATA/pki/"
ca_backup_unwrap "$CDATA/pki" && ok "CA: live key installed from the archive" || bad "CA install"
[[ "$(sha256sum "$CDATA/pki/ca-key.pem" | cut -d' ' -f1)" == "$(cat "$ROOT/ca-key.sha")" ]] && ok "CA: restored key identical to the source CA key" || bad "CA key differs"
[[ "$(sha256sum "$CDATA/pki/ca-cert.pem" | cut -d' ' -f1)" == "$(cat "$ROOT/ca-cert.sha")" ]] && ok "CA: certificate identical" || bad "CA cert differs"

# 4f. legacy co-located key is not copied to the clean host
[[ ! -e "$CDATA/.backup_key" ]] && ok "clean host: no legacy co-located key" || bad "legacy key present"

stop_pg "$PGCLEAN"
echo
echo "RESULT: passed=$pass failed=$fail" | tee -a "$RESULTS"
[[ $fail -eq 0 ]]
