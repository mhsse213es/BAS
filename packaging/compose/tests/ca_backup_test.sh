#!/usr/bin/env bash
# packaging/compose/tests/ca_backup_test.sh
# Exercises ca-backup.sh: the CA private key never appears in a backup in plaintext, and it restores exactly.
set -euo pipefail
# Git Bash on Windows rewrites "/CN=..." arguments as paths; this stops that. No effect on Linux.
export MSYS2_ARG_CONV_EXCL="*"

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TESTDIR="$(mktemp -d)"
if command -v cygpath >/dev/null 2>&1; then TESTDIR="$(cygpath -m "$TESTDIR")"; fi
trap 'rm -rf "$TESTDIR"' EXIT

# shellcheck source=../ca-backup.sh
source "$HERE/ca-backup.sh"

pass=0
fail=0
ok()  { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }

# A wrap key in the shape db-encryption-key.sh issues: base64 of 32 random bytes, one line.
WRAP_KEY="$TESTDIR/db-encryption.key"
openssl rand -base64 32 | tr -d '\n' > "$WRAP_KEY"; echo >> "$WRAP_KEY"
export CA_WRAP_KEY_FILE="$WRAP_KEY"

# A fake pki directory: CA certificate plus a plaintext private key.
make_pki() {
  local dir="$1"
  mkdir -p "$dir"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$dir/ca-key.pem" -out "$dir/ca-cert.pem" -days 30 -subj "/CN=test-ca" >/dev/null 2>&1
  echo "sentinel" > "$dir/ca-fingerprint.txt"
}

# --- stage: no plaintext key in the destination ---
SRC="$TESTDIR/src/pki"
make_pki "$SRC"
DEST="$TESTDIR/dest/pki"
if ca_backup_stage "$SRC" "$DEST" >/dev/null 2>&1; then ok "stage succeeds"; else bad "stage failed"; fi
if [[ ! -e "$DEST/ca-key.pem" ]]; then ok "destination has no plaintext ca-key.pem"; else bad "plaintext ca-key.pem was copied"; fi
if [[ -f "$DEST/ca-key.pem.wrapped" ]]; then ok "wrapped key is written"; else bad "wrapped key missing"; fi
if ! grep -q "PRIVATE KEY" "$DEST/ca-key.pem.wrapped"; then ok "wrapped key holds no PEM header"; else bad "wrapped key is readable PEM"; fi
if [[ -f "$DEST/ca-cert.pem" && -f "$DEST/ca-fingerprint.txt" ]]; then ok "other pki files are copied"; else bad "other pki files missing"; fi
probe="$TESTDIR/mode-probe"; : > "$probe"; chmod 0640 "$probe"
if [[ "$(stat -c %a "$probe")" == "640" ]]; then
  if [[ "$(stat -c %a "$DEST/ca-key.pem.wrapped")" == "600" ]]; then ok "wrapped key is mode 0600"; else bad "wrapped key mode is not 0600"; fi
else
  echo "SKIP: mode bits are not enforced on this filesystem; run on Linux to check 0600"
fi

# --- unwrap restores the exact key ---
RESTORE="$TESTDIR/restore/pki"
mkdir -p "$RESTORE"
cp "$DEST/ca-cert.pem" "$DEST/ca-fingerprint.txt" "$DEST/ca-key.pem.wrapped" "$RESTORE/"
if ca_backup_unwrap "$RESTORE" >/dev/null 2>&1; then ok "unwrap succeeds"; else bad "unwrap failed"; fi
if cmp -s "$SRC/ca-key.pem" "$RESTORE/ca-key.pem"; then ok "restored key is byte-identical"; else bad "restored key differs"; fi
rm -f "$RESTORE/ca-key.pem"

# --- unwrap never overwrites an existing key ---
cp "$SRC/ca-key.pem" "$RESTORE/ca-key.pem"
echo "other" > "$TESTDIR/other.key"
if ca_backup_unwrap "$RESTORE" >/dev/null 2>&1 && cmp -s "$SRC/ca-key.pem" "$RESTORE/ca-key.pem"; then
  ok "unwrap leaves an existing key untouched"
else
  bad "unwrap overwrote an existing key"
fi

# --- wrong wrap key is refused, nothing written ---
WRONG="$TESTDIR/wrong.key"
openssl rand -base64 32 | tr -d '\n' > "$WRONG"; echo >> "$WRONG"
RESTORE2="$TESTDIR/restore2/pki"
mkdir -p "$RESTORE2"
cp "$DEST/ca-key.pem.wrapped" "$RESTORE2/"
if CA_WRAP_KEY_FILE="$WRONG" ca_backup_unwrap "$RESTORE2" >/dev/null 2>&1; then
  bad "unwrap accepted the wrong key"
elif [[ ! -e "$RESTORE2/ca-key.pem" ]]; then
  ok "wrong key is refused and no key is written"
else
  bad "a partial key was written after a failed unwrap"
fi

# --- missing wrap key fails closed at stage time (no plaintext fallback) ---
DEST3="$TESTDIR/dest3/pki"
if CA_WRAP_KEY_FILE="$TESTDIR/absent.key" ca_backup_stage "$SRC" "$DEST3" >/dev/null 2>&1; then
  bad "stage succeeded without a wrap key"
elif [[ ! -e "$DEST3/ca-key.pem" && ! -e "$DEST3/ca-key.pem.wrapped" ]]; then
  ok "missing wrap key fails closed; no key written"
else
  bad "stage left key material after failing"
fi

# --- no CA key yet: nothing to wrap, stage still succeeds ---
EMPTY="$TESTDIR/empty/pki"
mkdir -p "$EMPTY"
echo "x" > "$EMPTY/ca-cert.pem"
DEST4="$TESTDIR/dest4/pki"
if ca_backup_stage "$EMPTY" "$DEST4" >/dev/null 2>&1 && [[ ! -e "$DEST4/ca-key.pem.wrapped" ]]; then
  ok "no CA key yet: stage copies the rest"
else
  bad "stage mishandled a pki with no CA key"
fi

# --- plaintext report finds old backups ---
BK="$TESTDIR/backups"
mkdir -p "$BK/20260101-000000/pki" "$BK/20260201-000000/pki"
cp "$SRC/ca-key.pem" "$BK/20260101-000000/pki/ca-key.pem"
cp "$DEST/ca-key.pem.wrapped" "$BK/20260201-000000/pki/"
report=$(ca_backup_plaintext_report "$BK")
if grep -q "20260101-000000" <<<"$report" && ! grep -q "20260201-000000" <<<"$report"; then
  ok "report lists only backups holding a plaintext CA key"
else
  bad "plaintext report wrong: $report"
fi

# --- the real _package_config (extracted from install.sh): the archive holds the wrapped key, never the plaintext ---
PKG_DATA="$TESTDIR/data"
mkdir -p "$PKG_DATA/pki" "$PKG_DATA/signing" "$PKG_DATA/certs"
cp "$SRC/ca-cert.pem" "$SRC/ca-fingerprint.txt" "$PKG_DATA/pki/"
cp "$SRC/ca-key.pem" "$PKG_DATA/pki/ca-key.pem"
echo "compose" > "$PKG_DATA/docker-compose.yml"; echo "env" > "$PKG_DATA/.env"
sed -n '/^_package_config() {/,/^}/p' "$HERE/install.sh" > "$TESTDIR/package_config.sh"
_resolve_license_file() { :; }
LICENSE_FILE="none.lic"
DATA_DIR="$PKG_DATA"
# shellcheck source=/dev/null
source "$TESTDIR/package_config.sh"
ARCHIVE="config.tar"
(cd "$TESTDIR" && _package_config "$ARCHIVE") && PKG_OK=1 || PKG_OK=0
if [[ "$PKG_OK" == 1 ]]; then ok "_package_config succeeds"; else bad "_package_config failed"; fi
listing=$(cd "$TESTDIR" && tar -tf "$ARCHIVE")
if grep -q "pki/ca-key.pem$" <<<"$listing"; then bad "archive contains the plaintext CA key"; else ok "archive contains no plaintext CA key"; fi
if grep -q "pki/ca-key.pem.wrapped$" <<<"$listing"; then ok "archive contains the wrapped CA key"; else bad "archive has no wrapped CA key"; fi
if grep -q "pki/ca-cert.pem$" <<<"$listing"; then ok "archive keeps the CA certificate"; else bad "CA certificate missing from archive"; fi
EXTRACT="$TESTDIR/extract"; mkdir -p "$EXTRACT"; (cd "$TESTDIR" && tar -xf "$ARCHIVE" -C "$EXTRACT")
if ca_backup_unwrap "$EXTRACT/pki" >/dev/null 2>&1 && cmp -s "$SRC/ca-key.pem" "$EXTRACT/pki/ca-key.pem"; then
  ok "archive restores the identical CA key"
else
  bad "archive does not restore the CA key"
fi
# Missing wrap key: the backup must fail rather than fall back to plaintext.
if (cd "$TESTDIR" && CA_WRAP_KEY_FILE="$TESTDIR/absent.key" _package_config "config2.tar") >/dev/null 2>&1; then
  bad "_package_config succeeded without a wrap key"
else
  ok "_package_config fails closed without a wrap key"
fi

echo "---"
echo "passed: $pass  failed: $fail"
[[ "$fail" -eq 0 ]]
