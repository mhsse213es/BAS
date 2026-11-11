#!/usr/bin/env bash
# packaging/compose/db-tls.sh
#
# Database server TLS material (P0.1). The orchestrator connects with sslmode=verify-full and sslrootcert pointing at this
# certificate, so the connection verifies both the chain and the hostname. The PostgreSQL container serves the same pair.
#
# Layout on a Linux host (DATA_DIR/dbtls, bind-mounted read-only into the postgres and orchestrator containers):
#   dbtls/server.key   0600, owned by the postgres user in the image (UID 70). Never copied into backups.
#   dbtls/server.crt   0644, self-signed leaf with SAN DNS:postgres and DNS:localhost. Also the client's trust anchor.
#
# The certificate is a pinned self-signed leaf rather than a CA chain: no second CA key is created, so there is one more
# private key to protect rather than two. It is regenerable, so it is excluded from upgrade backups. Losing it costs one
# regeneration (db_tls_ensure), not data.
#
# This file is sourced by install.sh. Functions return non-zero on failure and print a reason. No function prints a key.

DB_TLS_DIR="${DB_TLS_DIR:-}"
# Git Bash on Windows rewrites "/CN=..." arguments as paths; this stops that. No effect on Linux.
export MSYS2_ARG_CONV_EXCL="*"
DB_TLS_KEY_UID="${DB_TLS_KEY_UID:-70}"
DB_TLS_KEY_GID="${DB_TLS_KEY_GID:-70}"
DB_TLS_SAN="${DB_TLS_SAN:-DNS:postgres,DNS:localhost}"
DB_TLS_DAYS="${DB_TLS_DAYS:-3650}"

_dbtls_err() { echo "ERROR: $*" >&2; }

# _dbtls_key_crt_match KEY CRT: the certificate's public key is the key's public key.
_dbtls_key_crt_match() {
  local a b
  a=$(openssl x509 -in "$2" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null) || return 1
  b=$(openssl pkey -in "$1" -pubout 2>/dev/null | openssl sha256 2>/dev/null) || return 1
  [[ -n "$a" && "$a" == "$b" ]]
}

# db_tls_ensure: create the server pair if absent; verify it if present. An existing pair that does not verify is never
# overwritten silently. The operator is told why and what to do.
db_tls_ensure() {
  local dir="${DB_TLS_DIR:?DB_TLS_DIR must be set}"
  local key="${dir}/server.key" crt="${dir}/server.crt"

  if [[ -e "$key" && -e "$crt" ]]; then
    if ! openssl pkey -in "$key" -noout 2>/dev/null; then
      _dbtls_err "existing database TLS key ${key} is not a valid private key; not overwritten. Move it aside and rerun."
      return 1
    fi
    if ! openssl x509 -in "$crt" -noout 2>/dev/null; then
      _dbtls_err "existing database TLS certificate ${crt} is not valid; not overwritten. Move it aside and rerun."
      return 1
    fi
    if ! _dbtls_key_crt_match "$key" "$crt"; then
      _dbtls_err "database TLS key and certificate do not match; not overwritten. Move ${dir} aside and rerun."
      return 1
    fi
    if ! openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1; then
      _dbtls_err "database TLS certificate has expired; regenerate it by moving ${dir} aside and rerunning."
      return 1
    fi
    _dbtls_info_ok "database TLS material present and verified"
  elif [[ -e "$key" || -e "$crt" ]]; then
    _dbtls_err "database TLS material is incomplete (${dir} holds only one of server.key and server.crt); not overwritten."
    return 1
  else
    mkdir -p "$dir" || { _dbtls_err "cannot create ${dir}"; return 1; }
    if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$key" -out "$crt" -days "$DB_TLS_DAYS" \
        -subj "/CN=audspect-postgres" -addext "subjectAltName=${DB_TLS_SAN}" -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1; then
      _dbtls_err "could not generate the database TLS certificate (openssl req failed)"
      rm -f "$key" "$crt"
      return 1
    fi
    echo "generated database TLS certificate (SAN ${DB_TLS_SAN}, ${DB_TLS_DAYS} days)"
  fi

  chmod 0600 "$key" && chmod 0644 "$crt" || { _dbtls_err "could not set modes on the database TLS files"; return 1; }
  if [[ "$(id -u)" == "0" ]]; then
    chown "${DB_TLS_KEY_UID}:${DB_TLS_KEY_GID}" "$key" || { _dbtls_err "could not set owner on ${key}"; return 1; }
  fi
  return 0
}

_dbtls_info_ok() { echo "$*"; }
