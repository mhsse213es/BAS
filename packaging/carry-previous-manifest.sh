#!/bin/sh
# carry-previous-manifest.sh - keep the previous release's hashes in BINARIES.sha256 as "#prev" lines.
#
#   carry-previous-manifest.sh carry  <manifest> <previous>   append the missing hashes, print how many
#   carry-previous-manifest.sh verify <manifest> <previous>   exit 1 unless every previous hash is carried
#
# Why: an agent built before an upgrade still runs its old binary. If the new manifest no longer lists that
# hash, the server quarantines the agent as an unknown binary and only an operator can release it. With the old
# hash listed as "#prev <hash>  <file>", the server marks the agent "outdated" instead and returns it to active
# once it runs a current binary (orchestrator/internal/integrity/trust_state.go, manifest.go).
#
# A hash already present in the manifest, as an entry or as an earlier #prev line, is not repeated. #prev lines
# in <previous> are carried on too, so the chain keeps growing release to release.
#
# GNU sha256sum --check (what setup.sh runs, on Ubuntu) ignores #prev lines; busybox's sha256sum -c does not, so do
# not check this manifest with it.
#
# Run it before the manifest is signed: both signatures cover the whole file. POSIX sh + awk only, so it runs in
# the alpine manifest stage of orchestrator/Dockerfile as well as on a build host.
set -eu

mode="${1:-}"
manifest="${2:-}"
previous="${3:-}"
if [ -z "$mode" ] || [ ! -f "$manifest" ] || [ ! -f "$previous" ]; then
  echo "usage: $0 carry|verify <manifest> <previous>   (both files must exist)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# entries FILE: "<hash>  <file>" for every entry line and every #prev line, hash lowercased, CRs removed.
# Comments, blank lines and anything that is not a 64-hex hash followed by a file name are skipped.
entries() {
  tr -d '\r' < "$1" | awk '
    /^[[:space:]]*$/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (line ~ /^#prev[[:space:]]/) { sub(/^#prev[[:space:]]+/, "", line) }
      else if (line ~ /^#/) { next }
      h = tolower(substr(line, 1, 64))
      rest = substr(line, 65)
      sub(/^[[:space:]]+/, "", rest)
      if (length(h) != 64 || h !~ /^[0-9a-f]+$/ || rest == "") next
      print h "  " rest
    }'
}

# malformed_prev FILE: print every "#prev" line the server could not read as "#prev <64 hex>  <file>".
malformed_prev() {
  tr -d '\r' < "$1" | awk '
    /^#prev/ {
      if (!($1 == "#prev" && NF == 3 && length($2) == 64 && $2 ~ /^[0-9a-f]+$/)) print
    }'
}

entries "$manifest" > "$tmp/current"
entries "$previous" > "$tmp/previous"

# missing: the previous release's entries whose hash is not in the manifest (as an entry or a #prev line).
awk 'NR == FNR { seen[$1] = 1; next } !($1 in seen) { seen[$1] = 1; print $1 "  " $2 }' \
  "$tmp/current" "$tmp/previous" > "$tmp/missing"

case "$mode" in
  carry)
    # A manifest without a trailing newline would have the first #prev line glued onto its last entry.
    if [ -s "$manifest" ] && [ -n "$(tail -c1 "$manifest")" ]; then printf '\n' >> "$manifest"; fi
    awk '{ print "#prev " $1 "  " $2 }' "$tmp/missing" >> "$manifest"
    wc -l < "$tmp/missing" | tr -d ' '
    ;;
  verify)
    bad="$(malformed_prev "$manifest")"
    if [ -n "$bad" ]; then
      echo "BINARIES.sha256 has #prev lines the server cannot read:" >&2
      echo "$bad" >&2
      exit 1
    fi
    if [ -s "$tmp/missing" ]; then
      echo "$(wc -l < "$tmp/missing" | tr -d ' ') hash(es) of the previous release are neither entries nor #prev lines in the manifest:" >&2
      cat "$tmp/missing" >&2
      exit 1
    fi
    echo "ok: every previous-release hash is carried"
    ;;
  *)
    echo "unknown mode: $mode (use carry or verify)" >&2
    exit 2
    ;;
esac
