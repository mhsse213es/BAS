#!/usr/bin/env bash
# Offline Docker prerequisites (docker-offline-lib.sh): the pin file and the library agree, the bundle's files are
# SHA-256 verified before use (a tampered file is refused), and CPU mapping / bundle detection behave.
# Runs the real library functions against a temporary fake bundle. Usage: bash offline_prereqs_test.sh
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib="${here}/../docker-offline-lib.sh"
pin="${here}/../../docker-static.pin"
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }

pinval() { grep -E "^$1=" "$pin" | head -1 | cut -d= -f2; }
libval() { grep -oE "readonly $1=\"[^\"]+\"" "$lib" | head -1 | cut -d'"' -f2; }

# 1. pin file == library constants (the build verifies against the pin, the installer against the library)
for pair in "DOCKER_VERSION:DOCKER_STATIC_VERSION" "COMPOSE_VERSION:COMPOSE_STATIC_VERSION" \
            "DOCKER_SHA256_X86_64:DOCKER_SHA256_X86_64" "DOCKER_SHA256_AARCH64:DOCKER_SHA256_AARCH64" \
            "COMPOSE_SHA256_X86_64:COMPOSE_SHA256_X86_64" "COMPOSE_SHA256_AARCH64:COMPOSE_SHA256_AARCH64"; do
  p="${pair%%:*}"; l="${pair##*:}"
  a="$(pinval "$p")"; b="$(libval "$l")"
  if [[ -n "$a" && "$a" == "$b" ]]; then pass "pin $p matches library $l"; else fail "pin $p ('$a') != library $l ('$b')"; fi
done

# A writable copy of the library (its constants are readonly) with test hashes for a fake bundle.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tools/docker"
arch="$(uname -m)"; case "$arch" in x86_64) a=x86_64 ;; aarch64|arm64) a=aarch64 ;; *) a="" ;; esac
if [[ -z "$a" ]]; then echo "SKIP  unsupported test CPU $arch"; exit 0; fi
ver="$(libval DOCKER_STATIC_VERSION)"
printf 'fake docker archive\n' > "$tmp/tools/docker/docker-${ver}-${a}.tgz"
printf 'fake compose\n'        > "$tmp/tools/docker/docker-compose-linux-${a}"
dsha="$(sha256sum "$tmp/tools/docker/docker-${ver}-${a}.tgz" | cut -d' ' -f1)"
csha="$(sha256sum "$tmp/tools/docker/docker-compose-linux-${a}" | cut -d' ' -f1)"
sed -e 's/^readonly //' \
    -e "s/^DOCKER_SHA256_${a^^}=.*/DOCKER_SHA256_${a^^}=\"${dsha}\"/" \
    -e "s/^COMPOSE_SHA256_${a^^}=.*/COMPOSE_SHA256_${a^^}=\"${csha}\"/" "$lib" > "$tmp/lib.sh"

run() { ( SCRIPT_DIR="$tmp"; err() { echo "ERR: $*"; }; . "$tmp/lib.sh"; "$@" ) 2>&1; }

out="$(run _verify_bundled docker)"
[[ "$out" == "$tmp/tools/docker/docker-${ver}-${a}.tgz" ]] && pass "matching Docker archive verifies" || fail "Docker verify: $out"
out="$(run _verify_bundled compose)"
[[ "$out" == "$tmp/tools/docker/docker-compose-linux-${a}" ]] && pass "matching Compose binary verifies" || fail "Compose verify: $out"

printf 'tampered\n' >> "$tmp/tools/docker/docker-compose-linux-${a}"
out="$(run _verify_bundled compose)"; rc=$?
if grep -q "does not match the SHA-256 pinned" <<<"$out" && ! grep -q "^$tmp" <<<"$out"; then pass "tampered Compose binary is refused"; else fail "tampered file accepted: $out"; fi

rm -f "$tmp/tools/docker/docker-compose-linux-${a}"
out="$(run _verify_bundled compose)"
grep -q "release bundle is incomplete" <<<"$out" && pass "missing file reports an incomplete bundle" || fail "missing file: $out"

run _bundled_has docker >/dev/null && pass "_bundled_has sees the Docker archive" || fail "_bundled_has docker"
run _bundled_has compose >/dev/null && fail "_bundled_has compose true with file removed" || pass "_bundled_has is false when the file is absent"

# 2. real build inputs, when present, match the pin (catches a stale packaging/tools/docker)
real="${here}/../../tools/docker"
if [[ -d "$real" ]]; then
  for f in "docker-${ver}-x86_64.tgz:DOCKER_SHA256_X86_64" "docker-${ver}-aarch64.tgz:DOCKER_SHA256_AARCH64" \
           "docker-compose-linux-x86_64:COMPOSE_SHA256_X86_64" "docker-compose-linux-aarch64:COMPOSE_SHA256_AARCH64"; do
    [[ -f "$real/${f%%:*}" ]] || { echo "SKIP  ${f%%:*} not downloaded"; continue; }
    got="$(sha256sum "$real/${f%%:*}" | cut -d' ' -f1)"
    [[ "$got" == "$(libval "${f##*:}")" ]] && pass "packaging/tools/docker/${f%%:*} matches the pin" || fail "packaging/tools/docker/${f%%:*} differs from the pin"
  done
fi

echo; [[ $fails -eq 0 ]] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
