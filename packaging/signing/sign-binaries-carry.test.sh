#!/usr/bin/env bash
# packaging/signing/sign-binaries-carry.test.sh
#
# Proves sign-binaries.sh (the Linux build path, called from packaging/build.sh) keeps the previous release's hashes
# in BINARIES.sha256 as "#prev" lines before the manifest is signed, and fails closed when BAS_PREVIOUS_MANIFEST is
# set but unusable. gpg is a stub on PATH (no key needed): it accepts any key and writes a dummy signature, so this
# checks the manifest, not the signing. The scripts are copied into a temp tree, so nothing in the repo is touched.
# Run: bash packaging/signing/sign-binaries-carry.test.sh
set -euo pipefail
unset CDPATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

fails=0
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; fails=$((fails + 1)); }
h() { printf '%064d' "$1"; }

# temp copy of the tree layout the scripts expect: <root>/signing/sign-binaries.sh and <root>/carry-previous-manifest.sh
mkdir -p "$T/pkg/signing" "$T/bin" "$T/stub"
cp "$HERE/sign-binaries.sh" "$T/pkg/signing/"
cp "$HERE/../carry-previous-manifest.sh" "$T/pkg/"
echo "stub pubkey" > "$T/pkg/signing/pubkey.asc"
cat > "$T/stub/gpg" <<'EOF'
#!/bin/sh
# stub: --list-secret-keys succeeds; --detach-sign writes a dummy signature to the --output path.
out=""; while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift;; esac; shift; done
[ -n "$out" ] && echo "stub signature" > "$out"
exit 0
EOF
chmod +x "$T/stub/gpg"
export PATH="$T/stub:$PATH"

run() { ( cd "$T" && bash "$T/pkg/signing/sign-binaries.sh" "$T/bin" ) 2>&1; }
fresh_bin() { rm -rf "$T/bin"; mkdir "$T/bin"; printf 'linux' > "$T/bin/bas-agent-linux-amd64"; printf 'mac' > "$T/bin/bas-agent-darwin-arm64"; }

printf '%s  bas-agent-linux-amd64\n%s  bas-agent-darwin-arm64\n' "$(h 1)" "$(h 2)" > "$T/previous.sha256"

echo "with a previous manifest"
fresh_bin
out="$(BAS_PREVIOUS_MANIFEST="$T/previous.sha256" run)"
M="$T/bin/BINARIES.sha256"
[ "$(grep -c '^#prev ' "$M")" = "2" ] && pass "both previous hashes are carried as #prev lines" || fail "#prev lines: $(grep -c '^#prev ' "$M")"
grep -qx "#prev $(h 2)  bas-agent-darwin-arm64" "$M" && pass "the Mac hash is carried" || fail "Mac #prev line missing"
grep -qx "#prev $(h 1)  bas-agent-linux-amd64" "$M" && pass "the Linux hash is carried" || fail "Linux #prev line missing"
echo "$out" | grep -q "carried 2 previous-release hash" && pass "the build log says how many were carried" || fail "no log line"
[ -f "$M.asc" ] && pass "the manifest is still signed after carrying" || fail "manifest not signed"
( cd "$T/bin" && sha256sum --check --strict --quiet BINARIES.sha256 ) >/dev/null 2>&1 && pass "sha256sum --check --strict (setup.sh) accepts it" || fail "sha256sum --strict rejects the manifest"

echo "without a previous manifest"
fresh_bin
out="$(env -u BAS_PREVIOUS_MANIFEST bash -c "cd '$T' && bash '$T/pkg/signing/sign-binaries.sh' '$T/bin'" 2>&1)"
[ "$(grep -c '^#prev ' "$M" || true)" = "0" ] && pass "no #prev lines are invented" || fail "unexpected #prev lines"
echo "$out" | grep -q "BAS_PREVIOUS_MANIFEST not set" && pass "it warns that agents on the last release will be quarantined" || fail "no warning"

echo "an unusable previous manifest fails closed"
fresh_bin
if BAS_PREVIOUS_MANIFEST="$T/does-not-exist" run >/dev/null 2>&1; then fail "a missing previous manifest was accepted"; else pass "a missing previous manifest stops the build"; fi

echo
if [ "$fails" -eq 0 ]; then echo "PASS: all checks passed"; else echo "FAIL: $fails check(s) failed"; exit 1; fi
