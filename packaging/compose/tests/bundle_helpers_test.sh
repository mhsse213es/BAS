#!/usr/bin/env bash
# packaging/compose/tests/bundle_helpers_test.sh
# Every helper the installers source or require from SCRIPT_DIR must be copied into the distribution bundle by
# packaging/build.sh. A missing one makes the shipped installer refuse to run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$HERE/../build.sh"

pass=0
fail=0
ok()  { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }

# Helpers the installers need at runtime: anything they source or test with -f "${SCRIPT_DIR}/...".
required=$(cat "$HERE/install.sh" "$HERE/setup.sh" "$HERE/uninstall.sh"   | grep -oE '[$][{]SCRIPT_DIR[}]/[A-Za-z0-9_.-]+'   | sed 's#.*/##' | grep -E '[.]sh$' | sort -u || true)

for f in $required setup.sh; do
  if grep -qE "cp \"\\\$\{REPO_ROOT\}/packaging/compose/${f}\"" "$BUILD"; then
    ok "bundle copies ${f}"
  else
    bad "bundle does not copy ${f}, which the installers require"
  fi
done

# The Windows build (packaging/windows-build.ps1) produces the bundle that is actually shipped. It must copy the same
# files as build.sh, or the shipped installer refuses to run. setup.sh is the fresh-install entry point that the
# bundle's own verify.sh tells operators to run, so it is required as well.
WINBUILD="$HERE/../windows-build.ps1"
for f in $required setup.sh; do
  if grep -qF "\\${f}\"" "$WINBUILD"; then
    ok "windows build copies ${f}"
  else
    bad "windows build does not copy ${f}, which the shipped installer requires"
  fi
done

# install.sh itself is the installer entry point; it must be in the bundle.
if grep -qE 'cp "\$\{REPO_ROOT\}/packaging/compose/install\.sh"' "$BUILD"; then
  ok "bundle copies install.sh"
else
  bad "bundle does not copy install.sh"
fi

echo "---"
echo "passed: $pass  failed: $fail"
[[ "$fail" -eq 0 ]]
