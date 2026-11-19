#!/bin/sh
# Fetches the pinned SigmaHQ commit into tools/rulelib/sigma (git-ignored). DEV-TIME ONLY: this needs the network,
# so it runs on a build machine, never on a customer server. The rules the product ships are generated from this
# checkout by scripts/rulelib-gen and committed, so customers need no download.
set -eu
cd "$(dirname "$0")"
commit=$(tr -d '[:space:]' < SIGMA_COMMIT)
[ -d sigma/.git ] || { git init -q sigma && git -C sigma remote add origin https://github.com/SigmaHQ/sigma.git; }
git -C sigma fetch -q --depth 1 origin "$commit"
git -C sigma checkout -q FETCH_HEAD
test "$(git -C sigma rev-parse HEAD)" = "$commit" && echo "SigmaHQ at $commit"
