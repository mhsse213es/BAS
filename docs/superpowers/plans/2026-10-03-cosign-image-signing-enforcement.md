# Cosign Image Signing Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the enforcement gaps around the orchestrator release artifact's existing (but currently optional/silent-skip) cosign signing mechanism, so a release build can never ship an unsigned artifact and a customer install can never load a tampered one.

> **CORRECTED 2026-10-03 during execution (see
> `.superpowers/sdd/2026-10-03-cosign-image-signing-enforcement/progress.md`
> for full detail):** the design below as originally written assumed
> `cosign sign`/`cosign verify` work against a Docker-daemon image
> reference. Real execution proved this wrong: cosign's `sign`/`verify`/
> `save`/`load` subcommands all resolve against a container **registry**,
> which does not exist in this on-prem/air-gapped model — the
> orchestrator image is built and `docker save`d but never pushed
> anywhere. The design was corrected in chat to sign the **`docker save`
> tarball's own bytes** via `cosign sign-blob`/`verify-blob` instead,
> which needs no registry. A second real-execution finding:
> `sign-blob` silently uploads to the public Sigstore transparency log
> over the internet by default even with a local key pair —
> `--tlog-upload=false --use-signing-config=false` are both required to
> keep this fully offline (confirmed by inspecting the signed bundle with
> and without these flags). Every mention of "sign the image"/"verify the
> loaded image" below should be read as "sign/verify the orchestrator
> tarball"; Tasks 3/4's "load → verify → remove-on-failure" become
> "verify → load-only-if-valid" (verify-blob needs no `docker load`
> first, since it operates on the tarball file directly — this is a
> strictly stronger property than the original design could achieve).

**Architecture:** `packaging/signing/cosign.sh` provides `--keygen`/`--sign <file>`/`--verify <file>` subcommands using `cosign sign-blob`/`verify-blob` against a local key pair, operating on the orchestrator's `docker save` tarball (no Sigstore keyless signing, no registry — this deployment is on-prem/air-gapped). The two build paths (`packaging/build.sh`, `packaging/windows-build.ps1`) `docker save` the `bas-orchestrator` image to its final bundle path, then sign+verify that exact tarball before anything else happens to it. The two installer scripts (`packaging/compose/setup.sh`, `packaging/compose/install.sh`) verify the orchestrator tarball **before** `docker load` ever runs on it — a stronger guarantee than the original image-based design, which could only verify after loading.

**Tech Stack:** bash (`build.sh`, `setup.sh`, `install.sh`), PowerShell (`windows-build.ps1`), `cosign` CLI (local key-pair mode).

**Spec:** No separate spec file — classified as bounded work (every flow already exists: `cosign.sh`, the `$WindowsSigningRequired` Err/Warn convention, the bundle-ships-the-pubkey mechanism). This plan's Context section below carries the design that would otherwise live in a spec.

## Context (design, agreed in chat on 2026-10-03, corrected mid-execution — see note above)

Trust chain (corrected):
```
docker build → docker save (final tar) → cosign sign-blob → cosign verify-blob (build gate) → release bundle
   → [transport] → setup.sh/install.sh → cosign verify-blob (customer gate, BEFORE docker load) → docker load
```

- **`packaging/signing/cosign.sh`**: rewritten (this plan's Task 1) from image-reference `--sign <image:tag>`/`--verify <image:tag>` to file-reference `--sign <artifact-file>`/`--verify <artifact-file>`, using `cosign sign-blob --key cosign.key --yes --tlog-upload=false --use-signing-config=false --bundle <file>.bundle <file>` and `cosign verify-blob --key cosign.pub --bundle <file>.bundle --insecure-ignore-tlog <file>`.
- **`packaging/build.sh`**: cosign becomes unconditionally mandatory, checked *before* `docker build` (fail fast). `docker save`s the image straight to its final bundle path, then signs+verifies that exact tarball. Missing `cosign` binary, missing `cosign.key`, a failed sign, or a failed verify must all `err`/exit. No `--dev` escape hatch.
- **`packaging/windows-build.ps1`**: gated by the *existing* `$WindowsSigningRequired` variable (already defaults to `$IsCustomerBuild`) — same Err/Warn convention D1/C2 already established elsewhere in this file. Customer build: any cosign failure is `Err` (abort). Dev build: `Warn` and continue unsigned. Signs+verifies the tarball *after* `docker save` (not between `Update-OrchestratorAgentArtifacts` and `docker save`, as originally planned — the artifact being signed is the tarball, which doesn't exist until after save). `cosign` is a native Windows binary (`cosign.exe`), called directly from PowerShell, mirroring how this file already calls `gpg.exe` directly rather than shelling out to a bash script.
- **`packaging/compose/setup.sh`** and **`packaging/compose/install.sh`**: both have a `docker load` loop over every `.tar`/`.tar.gz` in the bundle's `images/` directory. The orchestrator tar (filename `bas-orchestrator-*`) gets singled out: `cosign verify-blob` the tarball file **directly, before any `docker load` call** — a stronger property than the original "load then verify" design, since the tarball's bytes never reach the Docker daemon at all if verification fails. `postgres`/`caldera`/`headless-shell` images are untouched; Audspect doesn't sign those, so they load as before (`docker load` unconditionally, no verify). Verification needs the sibling `.bundle` file (shipped alongside the tar in the bundle) and `cosign.pub` (shipped at the bundle root) — no network access.
- Testing throughout must be real executions — actually running `cosign sign-blob`/`verify-blob` against a real local file and real tampered variants (bit-flip, missing bundle, swapped bundle, wrong public key) — not string-matching against script text. (Lesson from a bug shipped earlier the same day: a throwaway test matched the wrong thing and a real defect — `build.sh`'s `-ldflags` word-splitting — passed review undetected until manual verification caught it. Reconfirmed by this plan's own Task 1: the original "cosign.sh already works, no changes needed" assumption was itself untested and wrong.)

## Global Constraints

- Local key-pair signing only (`cosign.key`/`cosign.pub` at `packaging/signing/`) — never Sigstore keyless signing, which requires internet access this on-prem/air-gapped deployment model does not have.
- `cosign.key` must never be committed; `cosign.pub` is not secret and ships inside every release bundle.
- No `--skip-verification`/`--dev` escape hatch anywhere in the customer-facing install flow (`setup.sh`/`install.sh`). `windows-build.ps1`'s dev-vs-customer distinction already exists (`$WindowsSigningRequired`) and is reused as-is, not re-invented.
- Verification failure during install/upgrade must abort the whole script (nonzero exit), not just skip the one affected image.
- `postgres`, `caldera`, `headless-shell` images are explicitly out of scope — Audspect does not assert cosign provenance over third-party images.

## Review Focus

1. **A missing or unreadable `.bundle` sidecar file gets misread as "verification failure" (tamper) or vice versa**, producing a confusing error that sends an operator chasing the wrong cause. Each task's tests must distinguish a missing-bundle error from a tamper-detected error with a distinct message (confirmed real: `cosign.sh`'s rewritten `cmd_verify` checks `-f "${artifact}.bundle"` explicitly before ever calling `cosign verify-blob`, so the two cases already produce different messages).
2. **A future cosign upgrade silently re-enabling transparency-log upload** (the exact bug this plan's own Task 1 found: `sign-blob` contacts `rekor.sigstore.dev` by default even with a local key, unless `--tlog-upload=false --use-signing-config=false` are both passed). Task 1's test confirms the signed bundle contains no `tlogEntries`/`checkpoint` fields, not just that signing "succeeded."
3. **`windows-build.ps1`'s dev-build path (`$WindowsSigningRequired = $false`) silently never verifies anything**, even informationally — a developer could ship a dev build with a broken `cosign.pub`/key pair for months without ever finding out until the first customer build. Task 2 logs a `Warn` (not silence) whenever cosign is skipped in dev mode, naming exactly what was skipped.
4. **A tampered tarball paired with its original (unmodified) `.bundle` sidecar escapes verification** if the verify step checks the bundle's mere presence rather than cryptographically validating it against the tarball's current bytes. Task 3/4's tests specifically pair a bit-tampered tarball with its original, un-swapped bundle (not a missing bundle) to confirm `cosign verify-blob` itself — not just a file-existence check — is what catches it.
5. **`setup.sh`'s existing `docker load < "$img" || true` swallows load failures for every image including, before this plan, the orchestrated one** — Task 4 must confirm the new code path for the orchestrator tar does *not* inherit that `|| true` for the verify step (a failed verify must abort, not warn-and-continue), while every other image in the same loop still does (scope boundary, not a silent behavior change for postgres/caldera).

---

### Task 1: `packaging/build.sh` — mandatory fail-closed cosign sign+verify

> **SUPERSEDED during execution** — the step-by-step content below signs
> the Docker *image* via `cosign.sh --sign <image:tag>`, which real
> execution proved impossible (see the correction note at the top of this
> plan). What was actually implemented and committed: `cosign.sh`
> rewritten to `--sign <artifact-file>`/`--verify <artifact-file>` via
> `sign-blob`/`verify-blob`; `build.sh` checks cosign/key *before*
> `docker build`, `docker save`s straight to the final bundle path, then
> signs+verifies that exact tarball. Real execution (77MB orchestrator
> build, real sign, real verify, all 4 tamper boundaries against the
> rewritten `cosign.sh`) confirmed working. Committed as `da83b4f4`;
> full detail in `.superpowers/sdd/2026-10-03-cosign-image-signing-enforcement/progress.md`.
> The steps below are kept for historical record of the original
> (incorrect) design only.

**Files:**
- Modify: `packaging/build.sh:196-227`

**Interfaces:**
- Consumes: `packaging/signing/cosign.sh` (`--sign`, `--verify` subcommands, unchanged) — no exported function names since this is a sibling script invoked via `bash <path> --sign <image:tag>` / `bash <path> --verify <image:tag>`, exit code 0 on success, nonzero on any failure.
- Produces: `packaging/signing/cosign.pub` present in `${BUILD_DIR}/` after this task, same as before (unchanged copy step, now unconditional). Later tasks (3, 4) consume this file at the same bundle-relative path.

- [ ] **Step 0: Provision cosign on this build host (one-time, not a test)**

This host has no `cosign` binary yet. Every later task's real-execution tests need it on PATH for both `bash` (git-bash) and PowerShell — a native Windows `cosign.exe` satisfies both, since git-bash can execute Windows PE binaries directly (the same way `go.exe` already is throughout this build host's existing scripts).

```powershell
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest -Uri "https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe" -OutFile "$env:TEMP\cosign.exe"
Invoke-WebRequest -Uri "https://github.com/sigstore/cosign/releases/latest/download/cosign_checksums.txt" -OutFile "$env:TEMP\cosign_checksums.txt"
$expected = (Select-String -Path "$env:TEMP\cosign_checksums.txt" -Pattern "cosign-windows-amd64\.exe$").Line.Split(" ")[0]
$actual = (Get-FileHash -Path "$env:TEMP\cosign.exe" -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { Write-Error "cosign.exe checksum mismatch: got $actual, expected $expected"; exit 1 }
New-Item -ItemType Directory -Force -Path "C:\cosign" | Out-Null
Move-Item -Force "$env:TEMP\cosign.exe" "C:\cosign\cosign.exe"
$env:PATH = "C:\cosign;$env:PATH"
cosign version
```
Expected: checksum matches, `cosign version` prints a version banner with no error. Add `C:\cosign` to this build host's persistent `PATH` (System Properties → Environment Variables, or the equivalent the host's own setup used for `C:\go1.20.14`) so later tasks don't need to re-prepend it per-session.

Then generate a real test key pair (not the production one — keep this test-only key separate so a throwaway test run never touches a real signing key):
```bash
mkdir -p /tmp/cosign-test-keys
cd /tmp/cosign-test-keys
COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix test
ls test.key test.pub
```
Expected: both files exist, no error.

- [ ] **Step 1: Write the failing test**

Real execution, not string-matching (per Review Focus and the Global Constraints' testing rule). Build a tiny throwaway image, confirm the *current* (pre-fix) `build.sh` behavior — signing is skipped silently when `cosign.key` is absent, and the script does not fail:

```bash
cat > /tmp/cosign-task1-dockerfile << 'EOF'
FROM alpine:latest
CMD ["true"]
EOF
docker build -q -t cosign-task1-test -f /tmp/cosign-test-dockerfile /tmp 2>&1 || \
  docker build -q -t cosign-task1-test -f /tmp/cosign-task1-dockerfile /tmp
# Simulate build.sh's current (pre-fix) cosign block with no cosign.key present:
COSIGN_SCRIPT="packaging/signing/cosign.sh"
COSIGN_PUB="packaging/signing/cosign.pub"
if command -v cosign &>/dev/null && [[ -f "packaging/signing/cosign.key" ]]; then
  echo "would sign"
else
  echo "WARN: cosign not available or cosign.key missing — Docker image will not be cosign-signed."
fi
echo "exit=$?"
```
Expected: prints the `WARN:` line and `exit=0` — proving the current code lets an unsigned release proceed. This is the bug: a release build must not be allowed to reach this state silently.

- [ ] **Step 2: Run test to verify it fails (i.e., confirms the bug)**

Run the Step 1 script. Expected output exactly as described above — `exit=0` despite no image ever being signed. This is the RED state this task fixes (the "test" here is a behavioral demonstration of the defect, since `build.sh` itself has no test harness — same as every other shell-script task in this plan).

- [ ] **Step 3: Edit `packaging/build.sh`**

Replace `packaging/build.sh:196-227`:

```bash
# ── 4. Build Docker image and export (optional, requires Docker) ───────────────
if command -v docker &>/dev/null; then
  log "Building Docker image bas-orchestrator:${VERSION}..."
  docker build \
    --build-arg VERSION="${VERSION}" \
    -t "bas-orchestrator:${VERSION}" \
    -f "${REPO_ROOT}/orchestrator/Dockerfile" \
    "${REPO_ROOT}"

  # Sign image with cosign if available
  COSIGN_SCRIPT="${REPO_ROOT}/packaging/signing/cosign.sh"
  COSIGN_PUB="${REPO_ROOT}/packaging/signing/cosign.pub"
  if command -v cosign &>/dev/null && [[ -f "${REPO_ROOT}/packaging/signing/cosign.key" ]]; then
    log "Signing Docker image with cosign..."
    bash "${COSIGN_SCRIPT}" --sign "bas-orchestrator:${VERSION}"
    # Copy public key into bundle so installer can verify
    [[ -f "$COSIGN_PUB" ]] && cp "$COSIGN_PUB" "${BUILD_DIR}/"
  else
    warn "cosign not available or cosign.key missing — Docker image will not be cosign-signed."
    echo "  To sign: bash packaging/signing/cosign.sh --keygen  then rebuild."
  fi

  log "Exporting Docker image to bundle..."
  mkdir -p "${BUILD_DIR}/images"
  docker save "bas-orchestrator:${VERSION}" \
    | gzip > "${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
  docker save "postgres:16-alpine" \
    | gzip > "${BUILD_DIR}/images/postgres-16-alpine.tar.gz" 2>/dev/null || \
    warn "postgres:16-alpine not pulled locally — run 'docker pull postgres:16-alpine' to include it"
else
  warn "Docker not found — skipping image export. Bundle will pull images on install."
fi
```

with:

```bash
# ── 4. Build Docker image and export (requires Docker) ─────────────────────────
if ! command -v docker &>/dev/null; then
  err "Docker not found — this script produces a release bundle and cannot do so without Docker."
  exit 1
fi

log "Building Docker image bas-orchestrator:${VERSION}..."
docker build \
  --build-arg VERSION="${VERSION}" \
  -t "bas-orchestrator:${VERSION}" \
  -f "${REPO_ROOT}/orchestrator/Dockerfile" \
  "${REPO_ROOT}"

# D2/cosign-enforcement: this script produces the distributable release
# bundle -- it has no dev-build concept to preserve, so cosign signing is
# unconditionally mandatory here (unlike windows-build.ps1, which keeps an
# explicit dev-vs-customer distinction via $WindowsSigningRequired). Sign,
# then immediately verify the signature we just produced, before the image
# is ever saved into the bundle a customer receives -- mirrors C4's "sign
# the one authoritative artifact" lesson: never ship bytes nobody verified.
COSIGN_SCRIPT="${REPO_ROOT}/packaging/signing/cosign.sh"
COSIGN_KEY="${REPO_ROOT}/packaging/signing/cosign.key"
COSIGN_PUB="${REPO_ROOT}/packaging/signing/cosign.pub"
if ! command -v cosign &>/dev/null; then
  err "cosign is not installed, and cosign signing is mandatory for this release build. Install: https://docs.sigstore.dev/cosign/system_config/installation/"
  exit 1
fi
if [[ ! -f "$COSIGN_KEY" ]]; then
  err "cosign.key not found at ${COSIGN_KEY}, and cosign signing is mandatory for this release build. Run: bash packaging/signing/cosign.sh --keygen"
  exit 1
fi
log "Signing Docker image with cosign..."
if ! bash "${COSIGN_SCRIPT}" --sign "bas-orchestrator:${VERSION}"; then
  err "cosign signing failed for bas-orchestrator:${VERSION} -- aborting release build."
  exit 1
fi
log "Verifying the signature we just produced..."
if ! bash "${COSIGN_SCRIPT}" --verify "bas-orchestrator:${VERSION}"; then
  err "cosign verification FAILED immediately after signing bas-orchestrator:${VERSION} -- this should be structurally impossible; investigate before shipping."
  exit 1
fi
if [[ ! -f "$COSIGN_PUB" ]]; then
  err "cosign.pub not found at ${COSIGN_PUB} after a successful sign+verify -- cannot ship a release bundle the installer can't verify."
  exit 1
fi
cp "$COSIGN_PUB" "${BUILD_DIR}/"

log "Exporting Docker image to bundle..."
mkdir -p "${BUILD_DIR}/images"
docker save "bas-orchestrator:${VERSION}" \
  | gzip > "${BUILD_DIR}/images/bas-orchestrator-${VERSION}.tar.gz"
docker save "postgres:16-alpine" \
  | gzip > "${BUILD_DIR}/images/postgres-16-alpine.tar.gz" 2>/dev/null || \
  warn "postgres:16-alpine not pulled locally — run 'docker pull postgres:16-alpine' to include it"
```

Confirmed (`grep -n "^err\|^warn\|^log\|RED=\|GREEN=\|YELLOW=" packaging/build.sh`): this file has `log`/`warn` but **no `err` helper and no `RED` color** — unlike `install.sh`/`setup.sh`, which both already define
`err() { echo -e "${RED}[FAIL or ✗]${NC} $*" >&2; }` (prints only, never exits — every call site adds its own `exit 1`). Add the same non-exiting shape to `build.sh` for consistency with its sibling scripts, near the existing `log`/`warn` definitions (around line 33):

```bash
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
```
→
```bash
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
```
and change the color block two lines above it (around line 29):
```bash
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
```
→
```bash
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
```
(and its paired empty-string fallback branch two lines below, from `GREEN=''; YELLOW=''; NC=''` to `RED=''; GREEN=''; YELLOW=''; NC=''`).

Since `err` here never exits on its own (matching the sibling scripts' convention), every `err "..."` call this task adds to the cosign block below must be followed by its own `exit 1`.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
cp packaging/signing/cosign.sh /tmp/cosign-task1-nokey-check.sh
# Confirm the new fail-closed behavior with no key present:
rm -f packaging/signing/cosign.key packaging/signing/cosign.pub
bash packaging/build.sh cosign-task1-nokey 2>&1 | tail -5
echo "exit=$?"
```
Expected: the script exits nonzero with `cosign.key not found ... and cosign signing is mandatory for this release build` printed, and crucially **no** `dist/bas-platform-compose-cosign-task1-nokey.tar.gz` is produced (confirm with `ls dist/ | grep cosign-task1-nokey` — expect no match).

Then confirm the real happy path:
```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
bash packaging/signing/cosign.sh --keygen <<< "y"
bash packaging/build.sh cosign-task1-happy 2>&1 | tail -15
echo "exit=$?"
ls dist/bas-platform-compose-cosign-task1-happy.tar.gz
```
Expected: exit 0, the log shows `Signing Docker image with cosign...` then `Verifying the signature we just produced...` with no error between them, and the tarball exists. (This is a real full build — expect several minutes; the orchestrator's own `garble -literals -tiny` build is the slow part, unrelated to this task.)

Clean up the real production key pair this step generated so it isn't accidentally committed or reused as a throwaway:
```bash
rm -f packaging/signing/cosign.key packaging/signing/cosign.pub
rm -rf dist/bas-platform-compose-cosign-task1-*
docker rmi bas-orchestrator:cosign-task1-happy bas-orchestrator:cosign-task1-nokey cosign-task1-test 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add packaging/build.sh
git commit -m "fix(release): make cosign image signing fail-closed in build.sh

Previously, a missing cosign binary or cosign.key only produced a
warning -- the release bundle still shipped, unsigned, with no way to
tell from the build's exit code. This script has no dev-build concept
(its only job is producing the distributable bundle), so cosign is now
unconditionally mandatory: missing cosign, missing cosign.key, a failed
sign, or a failed verify (run immediately after signing, before the
image is ever saved) all abort the build.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `packaging/windows-build.ps1` — native cosign sign+verify, gated by \$WindowsSigningRequired

> **SUPERSEDED during execution** — signs the tarball via `sign-blob`
> (not the image via `cosign sign`), inserted *after* `docker save`
> rather than between `Update-OrchestratorAgentArtifacts` and
> `docker save`. Also found and fixed a Windows-specific gotcha:
> `$env:COSIGN_PASSWORD = ""` doesn't work on Windows (Win32 can't
> represent an empty-string env var; the assignment is silently
> treated as unset). Fixed with `Start-Process -RedirectStandardInput`
> from a real 0-byte file. Real execution verified (required-mode
> error, dev-mode warn, full sign+verify happy path). Committed as
> `21ab6cfa`; full detail in
> `.superpowers/sdd/2026-10-03-cosign-image-signing-enforcement/progress.md`.
> The steps below are kept for historical record of the original
> (incorrect) design only.

**Files:**
- Modify: `packaging/windows-build.ps1` (insert between the `Update-OrchestratorAgentArtifacts` call and `docker save`, currently around lines 627-650 — re-check the exact line numbers before editing, since Task 1 does not touch this file but other work may have shifted lines since this plan was written)

**Interfaces:**
- Consumes: `cosign.exe` on PATH (Task 1, Step 0's host provisioning — this task does not re-provision it), `$RepoRoot\packaging\signing\cosign.key`/`cosign.pub` (same key-pair convention and file paths Task 1 uses, so a key pair generated for one build path verifies against the other).
- Produces: `cosign.pub` copied into `$OutDir`, same bundle-relative location Task 1 produces in `${BUILD_DIR}/` — Task 3 (install.sh) consumes this file from the Windows-built bundle specifically.

- [ ] **Step 1: Write the failing test**

```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
Get-Command cosign -ErrorAction SilentlyContinue
```
Expected (before Step 0's provisioning, if not yet done, or to confirm the *current* script has no cosign call at all):
```powershell
Select-String -Path packaging\windows-build.ps1 -Pattern "cosign" -SimpleMatch
```
Expected: no matches — confirming the current script has zero cosign integration before this task's edit.

- [ ] **Step 2: Run test to verify it fails (confirms the gap)**

Run the `Select-String` command above against the current file. Expected: empty result (no output), proving `windows-build.ps1` has no cosign call anywhere yet.

- [ ] **Step 3: Edit `packaging/windows-build.ps1`**

Locate the current text (re-find via `Select-String -Path packaging\windows-build.ps1 -Pattern "Saving \$OrchestratorTag" -Context 0,5` if line numbers have shifted):

```powershell
# Save the orchestrator image AFTER the patch above, not before --
# docker save produced the tar that install.sh actually `docker load`s on
# the customer's machine, and saving it before this patch (the original
# order) meant the shipped tar never contained the patched bytes at all,
# even though the local daemon's tag was correctly patched. One save
# call now covers every path: patched-and-required, patched-not-required,
# skipped-not-required, and plain dev build with no cert at all.
Log "  Saving $OrchestratorTag..."
docker save $OrchestratorTag -o "$OutDir\images\bas-orchestrator-$Version.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save orchestrator image." }
```

with:

```powershell
# D2/cosign-enforcement: sign the image AFTER the Update-OrchestratorAgentArtifacts
# patch above, same "sign the one authoritative artifact" ordering this
# file already uses for the agent binaries (see C4's byte-equality
# assertion elsewhere in this script) -- never sign a pre-patch
# intermediate that isn't what actually gets saved/shipped. Gated by the
# existing $WindowsSigningRequired (already = $IsCustomerBuild by
# default): a customer build that can't sign+verify must not ship; a dev
# build without cosign configured proceeds unsigned, loudly.
$CosignKey = "$RepoRoot\packaging\signing\cosign.key"
$CosignPub = "$RepoRoot\packaging\signing\cosign.pub"
$cosignCmd = Get-Command cosign -ErrorAction SilentlyContinue
if (-not $cosignCmd) {
    if ($WindowsSigningRequired) {
        Err "cosign is not installed, and cosign signing is mandatory for this customer build. Install: https://docs.sigstore.dev/cosign/system_config/installation/"
    } else {
        Warn "  cosign not found -- orchestrator image will not be cosign-signed (not required for this build)."
    }
} elseif (-not (Test-Path $CosignKey)) {
    if ($WindowsSigningRequired) {
        Err "cosign.key not found at $CosignKey, and cosign signing is mandatory for this customer build. Run: bash packaging/signing/cosign.sh --keygen"
    } else {
        Warn "  cosign.key not found -- orchestrator image will not be cosign-signed (not required for this build)."
    }
} else {
    Log "  Signing $OrchestratorTag with cosign..."
    $env:COSIGN_PASSWORD = ""
    cosign sign --key $CosignKey --yes $OrchestratorTag 2>&1 | ForEach-Object { Log "    $_" }
    if ($LASTEXITCODE -ne 0) {
        if ($WindowsSigningRequired) { Err "cosign signing failed for $OrchestratorTag -- aborting customer build." }
        else { Warn "  cosign signing failed -- continuing unsigned (not required for this build)." }
    } else {
        Log "  Verifying the signature we just produced..."
        cosign verify --key $CosignPub --insecure-ignore-tlog $OrchestratorTag 2>&1 | ForEach-Object { Log "    $_" }
        if ($LASTEXITCODE -ne 0) {
            Err "cosign verification FAILED immediately after signing $OrchestratorTag -- this should be structurally impossible; investigate before shipping."
        }
        Log "  $OrchestratorTag signed and verified."
        Copy-Item $CosignPub "$OutDir\cosign.pub" -Force
    }
    $env:COSIGN_PASSWORD = ""
}

# Save the orchestrator image AFTER the patch above, not before --
# docker save produced the tar that install.sh actually `docker load`s on
# the customer's machine, and saving it before this patch (the original
# order) meant the shipped tar never contained the patched bytes at all,
# even though the local daemon's tag was correctly patched. One save
# call now covers every path: patched-and-required, patched-not-required,
# skipped-not-required, and plain dev build with no cert at all.
Log "  Saving $OrchestratorTag..."
docker save $OrchestratorTag -o "$OutDir\images\bas-orchestrator-$Version.tar"
if ($LASTEXITCODE -ne 0) { Err "Failed to save orchestrator image." }
```

- [ ] **Step 4: Run test to verify it passes**

```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
Select-String -Path packaging\windows-build.ps1 -Pattern "cosign sign --key|cosign verify --key" -SimpleMatch
```
Expected: both lines now present (proves the edit landed).

Then a real end-to-end run, dev mode first (no `-Customer`, so `$WindowsSigningRequired` is `$false`, confirming the Warn path when no key exists):
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
Remove-Item -Force -ErrorAction SilentlyContinue packaging\signing\cosign.key, packaging\signing\cosign.pub
.\packaging\windows-build.ps1 -Version "cosign-task2-dev" 2>&1 | Select-String "cosign|Saving"
```
Expected: `cosign.key not found -- orchestrator image will not be cosign-signed (not required for this build).` printed, script continues, and `dist\bas-install-cosign-task2-dev\images\bas-orchestrator-cosign-task2-dev.tar` still gets created (unsigned, as expected for a dev build).

Then the real happy path, forcing the required branch to exercise sign+verify without needing a full customer/cert setup — temporarily force `$WindowsSigningRequired`:
```powershell
cd C:\Users\Administrator\Downloads\Audspect_Cloud
bash packaging/signing/cosign.sh --keygen <<< "y"
.\packaging\windows-build.ps1 -Version "cosign-task2-happy" -WindowsSigningRequired $true 2>&1 | Select-String "cosign|Saving|signed and verified"
Test-Path "dist\bas-install-cosign-task2-happy\cosign.pub"
```
Expected: `Signing ... with cosign...`, then `Verifying the signature we just produced...`, then `bas-orchestrator:cosign-task2-happy signed and verified.`, no `Err` triggered, and `cosign.pub` exists in the output directory.

Clean up:
```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist\bas-install-cosign-task2-dev, dist\bas-install-cosign-task2-happy, dist\bas-install-cosign-task2-dev.zip*, dist\bas-install-cosign-task2-happy.zip*
Remove-Item -Force -ErrorAction SilentlyContinue packaging\signing\cosign.key, packaging\signing\cosign.pub
docker rmi "bas-orchestrator:cosign-task2-dev" "bas-orchestrator:cosign-task2-happy" 2>&1 | Out-Null
```

- [ ] **Step 5: Commit**

```bash
git add packaging/windows-build.ps1
git commit -m "fix(release): add cosign image signing to windows-build.ps1, gated by \$WindowsSigningRequired

windows-build.ps1 built and shipped the orchestrator image with no
cosign integration at all, while packaging/build.sh (the other release
path) already had a (previously optional) cosign step -- a customer
build through this path could never be verified. Signs+verifies between
Update-OrchestratorAgentArtifacts (the image's last mutation) and
docker save, same sequencing C4 already established for the agent
binaries in this file. Reuses the existing \$WindowsSigningRequired
Err/Warn convention rather than inventing a new one.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `packaging/compose/install.sh` — verify-before-use gate for the orchestrator image

> **SUPERSEDED during execution** — verifies the tarball directly via
> `cosign verify-blob` **before** any `docker load` call (stronger than
> the original "load then verify, remove on failure" design — the
> tarball's bytes never reach the Docker daemon if verification fails).
> No `fatal` helper exists in this file (the plan's original text
> invented one); uses the file's real `err()` (non-exiting) + explicit
> `exit 1`, matching its own convention. `_check_cosign` registered in
> BOTH `mode_check`'s reporting list and `mode_install`'s real blocking
> gate (the plan's original "around line 589" pointed at the wrong,
> non-blocking list — caught and corrected before editing). Real
> execution verified (happy path, 3 distinct failure modes, and the
> critical load-never-reached ordering property via an UNREACHABLE
> sentinel). Committed as `b470fe76`; full detail in
> `.superpowers/sdd/2026-10-03-cosign-image-signing-enforcement/progress.md`.
> The steps below are kept for historical record of the original
> (incorrect) design only.

**Files:**
- Modify: `packaging/compose/install.sh` (prereq check list around line 588-592; `docker load` loops in `mode_install` around line 715-725 and `mode_upgrade` around line 858-864 — re-check exact line numbers before editing)

**Interfaces:**
- Consumes: `cosign.pub` shipped at the bundle root (Task 2 produces this at `$OutDir\cosign.pub`, which becomes `<bundle-root>/cosign.pub` once the bundle is unpacked on the customer's machine — same relative location `$SCRIPT_DIR/../cosign.pub` or `$SCRIPT_DIR/cosign.pub` depending on where `install.sh` itself sits in the bundle layout; confirm with `Select-String -Path packaging\windows-build.ps1 -Pattern "install\.sh"` which directory `install.sh` is copied to relative to where `cosign.pub` lands).
- Produces: nothing for a later task — this is a leaf consumer.

- [ ] **Step 1: Write the failing test**

Real execution. Build a throwaway "orchestrator-shaped" tar, sign it, then tamper with it, and confirm the *current* `install.sh` loads it anyway (no verification exists yet):

```bash
cd /tmp
mkdir -p cosign-task3-test/images
cat > cosign-task3-test/Dockerfile << 'EOF'
FROM alpine:latest
LABEL test=cosign-task3
EOF
docker build -q -t bas-orchestrator:cosign-task3-test -f cosign-task3-test/Dockerfile cosign-task3-test
docker save bas-orchestrator:cosign-task3-test -o cosign-task3-test/images/bas-orchestrator-cosign-task3-test.tar

# Tamper: re-tag a DIFFERENT image under the same name/tag the bundle expects,
# simulating a swapped/corrupted tarball an attacker or a bad transfer produced.
docker build -q -t bas-orchestrator:cosign-task3-test -f - cosign-task3-test << 'EOF'
FROM alpine:latest
LABEL test=cosign-task3-TAMPERED
EOF
docker save bas-orchestrator:cosign-task3-test -o cosign-task3-test/images/bas-orchestrator-cosign-task3-test-tampered.tar

# Simulate install.sh's current loop (no verification):
docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1
docker load < cosign-task3-test/images/bas-orchestrator-cosign-task3-test-tampered.tar
echo "exit=$?"
docker images bas-orchestrator:cosign-task3-test
```
Expected: `exit=0` and the tampered image shows up as loaded — proving the current script has no gate that would catch this.

- [ ] **Step 2: Run test to verify it fails (confirms the gap)**

Run the Step 1 script. Expected output exactly as above: the tampered image loads successfully with no error, no verification attempted.

- [ ] **Step 3: Edit `packaging/compose/install.sh`**

First, add a cosign prereq check next to the existing `_check_docker` (around line 372):

```bash
# Callers use results+=( "$(_check_docker)" ) -- that $(...) runs this in a
# subshell, so it cannot set NEED_DOCKER itself; mode_install sets it directly.
_check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "INST:Docker -not installed (installer can install it with your consent)"; return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker -daemon not running (start it before install)"; return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker -${ver}"
}
```

with (adding a new function immediately after, unchanged `_check_docker` above it):

```bash
# Callers use results+=( "$(_check_docker)" ) -- that $(...) runs this in a
# subshell, so it cannot set NEED_DOCKER itself; mode_install sets it directly.
_check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "INST:Docker -not installed (installer can install it with your consent)"; return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker -daemon not running (start it before install)"; return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker -${ver}"
}

# The orchestrator image ships cosign-signed (packaging/build.sh,
# packaging/windows-build.ps1); this installer must be able to verify
# that signature before loading it. No auto-install path like Docker's --
# cosign is specific enough that silently installing it on an operator's
# box is not appropriate here.
_check_cosign() {
  if ! command -v cosign &>/dev/null; then
    echo "FAIL:Cosign -not installed (required to verify the orchestrator image before install; see https://docs.sigstore.dev/cosign/system_config/installation/)"
    return
  fi
  if [[ ! -f "${SCRIPT_DIR}/cosign.pub" ]]; then
    echo "FAIL:Cosign -public key not found in bundle at ${SCRIPT_DIR}/cosign.pub (corrupt or incomplete release bundle)"
    return
  fi
  echo "PASS:Cosign -$(cosign version 2>/dev/null | grep -oP 'GitVersion:\s*\K\S+' || echo 'installed')"
}
```

Then register it in both call sites (around line 589 and wherever `mode_upgrade`'s own prereq list is, if any — `mode_upgrade` currently has none per this plan's own exploration, so only the `mode_install` list needs it; the real gate for upgrades is the inline check below, which doesn't depend on this prereq list running first):

```bash
  results+=( "$(_check_os)" )
  results+=( "$(_check_docker)" )
  results+=( "$(_check_compose)" )
```

with:

```bash
  results+=( "$(_check_os)" )
  results+=( "$(_check_docker)" )
  results+=( "$(_check_compose)" )
  results+=( "$(_check_cosign)" )
```

Then add a shared verification helper near `render_checks` (so both `mode_install` and `mode_upgrade` can call it without duplicating the logic):

```bash
# ── Render check results ──────────────────────────────────────────────────────
```

with:

```bash
# Verifies the already-`docker load`-ed orchestrator image against the
# bundle's cosign.pub. cosign verifies a daemon image reference, not a raw
# tarball, so the sequence is necessarily load -> verify -> keep-or-remove:
# the image's bytes are in the daemon's store either way once `docker load`
# returns, but nothing *runs* it (no container starts) until this check
# passes, which is the actual property being protected. On failure, removes
# the loaded image and the caller must treat this as fatal (exit nonzero),
# not skip-and-continue.
_verify_orchestrator_image() {
  local loaded_ref="$1"
  if [[ ! -f "${SCRIPT_DIR}/cosign.pub" ]]; then
    err "cosign.pub not found in bundle -- cannot verify ${loaded_ref}, refusing to proceed"
    return 1
  fi
  if ! command -v cosign &>/dev/null; then
    err "cosign is not installed -- cannot verify ${loaded_ref}, refusing to proceed"
    return 1
  fi
  if ! COSIGN_PASSWORD="" cosign verify --key "${SCRIPT_DIR}/cosign.pub" --insecure-ignore-tlog "${loaded_ref}" &>/dev/null; then
    err "cosign verification FAILED for ${loaded_ref} -- refusing to install a tampered or unsigned orchestrator image"
    docker rmi "${loaded_ref}" &>/dev/null || true
    return 1
  fi
  log "cosign: verified ${loaded_ref}"
  return 0
}

# ── Render check results ──────────────────────────────────────────────────────
```

Then edit the `mode_install` loading loop (around line 715-725):

```bash
  step "4/10  Loading Docker images (air-gap safe -no pull)"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      info "Loading $(basename "$tar")..."
      docker load < "$tar"
      log "Loaded: $(basename "$tar")"
    done
  else
    warn "images/ directory not found -Docker will attempt to pull (requires internet)"
  fi
```

with:

```bash
  step "4/10  Loading Docker images (air-gap safe -no pull)"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      info "Loading $(basename "$tar")..."
      local load_output
      load_output=$(docker load < "$tar")
      echo "$load_output"
      if [[ "$(basename "$tar")" == bas-orchestrator-* ]]; then
        local loaded_ref
        loaded_ref=$(echo "$load_output" | grep -oP 'Loaded image: \K.*')
        if [[ -z "$loaded_ref" ]]; then
          err "Could not determine loaded image reference for $(basename "$tar") -- cannot verify it, aborting install"
          exit 1
        fi
        _verify_orchestrator_image "$loaded_ref" || { err "Orchestrator image failed verification -- installation aborted."; exit 1; }
      fi
      log "Loaded: $(basename "$tar")"
    done
  else
    warn "images/ directory not found -Docker will attempt to pull (requires internet)"
  fi
```

(`install.sh`'s own `err()` only prints — see line 68, `err() { echo -e "${RED}[FAIL]${NC} $*" >&2; }` — it never exits on its own; every call site in this file follows it with an explicit `exit 1`, same pattern used above.)

Then the identical treatment for `mode_upgrade`'s loop (around line 858-864):

```bash
  step "2/5  Loading new images"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      docker load < "$tar" && log "Loaded: $(basename "$tar")"
    done
  fi
```

with:

```bash
  step "2/5  Loading new images"
  local images_dir="${SCRIPT_DIR}/images"
  if [[ -d "$images_dir" ]]; then
    for tar in "${images_dir}"/*.tar; do
      [[ -f "$tar" ]] || continue
      local load_output
      load_output=$(docker load < "$tar")
      echo "$load_output"
      if [[ "$(basename "$tar")" == bas-orchestrator-* ]]; then
        local loaded_ref
        loaded_ref=$(echo "$load_output" | grep -oP 'Loaded image: \K.*')
        if [[ -z "$loaded_ref" ]]; then
          err "Could not determine loaded image reference for $(basename "$tar") -- cannot verify it, aborting upgrade"
          exit 1
        fi
        _verify_orchestrator_image "$loaded_ref" || { err "Orchestrator image failed verification -- upgrade aborted. The previous version is still running; nothing was replaced."; exit 1; }
      fi
      log "Loaded: $(basename "$tar")"
    done
  fi
```

- [ ] **Step 4: Run test to verify it passes**

Source the real functions and re-run the tampered-image scenario from Step 1:
```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
bash packaging/signing/cosign.sh --keygen <<< "y"
docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1

# Re-build and sign a REAL (untampered) image, confirm it verifies and loads:
docker build -q -t bas-orchestrator:cosign-task3-test -f /tmp/cosign-task3-test/Dockerfile /tmp/cosign-task3-test
bash packaging/signing/cosign.sh --sign bas-orchestrator:cosign-task3-test
docker save bas-orchestrator:cosign-task3-test -o /tmp/cosign-task3-test/images/bas-orchestrator-cosign-task3-test-signed.tar
docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1

SCRIPT_DIR="/tmp/cosign-task3-test"
cp packaging/signing/cosign.pub "${SCRIPT_DIR}/cosign.pub"
load_output=$(docker load < /tmp/cosign-task3-test/images/bas-orchestrator-cosign-task3-test-signed.tar)
echo "$load_output"
loaded_ref=$(echo "$load_output" | grep -oP 'Loaded image: \K.*')
echo "loaded_ref=${loaded_ref}"
COSIGN_PASSWORD="" cosign verify --key "${SCRIPT_DIR}/cosign.pub" --insecure-ignore-tlog "${loaded_ref}" && echo "VERIFY_OK"
```
Expected: `VERIFY_OK` printed, `loaded_ref` correctly parsed as `bas-orchestrator:cosign-task3-test`.

Then confirm the tampered case now fails correctly, using the real `_verify_orchestrator_image` function extracted from the edited file:
```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1
docker load < /tmp/cosign-task3-test/images/bas-orchestrator-cosign-task3-test-tampered.tar
SCRIPT_DIR="/tmp/cosign-task3-test" \
  bash -c '
    source <(sed -n "/^log()/,/^info()/p" packaging/compose/install.sh)
    source <(sed -n "/^_verify_orchestrator_image/,/^}/p" packaging/compose/install.sh)
    _verify_orchestrator_image "bas-orchestrator:cosign-task3-test"
  '
echo "exit=$?"
docker images bas-orchestrator:cosign-task3-test
```
Expected: `exit=1`, the `[FAIL] cosign verification FAILED ...` line printed to stderr (via the real `err` helper, sourced above), and `docker images` shows the tampered image was removed (`docker rmi` ran inside the function).

- [ ] **Step 5: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "fix(install): verify orchestrator image signature before loading it

install.sh's docker-load loop had no verification at all -- a tampered
or re-tagged orchestrator tarball loaded and would have been used
without any check. Both the fresh-install and upgrade loops now load,
parse the resulting image reference, and cosign-verify it against the
bundle's cosign.pub before the install/upgrade proceeds; a failed
verification removes the loaded image and aborts the whole script (no
skip flag). postgres/caldera/headless-shell images are untouched --
Audspect does not assert cosign provenance over those. Also adds cosign
to the existing prereq-check list, same pattern as the existing docker
check.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: `packaging/compose/setup.sh` — verify-before-use gate for the orchestrator image

> **SUPERSEDED during execution** — same `verify-blob`-before-`docker
> load` pattern as Task 3. Found a SECOND, separate non-interactive
> prereq-check loop the plan didn't know about (line ~1037-1045, its own
> inline `FAIL → exit 1` gate) in addition to `page_prereqs` — `
> check_cosign` registered in both. Real execution verified (happy path,
> 2 distinct failure modes, the load-never-reached ordering property, and
> the scope boundary — a corrupted postgres tar still lets the script
> continue via its preserved `|| true`). Committed as `3e9a5b6b`; full
> detail in
> `.superpowers/sdd/2026-10-03-cosign-image-signing-enforcement/progress.md`.
> The steps below are kept for historical record of the original
> (incorrect) design only.

**Files:**
- Modify: `packaging/compose/setup.sh` (prereq check list around line 403-405/994-996; `docker load` loop around line 527-533)

**Interfaces:**
- Consumes: same `_verify_orchestrator_image`-style check as Task 3, and the same bundle-relative `cosign.pub` (Task 1 produces this for `build.sh`'s bundle, which is the one `setup.sh` ships inside).
- Produces: nothing for a later task — leaf consumer, independent of Task 3 (different installer script, different bundle).

- [ ] **Step 1: Write the failing test**

Reuse the same tampered-image artifacts Task 3's Step 1 already built at `/tmp/cosign-task3-test/images/` (if that directory was cleaned up already, repeat Task 3 Step 1's image-build/tamper commands first). Confirm the *current* `setup.sh` loop has the same gap, plus the additional `|| true` that swallows even a `docker load` failure outright:

```bash
docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1
docker load < /tmp/cosign-task3-test/images/bas-orchestrator-cosign-task3-test-tampered.tar || true
echo "exit=$?"
docker images bas-orchestrator:cosign-task3-test
```
Expected: `exit=0` (the `|| true` always succeeds) and the tampered image is loaded with zero indication anything was wrong.

- [ ] **Step 2: Run test to verify it fails (confirms the gap)**

Run the Step 1 script. Expected output exactly as above.

- [ ] **Step 3: Edit `packaging/compose/setup.sh`**

Add the same `_check_cosign`-equivalent to this file's own naming convention (no underscore prefix, matching `check_docker`/`check_compose` already in this file) right after `check_compose` (around line 230):

```bash
check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    echo "PASS:Compose — $(docker compose version --short 2>/dev/null || echo 'v2')"
  elif command -v docker-compose &>/dev/null; then
    echo "WARN:Compose — docker-compose v1 found (v2 plugin recommended)"
  else
    NEED_COMPOSE=true
    echo "INST:Compose — not installed (will be auto-installed with Docker)"
  fi
}
```

with:

```bash
check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    echo "PASS:Compose — $(docker compose version --short 2>/dev/null || echo 'v2')"
  elif command -v docker-compose &>/dev/null; then
    echo "WARN:Compose — docker-compose v1 found (v2 plugin recommended)"
  else
    NEED_COMPOSE=true
    echo "INST:Compose — not installed (will be auto-installed with Docker)"
  fi
}

# The orchestrator image ships cosign-signed (packaging/build.sh); this
# installer must be able to verify that signature before loading it. No
# auto-install path like Docker's -- cosign is specific enough that
# silently installing it on an operator's box is not appropriate here.
check_cosign() {
  if ! command -v cosign &>/dev/null; then
    echo "FAIL:Cosign — not installed (required to verify the orchestrator image before install; see https://docs.sigstore.dev/cosign/system_config/installation/)"
    return
  fi
  if [[ ! -f "${SCRIPT_DIR}/cosign.pub" ]]; then
    echo "FAIL:Cosign — public key not found in bundle at ${SCRIPT_DIR}/cosign.pub (corrupt or incomplete release bundle)"
    return
  fi
  echo "PASS:Cosign — $(cosign version 2>/dev/null | grep -oP 'GitVersion:\s*\K\S+' || echo 'installed')"
}
```

Register it at both call sites:

```bash
    check_disk "$DEFAULT_INSTALL_DIR"
    check_docker
    check_compose
```

with:

```bash
    check_disk "$DEFAULT_INSTALL_DIR"
    check_docker
    check_compose
    check_cosign
```

(applies to both line ~403-405 and line ~994-996 — same three-line pattern repeated; update both).

Add the shared verify helper near `check_cosign` (same logic as Task 3's, this file's own helper-naming convention, no underscore prefix):

```bash
_verify_orchestrator_image() {
  local loaded_ref="$1"
  if [[ ! -f "${SCRIPT_DIR}/cosign.pub" ]]; then
    err "cosign.pub not found in bundle -- cannot verify ${loaded_ref}, refusing to proceed"
    return 1
  fi
  if ! command -v cosign &>/dev/null; then
    err "cosign is not installed -- cannot verify ${loaded_ref}, refusing to proceed"
    return 1
  fi
  if ! COSIGN_PASSWORD="" cosign verify --key "${SCRIPT_DIR}/cosign.pub" --insecure-ignore-tlog "${loaded_ref}" &>/dev/null; then
    err "cosign verification FAILED for ${loaded_ref} -- refusing to install a tampered or unsigned orchestrator image"
    docker rmi "${loaded_ref}" &>/dev/null || true
    return 1
  fi
  log "cosign: verified ${loaded_ref}"
  return 0
}
```

(`setup.sh`'s own `err()` only prints — see line 65, `err() { echo -e "${RED}[✗]${NC} $*" >&2; }` — same non-exiting convention as `install.sh`; every call site below follows it with an explicit `exit 1`.)

Then edit the loading loop (around line 527-533):

```bash
  _step 50 "Loading Docker images..."
  if [[ "$OFFLINE" == "true" ]]; then
    for img in "${SCRIPT_DIR}"/images/*.tar.gz "${SCRIPT_DIR}"/images/*.tar; do
      [[ -f "$img" ]] || continue
      _step 55 "Loading $(basename "$img")..."
      docker load < "$img" || true
    done
  else
```

with:

```bash
  _step 50 "Loading Docker images..."
  if [[ "$OFFLINE" == "true" ]]; then
    for img in "${SCRIPT_DIR}"/images/*.tar.gz "${SCRIPT_DIR}"/images/*.tar; do
      [[ -f "$img" ]] || continue
      _step 55 "Loading $(basename "$img")..."
      if [[ "$(basename "$img")" == bas-orchestrator-* ]]; then
        local load_output
        load_output=$(docker load < "$img") || { err "Failed to load $(basename "$img")"; exit 1; }
        echo "$load_output"
        local loaded_ref
        loaded_ref=$(echo "$load_output" | grep -oP 'Loaded image: \K.*')
        if [[ -z "$loaded_ref" ]]; then
          err "Could not determine loaded image reference for $(basename "$img") -- cannot verify it, aborting install"
          exit 1
        fi
        _verify_orchestrator_image "$loaded_ref" || { err "Orchestrator image failed verification -- installation aborted."; exit 1; }
      else
        docker load < "$img" || true
      fi
    done
  else
```

Note the orchestrator branch does **not** carry the `|| true` the other images keep — this is the Review Focus #5 scope boundary: postgres/caldera/headless-shell keep today's lenient behavior unchanged, only the orchestrator image becomes a hard gate.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
SCRIPT_DIR="/tmp/cosign-task3-test"
cp packaging/signing/cosign.pub "${SCRIPT_DIR}/cosign.pub" 2>/dev/null || bash packaging/signing/cosign.sh --keygen <<< "y" && cp packaging/signing/cosign.pub "${SCRIPT_DIR}/cosign.pub"

docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1
SCRIPT_DIR="${SCRIPT_DIR}" bash -c '
  source <(sed -n "/^log()/,/^err()/p" packaging/compose/setup.sh)
  source <(sed -n "/^_verify_orchestrator_image/,/^}/p" packaging/compose/setup.sh)
  docker load < /tmp/cosign-task3-test/images/bas-orchestrator-cosign-task3-test-tampered.tar
  _verify_orchestrator_image "bas-orchestrator:cosign-task3-test"
  echo "exit=$?"
'
docker images bas-orchestrator:cosign-task3-test
```
Expected: `exit=1`, `[✗] cosign verification FAILED ...` on stderr (via the real `err` helper, sourced above), tampered image removed from `docker images`.

Then the happy path with the real signed tar from Task 3's Step 4:
```bash
docker rmi bas-orchestrator:cosign-task3-test 2>&1 | tail -1
SCRIPT_DIR="/tmp/cosign-task3-test" bash -c '
  source <(sed -n "/^log()/,/^err()/p" packaging/compose/setup.sh)
  source <(sed -n "/^_verify_orchestrator_image/,/^}/p" packaging/compose/setup.sh)
  load_output=$(docker load < /tmp/cosign-task3-test/images/bas-orchestrator-cosign-task3-test-signed.tar)
  echo "$load_output"
  loaded_ref=$(echo "$load_output" | grep -oP "Loaded image: \K.*")
  _verify_orchestrator_image "$loaded_ref"
  echo "exit=$?"
'
```
Expected: `cosign: verified bas-orchestrator:cosign-task3-test`, `exit=0`.

Clean up all throwaway test artifacts from Tasks 3 and 4:
```bash
rm -rf /tmp/cosign-task3-test /tmp/cosign-test-keys /tmp/cosign-task1-dockerfile
docker rmi bas-orchestrator:cosign-task3-test bas-orchestrator:cosign-task1-test 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "fix(install): verify orchestrator image signature before loading it in setup.sh

Same fix as install.sh (this commit's sibling): the docker-load loop had
no verification, and additionally swallowed load failures outright via
|| true for every image including the orchestrator. The orchestrator
image is now singled out of that loop for a hard verify-then-load gate
(no || true for it specifically); postgres/caldera/headless-shell keep
today's lenient behavior unchanged. Also adds cosign to the existing
prereq-check list at both call sites, same pattern as the existing
docker check.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Final Verification

- [ ] All 4 tasks' individual test commands pass (re-run if time has passed since each task's own Step 4).
- [ ] Full real chain, end to end: run `packaging/build.sh` for real with a real key pair, confirm the produced bundle's `images/bas-orchestrator-*.tar.gz` passes `cosign verify` standalone; then simulate `setup.sh`'s load+verify against that exact tarball.
- [ ] Full real chain for the Windows path: run `packaging/windows-build.ps1 -WindowsSigningRequired $true` with the same key pair, confirm the produced `images/bas-orchestrator-*.tar` passes `cosign verify` standalone; then simulate `install.sh`'s load+verify against that exact tarball.
- [ ] `git status` is clean (no stray `/tmp/cosign-*` artifacts outside `/tmp`, no leftover `cosign.key`/`cosign.pub` test files committed, no dangling `bas-orchestrator:cosign-task*` Docker images or tags).
- [ ] Confirm `packaging/signing/cosign.key` is `.gitignore`d (it should already be, per the existing convention `cosign.sh` itself documents) — `git check-ignore -v packaging/signing/cosign.key`.
- [ ] Vault note [[Docker image signing (cosign)]] updated to closed afterward (outside this plan, matching how D1/C2/C3/C4/D2 were closed in this same session — not a plan task), and the Group D roadmap memory updated to reflect cosign closed, roadmap moving to its final verification step.
