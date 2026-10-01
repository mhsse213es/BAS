# C2 — Orchestrator Agent-Download Artifact Provenance Design

## Problem

The orchestrator's own Docker image (`orchestrator/Dockerfile`) builds its
own copies of the Windows, macOS, and Linux agent binaries — from the same
source trees (`agent/`, `agent-legacy/`, `installer/`) that
`packaging/windows-build.ps1` also builds — entirely inside Linux build
stages, landing in a `distroless` final image with no Windows signing
tooling available at all. `GET /api/agents/download/{platform}`
(`orchestrator/internal/api/handlers.go:1154`) serves these Docker-built
files directly, verified only against an RSA-signed content-integrity
manifest (`BINARIES.sha256` — proves "these are the bytes the image was
built with," not OS-native publisher trust).

D1 (`docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md`)
added Authenticode signing to `windows-build.ps1`'s own output — the
customer ZIP's Windows executables are now genuinely signed. But an
administrator who instead uses the running orchestrator's own download
page (confirmed live and advertised: `windows-amd64-setup` is the
dashboard's primary, most-prominent Windows download button,
`orchestrator/wwwroot/index.html:1922`) still receives a completely
separate, unsigned binary built inside the Docker image. Two independent
builds of "the same" software, one signed, one not — the exact outcome
the user flagged as unacceptable: *"windows-build.ps1 → signed agent,
orchestrator → separately built unsigned agent, which would recreate the
same problem later."*

A second, independent bug was found while scoping this: `docker save
$OrchestratorTag` (the call that produces the `.tar` `install.sh` actually
`docker load`s on the customer's machine — confirmed, it never rebuilds
from the Dockerfile) runs at `windows-build.ps1`'s early "step 4"
(line 231), *before* the existing `BINARIES.sha256.sig` image-patch step
("step 5c", line ~512) that mutates the image after the fact. The shipped
tar therefore never contains that patch — the local Docker daemon's tag
gets mutated, the already-saved tar does not. Any fix that patches the
image after signing inherits this defect unless the save is also moved.
Explicit decision: fold this fix into the same spec as C2, since C2's own
remediation requires it to work at all.

## Goals

- The orchestrator's download endpoint serves the *exact same signed
  bytes* as the customer ZIP for every artifact where a signed equivalent
  exists — one provenance chain, multiple delivery mechanisms, not two
  independent builds.
- No fallback to an unsigned artifact on a customer/release build: if
  signing was required and the patch can't be verified, the build fails
  closed (`Err`), the same way D1's own release gate does.
- Reuse the existing patch-image mechanism and the existing
  `$WindowsSigningRequired` flag — no new build platform, no Dockerfile
  restructuring, no external artifact repository (this product ships as
  an offline ZIP to air-gapped on-prem customers; a live fetch-from-store
  model doesn't fit that constraint).
- C2 *consumes* the signed artifacts D1 already produces. It introduces
  no second signing mechanism.

## Non-goals

- **macOS.** No macOS artifact exists today with a signed equivalent to
  inject (D1-macOS is prepared-but-not-activated, and the macOS scripts
  need a rework for bare Mach-O binaries before they can sign anything —
  see D1's review finding I8). The orchestrator's `darwin-amd64`/
  `darwin-arm64` downloads remain Docker-built and unsigned after this
  spec, same as today. Revisit when D1-macOS is activated.
- **Linux.** No OS-native signing mechanism applies (established D1
  boundary). Linux raw binaries are untouched by this spec.
- **C3 (manifest excludes zip/package downloads).** A real, separate,
  pre-existing bug found while reading this code: `BINARIES.sha256` lists
  only the 6 raw binaries, never the `.zip`/`.deb`/`.rpm` files the same
  endpoint also serves, so a verified-manifest deployment should
  currently refuse to serve any of them. This is a release-artifact
  inventory / download-authorization bug, orthogonal to whether the
  checked bytes are OS-signed. Logged as its own finding
  (`C3 - BINARIES.sha256 manifest excludes zip and package downloads` in
  the vault). Not fixed here. This spec's manifest-regeneration logic
  (below) preserves the existing 6-entry scope; it does not expand or
  narrow it.
- **Docker/cosign image signing.** A separate, already-acknowledged future
  finding (the orchestrator image itself has optional, silently-skippable
  cosign signing in `build.sh`). Not touched here.
- **Restructuring `orchestrator/Dockerfile`** to remove its own
  Windows/macOS build stages (Approach B, rejected during design — bigger
  surgery than this problem needs, and removes the dev-build fallback
  path).

## Architecture

```
windows-build.ps1
      │
      ├── build Windows artifacts            (5a, 5a2 — unchanged)
      ├── Authenticode-sign them              (5d — D1, unchanged)
      ├── re-verify signatures                 (new, this spec)
      │
      ▼
patch orchestrator image                       (extends existing 5c)
      │
      ├── inject exact signed Windows artifacts
      ├── rebuild Windows setup ZIP from signed installer
      ├── regenerate BINARIES.sha256 (changed entries only)
      ├── RSA-sign the regenerated manifest    (unchanged mechanism)
      │
      ▼
docker save                                     (moved: new position)
      │
      ▼
customer ZIP / offline delivery ─────┬──────────────────────┐
                                      │                      │
                              (inside the ZIP)      orchestrator download
                                                      endpoint (after
                                                      install.sh docker load)
                                      │                      │
                                      └── same signed bytes ──┘
```

One signing operation (D1's `Invoke-AuthenticodeSigning`), one set of
signed files on disk, one patch into the one image that both delivery
paths ultimately come from.

## Gating flag

Reuse `$WindowsSigningRequired` exactly as D1 defined it
(`packaging/windows-build.ps1` param block: `[Nullable[bool]]`, defaults
to `$IsCustomerBuild`, i.e. `-Customer`/`-CustomerID` both set). No new
inferred-environment heuristic.

- `$WindowsSigningRequired = $true` (customer/release build): any failure
  in the steps below — a signed artifact missing, re-verification
  failing, the patch build failing — is `Err` (abort, matches D1's
  fail-closed release-gate behavior). No fallback to the Docker-built
  unsigned copy.
- `$WindowsSigningRequired = $false` (dev build, no cert): `Warn` and
  continue on any failure. The orchestrator image keeps whatever the
  Docker build stages produced (today's status quo, unsigned) — this is
  the accepted, unchanged dev-build path, not a regression.

## Implementation

### New file: `packaging/signing/sign-orchestrator-artifacts.ps1`

Two functions, mirroring D1's separation of a pure/testable core from an
integration-heavy orchestration wrapper (the same split that let D1's
library code get real Pester coverage while `windows-build.ps1` itself is
verified end-to-end).

**`Update-BinaryManifestEntries(ManifestContent, Replacements)`** — pure,
no I/O, no Docker:
- `ManifestContent`: the full text of a `sha256sum`-format manifest
  (`<hash><two spaces><filename>` per line).
- `Replacements`: a hashtable `{filename -> new sha256 hex hash}`.
- Returns the manifest text with only the lines whose filename matches a
  key in `Replacements` rewritten to the new hash; every other line
  (including ones for files this spec never touches — the 4 Linux/darwin
  raw binaries) is returned byte-identical, same ordering, same line
  endings. A filename in `Replacements` with no matching line in the
  input is an error (`throw`) — a mismatch here means the manifest's
  known shape changed and this function's assumptions need revisiting,
  not a silent no-op.
- This is the piece C3 warns must not be touched: it preserves the
  existing 6-line scope exactly, never adding or removing entries.

**`Update-OrchestratorAgentArtifacts(OrchestratorTag, OutDir, Version, OrchestratorDir)`**
— the orchestration entry point called from `windows-build.ps1`. Like
D1's own `Invoke-AuthenticodeSigning`, this function takes no
"required" flag and makes no Err-vs-Warn decision itself: it either
completes the patch and returns `$true`, or stops at the first problem,
reports it via `Write-Error -ErrorAction Continue` (the same
caller-EAP-safety pattern D1's fix-pass established — see D1 review
finding I1), and returns `$false`. `windows-build.ps1`'s call site is the
only place `$WindowsSigningRequired` is read, exactly mirroring the
existing `Invoke-AuthenticodeSigning` call site in step 5d.
`OrchestratorDir` is passed through for step 6's RSA signing only — it
`Push-Location`s there and calls `go run scripts/signer.go sign
private_key.pem ...`, the exact same relative-path convention the
existing (unmodified) step 5c signing call already uses. No new signing
key or path configuration is introduced.

1. Build the expected signed-artifact paths from `$OutDir`:
   - `bas-agent-windows-amd64.exe`
   - `bas-agent-windows-legacy-amd64.exe`
   - `bas-agent-windows-legacy-amd64-setup.zip`
   - `BASAgent-Setup-$Version.exe`
2. For each, `Test-Path`; if any is missing, `Write-Error` naming it and
   `return $false` immediately — no partial patch attempt.
3. **Re-verify** each of the 4 files' Authenticode signature via
   `Test-AuthenticodeSignature` (dot-sourced from
   `verify-windows-signature.ps1`) before trusting any of them — defense
   in depth: this function must not assume step 5d's signing succeeded
   just because it ran earlier in the same script invocation. Any
   verification failure: `Write-Error` naming the file and reason,
   `return $false`.
4. Stage a patch context directory containing:
   - `bas-agent-windows-amd64.exe` ← copy of the signed file (exact name).
   - `bas-agent-windows-legacy-amd64.exe` ← copy of the signed file (exact
     name).
   - `bas-agent-windows-legacy-amd64-setup.zip` ← copy of the signed file
     (exact name; already contains the signed exe, per D1's C1 fix which
     moved this zip's creation to after signing).
   - `bas-agent-windows-amd64-setup.zip` ← **rebuilt**, not copied: copy
     `BASAgent-Setup-$Version.exe` to a temp file named `Audspect_Agent.exe`
     (matching the Dockerfile installer-stage's internal naming) and
     `Compress-Archive` it into this filename. This is the one artifact
     with no exact-name equivalent — same installer source
     (`installer/`), different packaging between the two pipelines.
5. Extract the manifest already pulled from the image in the existing
   step 5c flow (`docker cp ... /agents/BINARIES.sha256`, unchanged) and
   call `Update-BinaryManifestEntries` with:
   ```powershell
   @{
       "bas-agent-windows-amd64.exe"        = (Get-FileHash <signed path> -Algorithm SHA256).Hash.ToLower()
       "bas-agent-windows-legacy-amd64.exe" = (Get-FileHash <signed path> -Algorithm SHA256).Hash.ToLower()
   }
   ```
   Only these 2 of the manifest's 6 lines change. Write the result back
   to the staged `BINARIES.sha256` in the patch context.
6. RSA-sign the regenerated manifest the same way step 5c already does
   (`go run scripts/signer.go sign private_key.pem BINARIES.sha256`) —
   mechanism unchanged, just signing the updated content. Copy the `.sig`
   into the patch context.
7. Write the patch context's `Dockerfile`:
   ```dockerfile
   FROM <OrchestratorTag>
   COPY bas-agent-windows-amd64.exe /agents/bas-agent-windows-amd64.exe
   COPY bas-agent-windows-legacy-amd64.exe /agents/bas-agent-windows-legacy-amd64.exe
   COPY bas-agent-windows-legacy-amd64-setup.zip /agents/bas-agent-windows-legacy-amd64-setup.zip
   COPY bas-agent-windows-amd64-setup.zip /agents/bas-agent-windows-amd64-setup.zip
   COPY BINARIES.sha256 /agents/BINARIES.sha256
   COPY BINARIES.sha256.sig /agents/BINARIES.sha256.sig
   ```
   This **replaces** today's separate sig-only patch block in step 5c
   (same `FROM $OrchestratorTag` + `docker build -q -t $OrchestratorTag`
   pattern, now carrying 6 `COPY` lines instead of 1) — one patch, not
   two sequential ones.
8. `docker build -q -t $OrchestratorTag $patchCtx`. Non-zero exit:
   `Write-Error` with the build output, `return $false`.
9. Clean up the patch context directory.
10. Return `$true` on success.

### `packaging/windows-build.ps1` changes

- Dot-source `packaging/signing/sign-orchestrator-artifacts.ps1` near the
  other signing dot-sources (alongside `sign-windows.ps1` at the existing
  "-- 5d" section).
- Replace step 5c's existing standalone sig-only patch block (lines
  ~507–524 today) with a call to `Update-OrchestratorAgentArtifacts`
  (no `$WindowsSigningRequired` parameter — see above). The call site
  alone reads `$WindowsSigningRequired` and branches on the boolean
  result: `Err` if required, `Warn` if not — the exact same shape as
  the existing `Invoke-AuthenticodeSigning` call site in step 5d
  (`if (-not $signed -and $WindowsSigningRequired) { Err ... } elseif
  (-not $signed) { Warn ... }`).
- **Save-ordering fix:** remove the orchestrator-specific block (today's
  lines 230–234: `Log "Saving $OrchestratorTag..."` /
  `docker save $OrchestratorTag -o ...` / the size-log) from step 4
  entirely. The other three images' saves (postgres, headless-shell,
  caldera — lines 236–265) are untouched and stay in step 4, since
  nothing in this spec changes them. Insert the same orchestrator-save
  block immediately after the new `Update-OrchestratorAgentArtifacts`
  call (i.e., after the patch — whether it succeeded, was skipped as
  not-required, or is a dev build with no signing at all — the image
  under `$OrchestratorTag` is final by that point either way, so exactly
  one save call covers every path).

## Testing

**`packaging/signing/sign-orchestrator-artifacts.Tests.ps1`** (new Pester
file, no Docker required for this part):
- `Update-BinaryManifestEntries` replaces only the targeted lines,
  leaves every other line byte-identical (construct a small 6-line fake
  manifest, replace 2, assert the other 4 are untouched and the 2 match
  the new hashes).
- `Update-BinaryManifestEntries` throws when a replacement key has no
  matching line in the input (the "manifest shape changed" guard).
- `Update-BinaryManifestEntries` preserves line order and the
  `sha256sum`-compatible `<hash><two spaces><filename>` format exactly.

**`packaging/signing/verify-orchestrator-artifacts.Tests.ps1`** (new
Pester file, Docker required — this is the "endpoint-level test"
the finding asked for, run against the artifact the endpoint would
actually serve rather than a live HTTP call, since nothing in this test
environment can run the full orchestrator + its download route):
- Build a minimal throwaway image tagged like `$OrchestratorTag` (reuse
  or build a tiny fixture image with the right `/agents/` layout — not
  the full multi-stage orchestrator Dockerfile, which would make this
  test as slow as a full build; a `FROM scratch` or `FROM alpine` fixture
  with a placeholder `/agents/bas-agent-windows-amd64.exe` is enough to
  exercise the patch itself).
- Sign a throwaway test binary (same self-signed-test-cert fixture
  pattern D1's own tests use), run `Update-OrchestratorAgentArtifacts`
  against the fixture image, then `docker create`/`docker cp` each of the
  4 artifacts back out and assert each one's `Get-AuthenticodeSignature`
  reports `Valid` with the expected signer thumbprint — proving the
  *served* bytes (post-patch, as they'd sit in the image) carry a valid
  signature, not just the pre-patch files on disk.
- A regression test for the Review Focus item below (partial injection).

**Review Focus** (failure modes the tests above should exercise
deliberately, matching this session's established plan-writing
discipline):
- **Partial injection failure.** If `docker build` for the patch fails
  after some files were already staged, the *previous* patched (or
  original) image tag must remain unchanged — `docker build -t` either
  fully succeeds and retags, or fails and leaves the prior tag alone;
  confirm this is actually true for the tagging scheme used here (no
  partial image state) rather than assuming it from Docker's general
  behavior.
- **Manifest replacement with a mismatched filename** (the `throw` case
  above) — must not silently produce a manifest that no longer matches
  what's in the image.
- **`$WindowsSigningRequired=$false` with artifacts present anyway** (a
  dev build run with a real `-WindowsCertThumbprint` set) — artifacts
  should still get injected and verified; "not required" means failures
  are tolerated, not that success is declined.
- **Re-verification catching a signature that step 5d itself didn't
  produce** (e.g., stale file from a previous run left on disk with a
  different cert) — must fail the same way as a genuinely-missing file.
- **`docker save` ordering** — an integration-level check (can be a
  manual E2E verification step in the implementation plan rather than a
  Pester test, matching how D1's own `windows-build.ps1` changes were
  verified) confirming the saved `.tar`, once `docker load`ed fresh,
  serves the newly-signed bytes — not just that the local daemon's tag
  was patched.

## Acceptance criteria

- A customer/release build (`-Customer`/`-CustomerID` set) with a valid
  signing certificate produces an orchestrator image whose `/agents/`
  directory, once extracted, shows all 4 Windows artifacts with
  `Get-AuthenticodeSignature` reporting `Valid` and the signer thumbprint
  matching the certificate used.
- The same build's `BINARIES.sha256` inside that image has exactly 2
  changed lines (the Windows raw exes) versus the Docker-build-only
  manifest, both lines matching the signed files' actual hashes, and its
  `.sig` verifies against the RSA public key.
- The saved `dist\images\bas-orchestrator-$Version.tar`, `docker load`ed
  into a clean daemon, reproduces the same signed artifacts — not the
  pre-patch ones.
- A dev build with no cert and no `-Customer`/`-CustomerID` behaves
  exactly as before this spec (`Warn`s, ships the Docker-built unsigned
  artifacts, does not abort).
- A customer/release build missing a signed artifact, or one that fails
  re-verification, aborts the whole build (`Err`) rather than silently
  shipping a patched-with-nothing or partially-patched image.

## Open items

- C3 (manifest excludes zip/package downloads) is logged, not scoped
  here — its remediation is independent future work.
- Darwin binaries remain unsigned in the orchestrator image after this
  spec; revisit once D1-macOS's bare-Mach-O rework (D1 review finding I8)
  is done and a real macOS artifact exists anywhere in this pipeline.
- The Dockerfile's own Windows/installer build stages
  (`agent-builder`/`installer-builder`/`agent-legacy-builder`'s Windows
  targets) are left in place as the dev-build fallback source — this
  means Windows binaries are still compiled twice per customer build (once
  cross-compiled in Alpine, once natively on the Windows host before
  signing). Accepted as the cost of Approach A; revisit only if build
  time becomes a real problem, per the rejected Approach B.
