# C3: BINARIES.sha256 Manifest Package Coverage — Design

## Problem

`GET /api/agents/download/{platform}` (`orchestrator/internal/api/handlers.go:1158`)
serves 11 distinct files across 11 platform keys (`agentFiles`, lines
1140-1152):

| Platform key | File | In `BINARIES.sha256` today? |
|---|---|---|
| `linux-amd64` | `bas-agent-linux-amd64` | yes |
| `linux-arm64` | `bas-agent-linux-arm64` | yes |
| `linux-amd64-deb` | `bas-agent-linux-amd64.deb` | **no** |
| `linux-arm64-deb` | `bas-agent-linux-arm64.deb` | **no** |
| `linux-amd64-rpm` | `bas-agent-linux-amd64.rpm` | **no** |
| `windows-amd64-setup` | `bas-agent-windows-amd64-setup.zip` | **no** |
| `windows-amd64` | `bas-agent-windows-amd64.exe` | yes |
| `windows-legacy-amd64-setup` | `bas-agent-windows-legacy-amd64-setup.zip` | **no** |
| `windows-legacy-amd64` | `bas-agent-windows-legacy-amd64.exe` | yes |
| `darwin-amd64` | `bas-agent-darwin-amd64` | yes |
| `darwin-arm64` | `bas-agent-darwin-arm64` | yes |

`DownloadAgent`'s integrity check (handlers.go:1194-1211) is correctly
fail-closed: when the manifest is loaded and a requested file is not
listed, it logs `[!!] TAMPER... refusing to serve` and returns 500.
Manifest loading is unconditional at boot (`cmd/server/main.go:374`) and
every Docker-built image bakes `BINARIES.sha256` in (`orchestrator/Dockerfile:154`).

**This is a live production defect, not a latent hardening gap.** In
every real deployment, the 5 unlisted artifacts — including the
dashboard's primary "Download Agent" button (`windows-amd64-setup`,
`wwwroot/index.html:1922`) and all three Linux package buttons
(`wwwroot/index.html:1967-1969`) — return `500 agent binary failed
integrity verification` on every request.

`TestDownloadAgent_RefusesBinaryMissingFromManifest`
(`download_integrity_test.go:103`) proves the refusal behavior itself is
intentional and correct. Nothing tests it against the real 11-artifact
set, so nothing caught that 5 of them are permanently in the refused
state.

**A second, related defect** (found while designing this fix, not yet
observed in the wild because it's masked by the first): the Windows
code-signing patch step
(`Update-OrchestratorAgentArtifacts`, `packaging/signing/sign-orchestrator-artifacts.ps1:42-196`)
already rebuilds and re-injects **newly signed** content for both setup
zips into the live orchestrator image (lines 110, 119, 165-168) as part
of a required (customer) build — but its `$replacements` map
(lines 137-140) only recomputes manifest hashes for the two raw `.exe`
files, not the two zips it just mutated. Once this fix adds the zips to
the manifest, a signed production build would ship a manifest entry
hashing the *pre-signing* zip bytes while serving the *post-signing*
bytes — reintroducing, for exactly those 2 platforms, the same class of
silent manifest/artifact mismatch C4 just closed for the raw agent exe.

## Goals

- Every artifact `DownloadAgent` can serve has a correct, current entry
  in the RSA-signed `BINARIES.sha256` manifest, in both an unsigned
  (dev/no-cert) build and a signed (customer/required) build.
- The Windows code-signing patch step keeps the 2 setup-zip manifest
  entries truthful after it rebuilds them; it leaves the 3 Linux package
  entries alone, since nothing in that step touches Linux artifacts.
- A build-time test exists that would have caught the original gap (all
  11 artifacts present and correctly hashed in the real Docker image),
  and a fast unit-level test exists that would have caught the handler
  ever starting to default-permit an unlisted platform.

## Non-goals

- No change to `DownloadAgent`'s fail-closed logic or error handling —
  it is already correct. This spec closes the manifest coverage gap
  that was defeating it, not its own behavior.
- No package-native verification mechanism (`dpkg-sig`, `rpm --sign`, or
  a zip-specific signature). All 11 artifacts use the same whole-file
  SHA-256-in-a-signed-manifest mechanism the existing 6 already use.
- No full live-stack HTTP/JWT/Postgres end-to-end boot test (would not
  materially improve detection of either defect above; deferred as a
  candidate for a future release-verification suite, not required here).
- No change to the top-level `BASAgent-Setup-$Version.exe` /
  `dist/bas-install-*.zip` delivery pipeline (C4's and the existing GPG
  bundle-signing path) — this spec is scoped to the orchestrator's live
  `/api/agents/download/{platform}` endpoint only.
- No change to `agentFiles` itself (the set of served artifacts) — this
  spec makes the manifest match what's already served, not changes what's served.

## Architecture

Two independent fixes, kept separate because they close two different
failure modes:

```
docker build (orchestrator/Dockerfile)
  agent-builder:         5 raw bins + 1 zip (bas-agent-windows-amd64-setup.zip)
  agent-legacy-builder:  1 raw bin + 1 zip (bas-agent-windows-legacy-amd64-setup.zip)
  packager:              2 .deb + 1 .rpm
         |
         v
  binaries-manifest stage (FIX 1: Dockerfile)
    COPY all 11 artifacts in (was: 6)
    sha256sum all 11 -> BINARIES.sha256          <- correct baseline for
         |                                           every build, signed or not
         v
  final image: /agents/{11 artifacts, BINARIES.sha256(.sig)}


windows-build.ps1 (customer/signed build only)
  Invoke-AuthenticodeSigning on bas-agent-windows-amd64.exe,
                                 bas-agent-windows-legacy-amd64.exe
  rebuild both setup zips around the now-signed exe/installer
         |
         v
  Update-OrchestratorAgentArtifacts (FIX 2: sign-orchestrator-artifacts.ps1)
    re-inject signed exes + rebuilt zips into the image (already does this)
    $replacements: now hashes the 2 exes AND the 2 rebuilt zips (was: 2 exes only)
    regenerate + RSA-sign BINARIES.sha256                <- correct baseline for
         |                                                   a signed build
         v
  final image: /agents/{11 artifacts (2 exe + 2 zip now signed), BINARIES.sha256(.sig)}
```

The 3 Linux packages are untouched by the second diagram — nothing in
`Update-OrchestratorAgentArtifacts` builds, signs, or re-injects them, so
their Fix-1 manifest entries are final the moment `docker build` completes,
signed build or not.

## Implementation

### Fix 1 — `orchestrator/Dockerfile`, `binaries-manifest` stage (lines 90-99)

```dockerfile
FROM alpine AS binaries-manifest
RUN mkdir /agents
COPY --from=agent-builder /agents/bas-agent-linux-amd64 /agents/bas-agent-linux-arm64 \
     /agents/bas-agent-windows-amd64.exe /agents/bas-agent-darwin-amd64 /agents/bas-agent-darwin-arm64 \
     /agents/bas-agent-windows-amd64-setup.zip \
     /agents/
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe \
     /agents-legacy/bas-agent-windows-legacy-amd64-setup.zip \
     /agents/
COPY --from=packager /packages/bas-agent-linux-amd64.deb /packages/bas-agent-linux-arm64.deb \
     /packages/bas-agent-linux-amd64.rpm \
     /agents/
RUN cd /agents && sha256sum \
      bas-agent-linux-amd64 bas-agent-linux-arm64 bas-agent-windows-amd64.exe \
      bas-agent-darwin-amd64 bas-agent-darwin-arm64 bas-agent-windows-legacy-amd64.exe \
      bas-agent-windows-amd64-setup.zip bas-agent-windows-legacy-amd64-setup.zip \
      bas-agent-linux-amd64.deb bas-agent-linux-arm64.deb bas-agent-linux-amd64.rpm \
    > /agents/BINARIES.sha256
```

This adds a new stage dependency (`binaries-manifest` now also depends on
`packager`). BuildKit resolves stage build order from the `COPY --from=`
graph, not textual position, so no reordering of the stage *definitions*
is required — `packager` already appears earlier in the file (lines
101-110).

The final image's own artifact `COPY` lines (154-158) are unchanged —
they already copy from `agent-builder`/`agent-legacy-builder`/`packager`
directly, the same sources `binaries-manifest` now also reads from. The
served bytes and the manifested bytes are hashes of the same literal
`COPY` source, per the stage's own existing comment (Dockerfile:86-89).

### Fix 2 — `packaging/signing/sign-orchestrator-artifacts.ps1`, `Update-OrchestratorAgentArtifacts`

Add the 2 setup zips to the `$artifacts` map (already-rebuilt paths,
computed earlier in the function) and to `$replacements`:

```powershell
$replacements = @{
    "bas-agent-windows-amd64.exe"              = (Get-FileHash -Path $artifacts["bas-agent-windows-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
    "bas-agent-windows-legacy-amd64.exe"       = (Get-FileHash -Path $artifacts["bas-agent-windows-legacy-amd64.exe"] -Algorithm SHA256).Hash.ToLower()
    "bas-agent-windows-amd64-setup.zip"        = (Get-FileHash -Path (Join-Path $patchCtx "bas-agent-windows-amd64-setup.zip") -Algorithm SHA256).Hash.ToLower()
    "bas-agent-windows-legacy-amd64-setup.zip" = (Get-FileHash -Path $artifacts["bas-agent-windows-legacy-amd64-setup.zip"] -Algorithm SHA256).Hash.ToLower()
}
```

`bas-agent-windows-amd64-setup.zip` is hashed from `$patchCtx` (where
`Compress-Archive` just rebuilt it, line 119) rather than from
`$artifacts`, since — unlike the legacy zip — it has no pre-existing
`$OutDir` source; it only ever exists as the freshly rebuilt copy.

No change to `Update-BinaryManifestEntries` itself (it already replaces
an arbitrary set of keyed lines; it just needs more keys), no change to
the RSA signing call (`go run scripts/signer.go`, line 152) or to the
`Dockerfile` heredoc that re-injects the patched image (lines 162-171) —
both already operate on "whatever `BINARIES.sha256` currently contains,"
and Fix 1 already guarantees the pre-patch manifest has lines for both
zips to replace. The 3 Linux package entries are never touched by this
function — they are absent from both `$artifacts` and `$replacements`,
exactly as before.

## Error handling

Unchanged from the existing conventions:

- `DownloadAgent`: unchanged. Fail-closed on anything unlisted or
  hash-mismatched remains correct; this spec removes the condition that
  was triggering it for legitimate artifacts, not the check itself.
- `Update-OrchestratorAgentArtifacts`: unchanged pattern — any new
  `Get-FileHash`/`Update-BinaryManifestEntries` call added for the 2 zips
  runs under the function's existing `$ErrorActionPreference='Continue'`
  + explicit native-output-capture discipline (established by C2's fix
  pass), and a missing zip at the point of hashing is already fatal via
  the function's existing pre-flight `Test-Path` loop (lines 65-70),
  which already includes `bas-agent-windows-legacy-amd64-setup.zip` and
  needs `bas-agent-windows-amd64-setup.zip`'s rebuilt path added
  alongside it.

## Testing

**Acceptance matrix** (every artifact, both build modes):

| Artifact | Fix-1 (Docker build) manifest | Fix-2 (signing patch) | Final manifest invariant |
|---|---|---|---|
| Windows EXE ×2 | correct | updated | `manifest hash == SHA-256(actual post-signing bytes)` |
| Windows setup ZIP ×2 | correct | updated | `manifest hash == SHA-256(actual post-signing bytes)` |
| Linux raw ×2 | correct | untouched | `manifest hash == SHA-256(actual bytes)` |
| Linux packages ×3 | correct | untouched | `manifest hash == SHA-256(actual bytes)` |
| macOS raw ×2 | correct | untouched | `manifest hash == SHA-256(actual bytes)` |

Each cell is an equality assertion against the real artifact's bytes at
that point in the pipeline — never "the hash changed" as a standalone
assertion, since a hypothetical signing operation could coincidentally
produce identical bytes and a changed-ness check would then pass for the
wrong reason.

**Tier A — Go, `orchestrator/internal/api/download_integrity_test.go`, every run:**

Extend the existing fixture-manifest pattern (`writeAgentAndManifest`,
currently hardcoded to one filename) to write real fixture files for all
11 `agentFiles` entries plus a manifest listing all 11, then
table-drive over `agentFiles` confirming: all-present → every platform
key serves 200 with matching bytes; one entry removed from the manifest
→ exactly that platform key is refused, the rest unaffected; one
fixture file's bytes changed without updating the manifest → refused;
an unknown platform key → 404 (existing `TestDownloadAgent_UnknownPlatform`
behavior, unaffected by this change).

**Tier B — PowerShell/Docker, build-time:**

Extend `packaging/signing/verify-orchestrator-artifacts.Tests.ps1`'s
existing "regenerates BINARIES.sha256... matching the actual signed
bytes" test (currently asserting only the 2 exe entries and that
darwin/linux-raw are untouched) to assert the full acceptance matrix
above: build the real image (or reuse the suite's existing fixture
image), extract `BINARIES.sha256` both *before* (asserting all 11
present with correct bytes — the Fix-1 check) and *after*
`Update-OrchestratorAgentArtifacts` runs (asserting the 2 exe + 2 zip
entries now match the newly-signed bytes, and the 3 Linux package + 2
macOS + 2 Linux-raw entries are byte-identical to before — the Fix-2
check). Same cost class as C4's own manual E2E dry run (~5-10 min per
full build); this is PowerShell/Pester, not a Go integration test, per
this file's existing precedent (no Go test here spins up a real Docker
image — `download_integrity_test.go` is pure fixture-file, handler-level,
and stays that way for Tier A).

No Tier C (full live-stack HTTP/JWT/Postgres boot test): explicitly
out of scope per Non-goals — would not materially improve detection of
either defect this spec closes, at substantially higher cost.

## Acceptance criteria

- `orchestrator/Dockerfile`'s `binaries-manifest` stage sha256sums all
  11 artifacts `DownloadAgent` can serve; the final image's
  `BINARIES.sha256` lists all 11 with hashes matching the real files, in
  an unsigned (dev/no-cert) build.
- `Update-OrchestratorAgentArtifacts` regenerates manifest entries for
  both setup zips, matching their post-signing bytes, in a signed
  (required/customer) build — without touching the 3 Linux package
  entries.
- Tier A test suite covers all 11 `agentFiles` entries' serve/refuse
  behavior against a realistic manifest.
- Tier B test suite covers the full acceptance matrix above against a
  real Docker build, both pre- and post-signing-patch.
- Full existing Pester suite (`sign-windows.Tests.ps1`,
  `verify-windows-signature.Tests.ps1`, `verify-release.Tests.ps1`,
  `sign-orchestrator-artifacts.Tests.ps1`,
  `verify-orchestrator-artifacts.Tests.ps1`) and the orchestrator's Go
  test suite remain green.

## Open items

None.
