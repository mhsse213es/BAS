# C4: Installer-Embedded Agent Signing Design

**Status:** Approved (brainstormed 2026-10-01)
**Finding:** `Audspect-Vault/14 Risks/C4 - Installer-embedded agent hash never matches BINARIES.sha256.md`
**Related:** C2 (orchestrator agent-download endpoint signing, closed), D1 (Windows Authenticode signing, closed), C3 (manifest excludes zip/package downloads, open — this finding must land before C3's own fix)

## Problem

`windows-build.ps1`'s section 5a builds the Windows agent **twice**, independently:

1. `go build ... -o "$InstallerDir\bas_agent.exe" .` — the copy `installer/embed.go`'s `//go:embed bas_agent.exe` bakes into `BASAgent-Setup-$Version.exe` at compile time. Never signed.
2. `go build ... -o "$OutDir\bas-agent-windows-amd64.exe" .` — the standalone artifact. Signed by D1's existing pipeline, and (since C2) the source of `BINARIES.sha256`'s `windows-amd64` hash.

These are two separate compilations of the same source, and build (1) doesn't even set `CGO_ENABLED` explicitly (relying on whatever the ambient default is) while build (2) does (`CGO_ENABLED=0`) — so they are not guaranteed byte-identical even before signing enters the picture. Once C2 made `BINARIES.sha256`'s `windows-amd64` entry the hash of the *signed* standalone exe, the installer's embedded copy — the exact binary that `installer/main.go` writes to disk and that becomes the long-running agent service — can never hash-match it. `agent.go`'s `SelfHash`/heartbeat reports that mismatch to `orchestrator/internal/api/handlers.go`'s `HashKnown` check, which quarantines the agent (`state = 'quarantined'`) on its very first heartbeat, whenever a verified manifest is loaded (`h.manifest.Loaded()` — the normal production case).

This is not visible today only because C3's own bug refuses to serve either setup zip at all once a manifest is loaded — **C3's fix must not land before this one**, or every agent installed via the dashboard's primary `windows-amd64-setup` download starts getting quarantined. The same mismatch already existed, unnoticed, in the customer ZIP's own direct installer path (independent of the orchestrator) since before C2.

`orchestrator/Dockerfile` (lines 34, 47) already avoids this exact problem: it builds the agent once, then `cp`'s that file to `./bas_agent.exe` before building its own (unsigned) installer. `windows-build.ps1` should follow the same pattern, with a sign step inserted between the build and the embed.

## Goals

- The embedded agent `installer/embed.go` bakes into `BASAgent-Setup-$Version.exe` and the standalone `bas-agent-windows-amd64.exe` artifact must be byte-identical, signed once, by construction — not verified-equal after two independent builds.
- `BINARIES.sha256`'s `windows-amd64` entry must describe a binary that an agent installed via *either* distribution path (customer ZIP's own installer, or the orchestrator-rebuilt setup zip C2 already produces) will actually report in its heartbeat.
- A required (customer) build fails closed if this ever breaks again; the invariant is cheap enough to assert on every build, dev or customer.
- No changes to C2's code (`sign-orchestrator-artifacts.ps1`, `Update-OrchestratorAgentArtifacts`) or to the Dockerfile. No changes to the legacy agent build (`agent-legacy/`, go1.20.14) — it isn't embedded by anything and has no equivalent mismatch.

## Non-goals

- C3 (manifest excludes zip/.deb/.rpm) — separately scoped, must land *after* this finding, not touched here.
- Reproducible/deterministic builds in general (matching the Dockerfile's own `CGO_ENABLED=0` explicitly is a small hardening step here, not a broader reproducibility initiative).
- Any change to how `agent.go`'s `SelfHash` or `handlers.go`'s `HashKnown`/quarantine logic works — this fix makes the two hashes match; it doesn't touch the comparison itself.

## Architecture

Current order (`windows-build.ps1` section 5a, approx. lines 260-343):
```
build agent -> installer\bas_agent.exe   (unsigned, embed source)
build installer (embeds bas_agent.exe)   -> $OutDir\BASAgent-Setup-$Version.exe
build agent AGAIN -> $OutDir\bas-agent-windows-amd64.exe   (standalone)
... (later, section 5d) sign all three independently
```

New order:
```
dot-source sign-windows.ps1              (moved earlier, from section 5d)
build agent ONCE -> installer\bas_agent.exe
sign installer\bas_agent.exe             (NEW — same cert/required semantics as the existing bulk-sign loop)
build installer (embeds the NOW-SIGNED bytes) -> $OutDir\BASAgent-Setup-$Version.exe
copy installer\bas_agent.exe -> $OutDir\bas-agent-windows-amd64.exe   (replaces the second build)
assert Get-FileHash of both copies are equal -> Err (unconditional) if not
... (section 5d, unchanged) sign BASAgent-Setup-$Version.exe and bas-agent-windows-legacy-amd64.exe;
    bas-agent-windows-amd64.exe is EXCLUDED from this loop (already signed above) but still
    included in the list passed to step 7c's release-verification audit.
```

No change to the Dockerfile (which already follows this pattern, unsigned) or to C2's image-patching code (it consumes `$OutDir\bas-agent-windows-amd64.exe` and `$OutDir\BASAgent-Setup-$Version.exe` exactly as it does today — both are still present at the same paths, just now actually consistent with each other).

## Implementation

### Step 1: Move the `sign-windows.ps1` dot-source earlier

Move (not duplicate) the line
```powershell
. "$RepoRoot\packaging\signing\sign-windows.ps1"
```
from its current position at the top of section 5d to immediately before section 5a's agent build (before the current line 288, `Push-Location $AgentDir`). `verify-windows-signature.ps1`'s dot-source stays where it is today (section 5d), since nothing before that point needs `Test-AuthenticodeSignature`.

### Step 2: Sign the agent binary before the installer embeds it

Immediately after the existing agent build (today's lines 288-303, output unchanged at `installer\bas_agent.exe`), add `$env:CGO_ENABLED = "0"` to the existing `$env:GOOS`/`$env:GOARCH` assignment (line 289) for parity with the Dockerfile, then insert:

```powershell
# C4: sign the agent binary HERE, before the installer embeds it via
# go:embed, so the installer's embedded copy and the standalone artifact
# below are the exact same signed bytes -- not two independent builds
# that happen to both get signed later. Mirrors the Dockerfile's own
# build-once-then-cp pattern (orchestrator/Dockerfile:34,47), which never
# had this problem because it only ever builds the agent once.
if ($WindowsCertThumbprint) {
    $agentSigned = Invoke-AuthenticodeSigning -Path "$InstallerDir\bas_agent.exe" -CertThumbprint $WindowsCertThumbprint
    if (-not $agentSigned -and $WindowsSigningRequired) {
        Err "Authenticode signing failed for installer\bas_agent.exe and Windows signing is required for this build."
    } elseif (-not $agentSigned) {
        Warn "Authenticode signing failed for installer\bas_agent.exe (not required for this build -- continuing)."
    } else {
        Log "  installer\bas_agent.exe signed (embedded by the installer build below)."
    }
} elseif ($WindowsSigningRequired) {
    Err "Windows signing is required for this build (customer build) but -WindowsCertThumbprint / BAS_WINDOWS_CERT_THUMBPRINT is not set."
} else {
    Warn "No Windows signing certificate configured -- installer\bas_agent.exe will not be signed (dev build, not required)."
}
```

### Step 3: Replace the second build with a copy, and assert equality

Replace the existing "Also build standalone Windows agent binary" block (today's lines 330-343: `Push-Location $AgentDir` ... second `go build` ... `Pop-Location`) with:

```powershell
# Also stage the standalone Windows agent artifact (for manual / side-by-side
# deploy). Copied from the already-signed installer\bas_agent.exe, not
# rebuilt -- see the C4 comment above. A second independent build here
# would silently reintroduce the exact mismatch this fix removes (even
# with identical source and flags, re-signing a second time would embed a
# different RFC 3161 timestamp token and the two files would diverge).
Log "Staging standalone Windows agent binary..."
Copy-Item "$InstallerDir\bas_agent.exe" "$OutDir\bas-agent-windows-amd64.exe" -Force
if (-not (Test-Path "$OutDir\bas-agent-windows-amd64.exe")) {
    Warn "Standalone Windows agent staging failed."
} else {
    $wSizeMB = [math]::Round((Get-Item "$OutDir\bas-agent-windows-amd64.exe").Length / 1MB, 1)
    Log "  bas-agent-windows-amd64.exe (${wSizeMB}MB)"

    # C4's core invariant: the embed source and the standalone copy must be
    # byte-identical. Unconditional (not gated by $WindowsSigningRequired) --
    # this is a build-construction fact, not a signing policy, and under
    # this design it cannot legitimately fail.
    $embedHash = (Get-FileHash -Path "$InstallerDir\bas_agent.exe" -Algorithm SHA256).Hash
    $standaloneHash = (Get-FileHash -Path "$OutDir\bas-agent-windows-amd64.exe" -Algorithm SHA256).Hash
    if ($embedHash -ne $standaloneHash) {
        Err "installer\bas_agent.exe and bas-agent-windows-amd64.exe diverged after a copy -- this should be structurally impossible; investigate before shipping."
    }
}
```

### Step 4: Exclude the pre-signed standalone from the bulk-sign loop, keep it in the audit list

At the existing `$WindowsArtifactsToSign` definition (today's lines 395-399), keep it unchanged (still the full 3-file list — this is what step 7c's `Invoke-ReleaseVerification` audits, and the standalone exe deserves a verification record there even though it isn't re-signed). Add a second, signing-loop-only list immediately after it:

```powershell
# bas-agent-windows-amd64.exe was already signed above, before the
# installer embedded it (C4) -- signing it again here would embed a
# fresh RFC 3161 timestamp and break the byte-identity that fix
# depends on. $WindowsArtifactsToSign (the full list) still carries it
# through to step 7c's release-verification audit; this list is only
# for the loop immediately below.
$WindowsArtifactsToSignNow = @($WindowsArtifactsToSign | Where-Object { $_ -notlike "*bas-agent-windows-amd64.exe" })
```

Change the loop's header and iteration target (today's lines 401-410) from `$WindowsArtifactsToSign` to `$WindowsArtifactsToSignNow`:

```powershell
if ($WindowsCertThumbprint) {
    Log "Signing $($WindowsArtifactsToSignNow.Count) Windows executable(s)..."
    foreach ($artifact in $WindowsArtifactsToSignNow) {
        ...
```

The `elseif ($WindowsSigningRequired) { Err ... }` / `else { Warn ... }` branches around the loop (today's lines 411-415) are unchanged.

## Error handling / gating semantics

Identical to the existing D1 convention, applied one step earlier for this one file: cert present + sign succeeds → proceed; cert present + sign fails → `Err` if `$WindowsSigningRequired`, else `Warn` and continue with an unsigned embed source (dev-build fallback, matching today's behavior exactly); no cert + required → `Err`; no cert + not required → `Warn`, continue unsigned. The hash-equality assertion in Step 3 is the one new unconditional `Err` — it is not a signing-policy branch, it is a build-integrity tripwire that should never fire under this design.

## Testing

No Pester harness for `windows-build.ps1` itself, matching D1/Task 3's established precedent. Verify via a real end-to-end build:

1. Generate and trust a throwaway test certificate (same pattern as D1/C2's own verification).
2. Run with `-WindowsSigningRequired $true` and the test cert. Expect: completes; logs `installer\bas_agent.exe signed...`; the hash-equality assertion does not fire.
3. Extract (`docker create`/`docker cp`, same technique C2's own verification uses) the orchestrator-served `bas-agent-windows-amd64.exe` from the live image and confirm `Get-AuthenticodeSignature` is `Valid` with the expected thumbprint (re-confirms C2's own patch still works, now with correctly-matching bytes).
4. Confirm `Get-FileHash` of `$OutDir\bas-agent-windows-amd64.exe` equals `Get-FileHash` of `installer\bas_agent.exe` (captured before cleanup) — the core invariant, checked directly rather than only trusting the build's own internal assertion.
5. Run a bare dev build with no certificate at all (`-GpgSigningRequired $false`, no `-WindowsCertThumbprint`). Expect: completes; both copies are unsigned; no `Err`.
6. Clean up: test cert from all 3 stores, `dist\` output, image tags, any `orchestrator/agents/BINARIES.sha256(.sig)` test pollution via `git checkout --`.

## Acceptance criteria

- `installer\bas_agent.exe` (the `go:embed` source) and `$OutDir\bas-agent-windows-amd64.exe` (the standalone artifact) are byte-identical on every build, dev or customer, verified by an unconditional in-script assertion.
- Both carry a valid Authenticode signature whenever a certificate is configured, with the expected thumbprint.
- A required build with no certificate, or whose signing fails, aborts (`Err`) before packaging — unchanged from existing D1 behavior, now also covering this one additional signing point.
- A bare dev build with no certificate still completes successfully, both copies unsigned — unchanged from today.
- No changes to `sign-orchestrator-artifacts.ps1`, `Update-OrchestratorAgentArtifacts`, the Dockerfile, or the legacy agent build path.
- The release-verification audit (`release-verification.json`, step 7c) still records a per-artifact result for `bas-agent-windows-amd64.exe`.

## Open items

None — this is a self-contained, single-file change to `windows-build.ps1` with no cross-cutting dependencies beyond the sequencing constraint already noted (must land before C3's fix, not necessarily before C3 is scoped).
