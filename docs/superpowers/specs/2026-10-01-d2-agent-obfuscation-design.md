# D2 — Agent Binary Obfuscation Design

**Spec for:** [[D2 - Agent binary not obfuscated]] (Audspect-Vault/14 Risks/)
**Status:** Design approved in chat (spikes complete, all green); ready for writing-plans.

## Problem

Every customer-shipped Audspect agent binary (modern agent, 5 platforms, plus
the legacy Windows agent) is built with a plain, stripped `go build`. The
orchestrator gets full `garble -literals` obfuscation; the agent does not.
The vault note's recorded root cause —
`"golang.org/x/sys assembly is incompatible with garble"` — is **stale**. It
was true in commit from 2026-05-27, pinned to garble v0.12.1 at the time. The
orchestrator's garble pin has since moved to v0.17.0 (to support Go 1.26),
and nobody revisited the agent build after that move.

A pre-implementation spike (this session, 2026-10-01) re-tested the actual
current toolchain/garble combination across every artifact the agent ships
as, inside the real build environments, and found the blocker gone — plus
two new, previously-undiscovered compatibility gaps, both now root-caused and
fixed:

### Spike results

| Target | Environment | Garble | Result |
|---|---|---|---|
| linux-amd64, linux-arm64, darwin-amd64, darwin-arm64 | Docker `golang:1.26-alpine` | v0.17.0 | ✅ builds clean, `GOGARBLE=audspect/*` |
| windows-amd64 (modern) | Docker `golang:1.26-alpine` | v0.17.0 | ✅ builds + runs, `-tiny` also works |
| windows-amd64 (modern) | Native Windows build host | v0.17.0 | ❌ then ✅ (see Gap 1) |
| windows-amd64 (legacy, go1.20.14) | Docker, base image unchanged (`golang:1.26-alpine` + `GOTOOLCHAIN=go1.20.14`) | v0.10.1 | ❌ (see Gap 2) |
| windows-amd64 (legacy, go1.20.14) | Docker, base image = `golang:1.20.14-alpine` | v0.10.1 | ✅ builds, runs, correct usage output |
| windows-amd64 (legacy, go1.20.14) | Native Windows build host, `$env:GOTOOLCHAIN` set | v0.10.1 | ❌ (same as Gap 2) |
| windows-amd64 (legacy, go1.20.14) | Native Windows build host, side-by-side native GOROOT | v0.10.1 | ✅ builds, runs, correct usage output |

Runtime smoke-tested, not just build-tested: the linux-amd64 modern binary and
the windows-amd64 legacy binary were both executed (not just linked) and
produced correct flag-usage output. The modern windows-amd64 binary's usage
output includes `-tray`/`-status-window`/`-console`/`-update`, confirming the
windigo-dependent build tags still compile correctly under garble.

### Gap 1 — native Windows build host, module-toolchain vs. garble's linker patch

`packaging/windows-build.ps1` builds agents **natively on the Windows host**
(not via Docker — it needs direct file access for Authenticode signing). This
host's installed Go (1.26.2) was older than the repo's own `go.work`
requirement (`go >= 1.26.6`, pre-existing, unrelated to D2). That mismatch
makes `GOTOOLCHAIN=auto` silently download a *module toolchain* under
`GOMODCACHE` to satisfy the version — and Go refuses to let garble's internal
linker-source-patch step (used for `-literals`/`-tiny`, not just `-tiny`)
touch anything under `GOMODCACHE`:
```
go: overlay contains a replacement for ...\toolchain@v0.0.1-go1.26.6...\pcln.go.
Files beneath GOMODCACHE (...) must not be replaced.
```
Docker never hits this because `golang:1.26-alpine` ships a real GOROOT
install already ≥ the requirement — no module-toolchain download ever
triggers.

**Fixed** (already applied, verified, this session): upgraded the Windows
build host's Go install from 1.26.2 → **1.26.8** via the official MSI
(checksum-verified against the real `go.dev/dl` JSON before installing).
1.26.8 stays on the same minor line as `golang:1.26-alpine`'s 1.26.7 — it
does not cross into 1.27, which garble v0.17.0 cannot be built with (its
own go.mod requirement). Re-verified: native garble build now succeeds,
binary runs correctly.

### Gap 2 — legacy agent, same module-toolchain mechanism, different trigger

Reproduced in both Docker (`golang:1.26-alpine` + `ENV GOTOOLCHAIN=go1.20.14`)
and natively (`$env:GOTOOLCHAIN = "go1.20.14"` on the Windows host, exactly
as `packaging/windows-build.ps1` does today) — same mechanism as Gap 1, but
garble v0.10.1 (the newest version that still installs under a go1.20
toolchain; pre-dates Go's module-toolchain feature entirely) doesn't fail on
the `GOMODCACHE` overlay guard — it **panics** parsing `go list -json`
output, because the toolchain-auto-download prints a
`"go: toolchain ... invoked to provide go1.20.14"` banner line that v0.10.1's
JSON decoder (written in 2023, before this mechanism existed) cannot handle:
```
panic: go list error: exit status 1:
args: ["list" "-json" ... "runtime" ...]
go: toolchain go1.26.8 invoked to provide go1.20.14
```
**Fixed** (verified, not yet applied to real build files — that's this
plan's job): avoid the module-toolchain-download path entirely by using a
*real, GOROOT-installed* go1.20.14 instead of an auto-downloaded one:
- **Docker:** `agent-legacy-builder`'s base image changes from
  `golang:1.26-alpine` + `ENV GOTOOLCHAIN=go1.20.14` to
  `golang:1.20.14-alpine` directly, `GOTOOLCHAIN=local`. Verified: clean
  build, valid PE, runs correctly. `gcompat` (apk package, currently
  installed specifically as the glibc-linked-toolchain-download shim) is no
  longer needed — `golang:1.20.14-alpine`'s own Go binary is already
  musl-native.
- **Native host:** install a real go1.20.14 GOROOT **side-by-side** with the
  main 1.26.8 install (a persistent directory, not the throwaway temp path
  used for the spike), and change `windows-build.ps1`'s legacy-agent section
  to point `GOROOT`/`PATH` at it directly with `GOTOOLCHAIN=local`, instead
  of setting `$env:GOTOOLCHAIN = "go1.20.14"` on top of the main install.
  Verified: clean build, valid PE, correct usage output.

Neither fix changes the legacy agent's own toolchain version (still exactly
go1.20.14) or its Windows-version support target. Both fixes change *how*
that exact version is reached — a real install instead of an
auto-downloaded module toolchain — which is what garble actually needs.

### The three production build paths today

| Path | Agent build today | Garble? |
|---|---|---|
| `packaging/build.sh` (Linux compose bundle) | plain `go build`, 5 platforms, no legacy, no packages | No |
| `orchestrator/Dockerfile` (`agent-builder`/`agent-legacy-builder`/`packager`) | plain `go build`, feeds the orchestrator's download endpoint + Docker-embedded artifacts | No |
| `packaging/windows-build.ps1` (customer Windows release ZIP) | plain `go build`, natively on the Windows host; also cross-compiles bare linux-amd64/arm64 agents for the same ZIP | No |

All three need the same obfuscation added, consistently — not one obfuscated
path and others accidentally left plain.

### The C4 constraint

[[C4 - Installer-embedded agent hash never matches BINARIES.sha256]] just
fixed exactly this class of bug for signing: `windows-build.ps1` now builds
the standalone Windows agent **once**, signs it in place, and the
installer-embedded copy is a byte-for-byte `Copy-Item` of that same signed
source — never a second independent build. D2 must slot obfuscation in
*before* that single build-then-sign step, producing the one authoritative
byte sequence everything downstream (embed, copy, sign, package) consumes.
Never:
```
build normal agent
  +-- embed normal bytes
  +-- separately garble another build       <-- reintroduces C4's class of bug
```
Always:
```
source -> garble -> authoritative bytes -> embed/copy (same bytes) -> sign -> package
```
C4's existing hash-equality assertion
(`windows-build.ps1` ~line 383-386, comparing
`installer\bas_agent.exe` against `bas-agent-windows-amd64.exe`) remains the
final guard and needs no change — it already asserts on whatever bytes the
single build step produces, garbled or not.

## Goals

1. Every customer-shipped agent artifact — modern (5 platforms) and legacy
   Windows — obfuscated with garble, scoped via `GOGARBLE=audspect/*`.
2. All three production build paths (`build.sh`, `Dockerfile`,
   `windows-build.ps1`) obfuscate consistently. No path left accidentally
   plain.
3. Obfuscation happens before C4's single build-then-sign step; the
   authoritative bytes are what gets embedded, copied, signed, and shipped.
4. The stale "x/sys assembly incompatible with garble" comments/claims are
   removed everywhere they appear, replaced with the real, current
   constraints (garble version pinned per toolchain, `GOGARBLE` scope,
   real-GOROOT requirement for the legacy toolchain).
5. Validation proves obfuscation actually happened (not just that a build
   succeeded) and that obfuscated binaries are still fully functional,
   including Windows-specific runtime paths (tray/status UI, SSPI, mTLS,
   command execution, telemetry).

## Non-goals

- **No new `-tiny` adoption.** Validated to work (Docker, both toolchains),
  but not adopted globally just because it works — only where a specific
  need justifies it. Default to `-literals` alone, matching the
  orchestrator's actual Dockerfile invocation.
- **No toolchain version change for the legacy agent.** Still exactly
  go1.20.14. Only *how* that version is reached changes (real install vs.
  auto-download).
- **No change to any signing mechanism** (GPG for the compose bundle,
  Authenticode for Windows artifacts, RSA-signed manifest for the Docker
  image). D2 only changes what bytes exist before those mechanisms run.
- **No expansion of `packaging/build.sh`'s scope.** It doesn't build the
  legacy agent or Linux packages today; D2 obfuscates what it already
  builds and does not add new artifact types to it.
- **No broadening of `GOGARBLE`** beyond `audspect/*` (agent) /
  `github.com/audspect/*` (orchestrator, unchanged, different module path).
  Third-party deps (`golang.org/x/sys`, `windigo`, `sspi`, `gorilla/websocket`)
  stay un-obfuscated, deliberately — defense against a future
  reflection/assembly breakage in a dependency, same reasoning as the
  orchestrator's existing fpdf-driven scoping decision.

## Architecture

### Garble version / toolchain matrix (final)

| Build environment | Garble version | Go toolchain | How the toolchain is reached |
|---|---|---|---|
| Docker `golang:1.26-alpine` (modern agent, orchestrator) | v0.17.0 (existing pin, unchanged) | 1.26.7 | Image-native GOROOT |
| Docker `golang:1.20.14-alpine` (legacy agent — **new base image**) | v0.10.1 (**new pin**) | 1.20.14 | Image-native GOROOT |
| Native Windows build host (modern agent, orchestrator) | v0.17.0 | 1.26.8 (**host upgraded**, already applied) | Real GOROOT install |
| Native Windows build host (legacy agent) | v0.10.1 | 1.20.14 | Real GOROOT install, **side-by-side with main 1.26.8** |

### Pipeline (every path)

```
source
  v
garble -literals  (GOGARBLE=audspect/*)
  v
authoritative agent bytes
  v
   +---------------------+
   v                      v
Authenticode/GPG       installer embedding (modern Windows only)
signing                      |
   v                      v
   +---------------------+
              v
      package / ship
```

For the modern Windows agent specifically, this composes with C4's existing
flow exactly as C4 already does it — garble is simply inserted as the first
step of the single build invocation C4 already treats as authoritative;
nothing about "build once, copy, sign" changes structurally.

## Implementation

### 1. `orchestrator/Dockerfile`

**`agent-builder` stage (currently lines ~23-53):**
- Remove the stale comment (line 24: `"Plain stripped build: golang.org/x/sys
  assembly is incompatible with garble."`).
- Install garble v0.17.0 (same pin already used by the `builder` stage for
  the orchestrator — reuse, don't re-pin separately).
- Replace every `go build` invocation in this stage (the 5 raw binaries +
  the Windows installer's embedded-agent build) with
  `GOGARBLE='audspect/*' garble -literals build ...`, keeping existing
  `-ldflags`, `-trimpath` is dropped (garble implies path-independence via
  its own trimming; verify no `-trimpath`+garble conflict during
  implementation — flag as a task-level check, not a design blocker).

**`agent-legacy-builder` stage (currently lines ~55-83):**
- Change `FROM golang:1.26-alpine AS agent-legacy-builder` to
  `FROM golang:1.20.14-alpine AS agent-legacy-builder`.
- Remove `ENV GOTOOLCHAIN=go1.20.14` (no longer needed — the image's Go *is*
  1.20.14 natively).
- Remove `gcompat` from the `apk add` line (was only needed for the
  glibc-linked auto-downloaded toolchain; the image's native Go needs no
  shim).
- Keep the existing `GOVERSION` hard-assertion (lines ~75-80) — update its
  rationale comment (it was written assuming `GOTOOLCHAIN` auto-switch; now
  it's asserting the base image itself, which is a stronger, simpler
  guarantee) but keep the assertion itself as a real regression guard.
- Install garble v0.10.1, add `GOGARBLE='audspect/*' garble -literals`
  wrapping the existing `go build` call.

### 2. `packaging/build.sh`

- Remove the stale comment (line 48).
- Add a garble-for-agent detection block mirroring the existing
  orchestrator one (lines ~36-46), but scoped `GOGARBLE='audspect/*'`
  (different module path than the orchestrator's
  `github.com/audspect/*` — do not reuse that exact string).
- `GOBUILD_AGENT` becomes conditional exactly like `GOBUILD_ORCH` already
  is: garble-wrapped when garble is found, plain `go build` fallback
  otherwise (dev-build tolerance, matching existing orchestrator pattern).
- This script's garble install guidance should be pinned to v0.17.0
  explicitly (not `@latest`, which could silently pick up a version
  requiring Go ≥1.27 as happened with v0.18.0) — update the existing
  orchestrator-only comment to state the pin clearly for both binaries.

### 3. `packaging/windows-build.ps1`

- **Modern agent** (`installer\bas_agent.exe` build, ~line 291-316): insert
  garble into this single build invocation (the one C4 already treats as
  authoritative) — `GOGARBLE='audspect/*' garble -literals build` in place
  of the current `go build`. No change to the C4 copy/sign flow after it.
- **Legacy agent** (~lines 390-424):
  - Remove `$env:GOTOOLCHAIN = "go1.20.14"`.
  - Point `$env:GOROOT` and `PATH` at a real, persistently-installed
    go1.20.14 (install location TBD at plan time — e.g.
    `C:\go1.20.14`, provisioned once on the build host, documented as a
    prerequisite the same way the 1.26.8 host upgrade now is).
  - Set `$env:GOTOOLCHAIN = "local"` explicitly (prevents any accidental
    auto-download even with the dedicated GOROOT present).
  - Keep the existing `$legacyGoVersion` hard-assertion (~line 409-414) —
    it's still a real regression guard, now asserting the dedicated GOROOT
    rather than an auto-switched one.
  - Install garble v0.10.1 (separate pin from the modern path's v0.17.0 —
    document both pins and why they differ, same rationale as the matrix
    above).
  - Wrap the existing `go build` (~line 416) with
    `GOGARBLE='audspect/*' garble -literals build`.
- **Host prerequisites doc update:** wherever this repo documents build-host
  setup (README, packaging docs, or a comment block at the top of this
  script — identify at plan time), add: Go ≥1.26.6 (currently 1.26.8,
  upgraded 2026-10-01) for the main toolchain, plus a dedicated go1.20.14
  install for the legacy agent, plus garble v0.17.0 and v0.10.1 both
  installed and resolvable.

## Error handling

No new error-handling design is needed beyond what already exists:
- `build.sh` and `windows-build.ps1` already have garble-missing /
  signing-missing fallback paths (warn + plain build for dev, hard `Err` for
  release-required builds where applicable). Garble-for-agent follows the
  exact same existing pattern, not a new one.
- The Dockerfile's `agent-legacy-builder` GOVERSION assertion already fails
  the build loudly if the toolchain isn't exactly go1.20.14 — unchanged
  behavior, just a stronger guarantee now that it's asserting a native
  image rather than a downloaded toolchain.
- C4's byte-equality assertion is the existing fail-loud guard against
  obfuscation (or anything else) introducing a divergence between the
  installer-embedded and standalone modern Windows agent. No new assertion
  needed; it already covers this.

## Testing

Three levels, per your explicit instruction:

### Level 1 — build, for every shipped target

- [ ] linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64
  (modern), windows-amd64 (legacy) all build successfully via garble in
  their real production path (Docker and/or native host, matching how that
  artifact actually ships).
- [ ] For each, confirm the binary is **actually obfuscated**, not merely
  produced — e.g. `strings` on the binary should not show plain Audspect
  package paths/identifiers that garble is supposed to rename; a
  `garble -debugdir` comparison (as already used for the orchestrator's
  fpdf verification) is the precedent to follow.

### Level 2 — functional smoke, every applicable agent

- [ ] Process starts.
- [ ] Logging initializes.
- [ ] Configuration/argument parsing works (`-h` usage output, as already
  smoke-tested during this spec's spikes).
- [ ] Agent can initialize its normal runtime.
- [ ] Clean shutdown works.

### Level 3 — Windows-specific functionality (modern)

- [ ] Tray/status-window UI via windigo.
- [ ] SSPI authentication.
- [ ] WebSocket/mTLS connection to a real or test orchestrator.
- [ ] Command reception.
- [ ] Scenario execution.
- [ ] Telemetry/result reporting.

For legacy Windows, test the equivalent functionality that actually exists
in that agent (it has no tray/status-window UI per its own flag set — do not
force the modern agent's test matrix onto it).

### Regression guard

- [ ] C4's existing hash-equality assertion between
  `installer\bas_agent.exe` and `bas-agent-windows-amd64.exe` still passes
  after obfuscation is introduced (proves obfuscation didn't reintroduce a
  second-build divergence).

## Acceptance criteria

1. All three production build paths obfuscate every agent artifact they
   produce, consistently (`GOGARBLE='audspect/*'`, `-literals`).
2. No path builds an agent artifact plain while another path obfuscates the
   "same" artifact.
3. Legacy Windows agent is obfuscated, using the Gap 2 fix (native go1.20.14
   GOROOT, not an auto-downloaded module toolchain), in both Docker and the
   native host.
4. C4's single-build-then-sign invariant is unchanged and its regression
   test still passes.
5. All Level 1/2/3 validation checks pass.
6. Every stale "x/sys incompatible with garble" comment is removed from
   `orchestrator/Dockerfile` and `packaging/build.sh`, replaced with the
   real current constraints.
7. [[D2 - Agent binary not obfuscated]] vault note updated to closed, with
   the real root-cause history (stale finding, two newly-discovered and
   fixed toolchain gaps) recorded — matching how C3/C4 were closed out in
   this same session.

## Open items

None — every question raised during brainstorming was resolved with a real,
verified spike before this spec was written: the original blocker (stale),
the legacy toolchain gap (real, root-caused, fixed), and the native-host
toolchain gap (real, root-caused, fixed — and the fix already applied to
this build host).
