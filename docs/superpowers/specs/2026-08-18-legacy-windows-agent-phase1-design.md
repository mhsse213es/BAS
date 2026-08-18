# Legacy Windows Agent — Phase 1 (Scaffold, Enrollment, Build/Release) Design

## Context

Audspect's Windows agent (`agent/`, Go module `audspect/agent`) targets `go 1.26.0`. Go itself
requires Windows 10 / Server 2016 or later as a compile target starting with **Go 1.21** — the
current toolchain cannot produce a binary that runs on Windows 7/8/8.1 or Server 2008 R2–2012 R2,
regardless of build flags. Supporting those OSes requires a second, deliberately old Go toolchain
frozen at the last release that still targets them.

The customer base includes BFSI environments where legacy Windows client/server estates are still
present in production, and the platform currently has no way to enroll or assess them.

## Legacy Support Contract

This is a **compatibility agent**, not an old version of Audspect. It is not held to feature parity
with the modern agent, and it is not expected to catch up automatically as the modern agent gains
capabilities. Every future feature gets classified against this contract before it's considered for
the legacy agent:

- **A — Legacy-compatible**: implemented for both agents from the start.
- **B — Modern-only**: requires Windows 10+ APIs, newer OS security facilities, or newer
  Go/runtime/dependencies the legacy toolchain can't build. Modern agent only, by design.
- **C — Legacy-backportable**: technically portable to the legacy agent but not done automatically;
  an explicit, separate decision each time.

### Platform support (v1)

| Platform | v1 |
|---|---|
| Windows 7 SP1 x64 | ✅ |
| Windows 8 / 8.1 x64 | ✅ |
| Server 2008 R2 x64 | ✅ |
| Server 2012 / 2012 R2 x64 | ✅ |
| Windows 7/8 32-bit (x86) | ❌ |
| Server 2008/2012 32-bit (x86) | ❌ |

**Architecture support: Legacy Windows Agent v1 supports Windows x86-64 (amd64) only. 32-bit
Windows (386/x86) is explicitly out of scope for v1.** 32-bit introduces a second compatibility
axis (32-bit API behavior, WOW64, Program Files/registry redirection, pointer-width assumptions,
separate installer/service behavior, separate test infrastructure) on top of an already broad OS
range, with no architectural benefit to proving out in Phase 1. Support for 32-bit systems may be
evaluated separately based on customer demand and compatibility feasibility.

### Capability matrix (target — Phases 1–3 combined)

| Capability | Modern | Legacy |
|---|---|---|
| Enrollment / authentication | ✅ | ✅ (Phase 1) |
| Secure communication (WS) | ✅ | ✅ (Phase 1) |
| Agent health / status | ✅ | ✅ (Phase 1) |
| System inventory (OS/version/build) | ✅ | ✅ (Phase 2) |
| User/account enumeration | ✅ | ✅ (Phase 2) |
| Installed software | ✅ | ✅ (Phase 2) |
| Services / processes | ✅ | ✅ (Phase 2) |
| Basic network configuration | ✅ | ✅ (Phase 2) |
| Firewall / security configuration (where OS exposes it) | ✅ | ✅ (Phase 2) |
| Patch / update inventory | ✅ | ✅ (Phase 2) |
| File / registry checks (OS-compatible subset) | ✅ | ✅ (Phase 2) |
| Core posture checks | ✅ | ✅ (Phase 2) |
| Core BAS/ART simulations (legacy-safe subset) | ✅ | ⚠️ (Phase 3, compatible scenarios only) |
| Findings/results/telemetry reporting | ✅ | ✅ (Phase 2, reuses Phase 1 comms) |
| Advanced Windows telemetry | ✅ | ❌ |
| Windows 10/11-specific controls | ✅ | ❌ |
| Modern-Defender-dependent features | ✅ | ❌ |
| Future modern-only capabilities | ✅ | ❌ / ⚠️ per A/B/C classification |

This spec covers **Phase 1 only** (bolded rows above). Phases 2 and 3 get their own specs once
Phase 1 proves the agent can build, sign, install, enroll, communicate, and appear correctly in the
console — before any effort goes into collectors or scenario content.

## Phase 1 Scope

Prove the legacy agent can:
1. Build reproducibly with a verified, pinned Go 1.20.14 toolchain, amd64 only.
2. Install as a Windows service on a legacy target (manual VM verification, not CI).
3. Enroll with the orchestrator over the same WS protocol the modern agent uses.
4. Report health/status on the same heartbeat mechanism.
5. Appear in the console's Agents list, distinguishable as a legacy agent.
6. Ship through the real release pipeline: `BINARIES.sha256` entry, RSA signature, a download
   card in the console's Deploy Agent section.

Explicitly **not** in Phase 1: any inventory/posture collector, any ART/BAS simulation, any
server-side technique compatibility gating. The agent enrolls, reports "I'm alive," and does
nothing else yet.

## Architecture

### Module structure

New sibling Go module at `agent-legacy/`, module path `audspect/agent-legacy`. It does not import
`agent/`'s dependency graph — `agent/go.mod` pins dependency versions chosen against `go 1.26`,
some of which may already require Go 1.21+ to build. `agent-legacy/go.mod` pins its own dependency
versions (e.g. `golang.org/x/sys/windows`) at whichever versions still build under Go 1.20.

Where Phase 1 code is genuinely identical in intent to the modern agent (e.g. the WS
enrollment/heartbeat protocol's wire shape), it is **re-implemented**, not shared via a common
package. A shared package would need to satisfy Go 1.20's language/stdlib ceiling forever, which
is exactly the "heaviest ongoing constraint" option already rejected. Protocol compatibility is
enforced by both agents talking to the same orchestrator endpoints and message shapes, not by
sharing Go source.

`agent-legacy/CAPABILITY_MATRIX.md` is the checked-in, canonical copy of the tables above — the
source of truth every future A/B/C classification decision references and updates.

### Toolchain pinning (verified, not assumed)

A bare `go 1.20` line in `go.mod` only enforces a minimum *language* version — if a newer `go`
binary is on PATH, the build still uses it, which does not produce a binary linked against the
Go 1.20 runtime/stdlib the legacy OS compatibility actually depends on. Phase 1 pins the toolchain
via **`GOTOOLCHAIN=go1.20.14` set explicitly in the build environment only** — `go.mod` carries no
`toolchain` directive at all. This was verified empirically during implementation: the `toolchain`
directive syntax is itself a Go 1.21+ concept. Once `GOTOOLCHAIN=go1.20.14` correctly re-execs the
1.21+ dispatcher into the real go1.20.14 binary, that binary parses `go.mod` itself to do the
build — and go1.20.14 doesn't recognize the `toolchain` keyword, since it predates it, so a
`toolchain go1.20.14` line in `go.mod` breaks the build with `unknown directive: toolchain` the
moment `GOTOOLCHAIN` actually takes effect. The two mechanisms are mutually exclusive; `go.mod`
must stay at a bare `go 1.20`, and `GOTOOLCHAIN` is the only pin.

Before producing the artifact, the build script runs `go version` against the resolved toolchain
and **fails the build** if the output is not exactly `go1.20.14` — this is a hard assertion, not a
log line, so a silent toolchain drift (e.g. `GOTOOLCHAIN` unset in some other CI context) breaks
the build loudly instead of quietly shipping a binary built against the wrong runtime.

`go1.20.14` (released 2024-02-06) is confirmed via go.dev's own release history as the final Go 1.20
patch release.

### Build & release pipeline changes

- `scripts/build-agent-legacy.ps1` (new, mirrors `scripts/build-agent.ps1`'s shape): sets
  `GOTOOLCHAIN=go1.20.14`, `GOOS=windows`, `GOARCH=amd64`, asserts `go version` as above, builds
  `agent-legacy/`.
- `packaging/windows-build.ps1` gets a new stage (alongside the existing 5a/5b agent-build steps)
  invoking the legacy build, producing a standalone binary and an installer EXE the same way the
  modern agent's installer is produced (embedding via the existing `installer/` pattern, reusing
  the same UAC-manifest/rsrc approach where compatible with the legacy toolchain — verify `rsrc`
  itself still runs fine invoked from the pinned toolchain's environment during implementation).
- New `BINARIES.sha256` entries for the legacy binary/installer, extracted and RSA-signed through
  the exact same step 5c mechanism already in place — no changes to the signing process itself.
- `internal/api/handlers.go`'s `agentFiles` map gets two new entries:
  `windows-legacy-amd64` → `bas-agent-windows-legacy-amd64.exe`,
  `windows-legacy-amd64-setup` → `bas-agent-windows-legacy-amd64-setup.zip`.
- `internal/api/routes.go` needs no changes — `/api/agents/download/{platform}` already serves any
  key present in `agentFiles`.

### Enrollment & console visibility

The legacy agent enrolls through the existing `/ws/agent` endpoint and enrollment flow — no new
backend enrollment code path. It reports its own OS version string (already possible via the
existing `getWindowsVersion()`/`RtlGetVersion()` pattern, re-implemented in the legacy module) so
the console can visually distinguish it from a modern agent in the Agents list (e.g. an "OS: Windows
7 SP1" value versus "Windows 10/11") — this uses fields the enrollment payload already carries, no
new schema. A future phase may add an explicit `agentBuild: "legacy"` marker if compatibility
gating (Phase 3) needs to distinguish agents structurally rather than by parsing the OS string; not
needed for Phase 1.

### UI — Deploy Agent section

A second card in "Deploy Agent," placed directly alongside the existing Windows Agent card, using
the plain `.agent-dl-card` styling (the grid Linux/macOS already use) rather than the
`.agent-dl-featured` treatment — this is deliberately not presented as the recommended path.

- Label: "Windows Agent (Legacy)"
- Sub-label: "Windows 7 SP1 / 8 / 8.1 / Server 2008 R2 – 2012 R2 (x64) — reduced capability"
- A link/tooltip pointing at the capability matrix, so an operator downloading it understands the
  reduced scope before installing, not after.
- Download links for the installer and CLI binary, matching the existing card's button pattern,
  pointed at the two new `agentFiles` keys.

## Testing

- **Toolchain assertion**: automated — the build script's `go version` check is itself the test;
  a CI/build run against a tampered or missing `GOTOOLCHAIN` must fail loudly.
- **Build success**: automated — `agent-legacy/` compiles clean for `GOOS=windows GOARCH=amd64`
  under the pinned toolchain.
- **Enrollment/health**: manual, on real (or VM) legacy hardware — install the built binary on a
  Windows 7 SP1 or Server 2008 R2 VM, confirm it enrolls, appears in the Agents list, and reports
  heartbeats on the same interval as the modern agent. This cannot be meaningfully automated in the
  existing Docker-based Go test suite (no Windows 7/2008R2 CI runner exists today) — call this out
  explicitly as a manual verification step in the implementation plan, not skip it.
- **Download pipeline**: automated where the modern agent's equivalent is — a handler test
  confirming `GET /api/agents/download/windows-legacy-amd64` serves the expected filename/MIME
  type from the `agentFiles` map, mirroring existing `DownloadAgent` tests.

## Out of scope for Phase 1 (explicitly deferred)

- Any inventory or posture collector (Phase 2).
- Any ART/BAS simulation content and the server-side compatibility-tagging mechanism that would be
  needed to know which techniques are legacy-safe before dispatching them (Phase 3).
- 32-bit (x86) builds.
- Anything older than Windows 7 SP1 / Server 2008 R2 (Vista, Server 2003) — would need an even
  older toolchain and its own API compatibility investigation; not requested.
