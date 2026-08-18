# Legacy Windows Agent — Capability Matrix

**Architecture support: Legacy Windows Agent v1 supports Windows x86-64 (amd64) only. 32-bit
Windows (386/x86) is explicitly out of scope for v1.** 32-bit introduces a second compatibility
axis (32-bit API behavior, WOW64, Program Files/registry redirection, pointer-width assumptions,
separate installer/service behavior, separate test infrastructure) on top of an already broad OS
range, with no architectural benefit to proving out in Phase 1. Support for 32-bit systems may be
evaluated separately based on customer demand and compatibility feasibility.

This is a **compatibility agent**, not an old version of Audspect. It is not held to feature parity
with the modern agent, and it is not expected to catch up automatically as the modern agent gains
capabilities. Every future feature gets classified against this contract before it's considered for
the legacy agent:

- **A — Legacy-compatible**: implemented for both agents from the start.
- **B — Modern-only**: requires Windows 10+ APIs, newer OS security facilities, or newer
  Go/runtime/dependencies the legacy toolchain can't build. Modern agent only, by design.
- **C — Legacy-backportable**: technically portable to the legacy agent but not done automatically;
  an explicit, separate decision each time.

## Platform support (v1)

| Platform | v1 |
|---|---|
| Windows 7 SP1 x64 | ✅ |
| Windows 8 / 8.1 x64 | ✅ |
| Server 2008 R2 x64 | ✅ |
| Server 2012 / 2012 R2 x64 | ✅ |
| Windows 7/8 32-bit (x86) | ❌ |
| Server 2008/2012 32-bit (x86) | ❌ |

## Capability matrix (target — Phases 1–3 combined)

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

Phase 1 covers enrollment, secure communication, and agent health/status only — no collector, no
ART/BAS simulation content, no server-side compatibility gating. See
`docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md` for the full Phase 1
design and `docs/superpowers/plans/2026-08-18-legacy-windows-agent-phase1-plan.md` for its
implementation plan.
