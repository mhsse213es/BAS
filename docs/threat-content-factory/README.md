# Threat Content Factory (TCF)

Goal: turn threat intelligence into governed, validated, signed, executable Audspect content — repeatably and measurably (Threat-to-Content Velocity).

Principle: the Content Registry is the system of record for executable threat content and its lifecycle; the existing intelligence tables remain the system of record for threat intelligence.

## End-state pipeline

```
Threat intelligence sources (MISP · OpenCTI · OTX · future feeds)
        ↓
Normalize, deduplicate and prioritize threats
  (canonical identity · provenance · ATT&CK mapping)
        ↓
Reuse and generate content
        ↓
Safety checks and automated validation
        ↓
Human approval · signing · publishing
        ↓
Customer execution and evidence
  (detection results · exposure insights · feedback · measured TCV)
```

## Phases

| Phase | Scope | What it adds | Spec | Status |
|---|---|---|---|---|
| 1 | Content Registry — identity, immutable versions, provenance snapshots, origin/trust/lifecycle, runtime gate, run → version linkage | System of record for executable content and its lifecycle | [2026-10-04-tcf-phase1-content-registry-design.md](../superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md) | Done |
| 2 | Canonical threat identity + evidence engine — actor/threat identity, intel content identity, evidence model with claims/retractions, `threat_techniques` projection, generation reproducibility, content↔threat relationships (`generated_for`/`emulates`), TCV clocks and stops | Normalize, deduplicate and prioritize threats; canonical identity, provenance, ATT&CK mapping | [2026-10-06-tcf-phase2-canonical-threat-design.md](../superpowers/specs/2026-10-06-tcf-phase2-canonical-threat-design.md) | Done (2A, 2B, 2C) |
| 11 | Factory analytics | Measures content velocity, freshness, coverage, validation quality, and reuse | — | Not started — next to spec |
| 8 | Signing and distribution | Publishes trusted vendor content for online and air-gapped customer installations, with verified integrity | — | Not started |
| 9 | Threat-content scheduling | Automates ingestion-to-content workflows with reliable retries and lifecycle handling | — | Not started |
| 7 | Approval pipeline | Extends the existing lifecycle state machine only where a demonstrated gap exists | — | Not started |
| 10 | Threat exposure | Prioritizes threats against a customer's technologies, controls, and environment | — | Not started |
| 4 | Content reuse and composition | Reuses ART, Caldera, and existing Audspect scenarios before generating new behavior | — | Not started |
| 5 | Safety engine | Evaluates risk, reversibility, privileges, blast radius, and execution eligibility — extended to cover assembled (composed) content | — | Not started |
| 6 | Automated validation lab | Tests candidate content and gathers execution and detection evidence | — | Not started |
| 12 | Enterprise scale (offline, rollback, compatibility) | — | — | Not started |

Phases 4–11 are not necessarily all greenfield — Audspect already has components of several (e.g. ART/Caldera integration, scenario validation, OpenAEV exercises, threat prioritization). The work ahead is to **inventory, integrate, and verify** these as a coherent factory, not rebuild everything from scratch. Rows above are listed in build order, not phase-number order — see the sequencing rationale and dependency structure below.

**Next step:** fully specify Phase 11 via the normal brainstorming → spec → plan cycle. See [roadmap-phases-4-11.md](roadmap-phases-4-11.md) for the full code-backed gap inventory, dependency-aware build sequence, and per-phase master table (baseline, gap, dependencies, deliverable, exit criteria, risk/cost) this ordering is based on.

Positioning rule: do not claim parity with Picus / SafeBreach / Cymulate / AttackIQ in customer material until the factory produces measured numbers.
