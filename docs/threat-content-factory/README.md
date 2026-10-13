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
| 2 | Canonical threat identity + evidence engine — actor/threat identity, intel content identity, evidence model with claims/retractions, `threat_techniques` projection, generation reproducibility, content↔threat relationships (`generated_for`/`emulates`), TCV clocks and stops | Normalize, deduplicate and prioritize threats; canonical identity, provenance, ATT&CK mapping | [2026-10-06-tcf-phase2-canonical-threat-design.md](../superpowers/specs/2026-10-06-tcf-phase2-canonical-threat-design.md) | 2A + 2B done; 2C (emulation + TCV) in progress |
| 4 | Content reuse and composition | Reuses ART, Caldera, and existing Audspect scenarios before generating new behavior | — | Not started |
| 5 | Safety engine | Evaluates risk, reversibility, privileges, blast radius, and execution eligibility | — | Not started |
| 6 | Automated validation lab | Tests candidate content and gathers execution and detection evidence | — | Not started |
| 7 | Approval pipeline | Separates generated candidates from approved, publishable content | — | Not started |
| 8 | Signing and distribution | Publishes trusted vendor content for online and air-gapped customer installations | — | Not started |
| 9 | Threat-content scheduling | Automates ingestion-to-content workflows with reliable retries and lifecycle handling | — | Not started |
| 10 | Threat exposure | Prioritizes threats against a customer's technologies, controls, and environment | — | Not started |
| 11 | Factory analytics | Measures content velocity, freshness, coverage, validation quality, and reuse | — | Not started |
| 12 | Enterprise scale (offline, rollback, compatibility) | — | — | Not started |

Phases 4–11 are not necessarily all greenfield — Audspect already has components of several (e.g. ART/Caldera integration, scenario validation, OpenAEV exercises, threat prioritization). The work ahead is to **inventory, integrate, and verify** these as a coherent factory, not rebuild everything from scratch.

**Next step (recommended):** finish Phase 2C, declare Phase 2 complete against its existing acceptance criteria, then run a separate TCF roadmap review to inventory which of phases 4–11's capabilities already exist, which are partial, and which genuinely need building — rather than treating canonical threat intelligence (Phase 2) alone as a complete factory.

Positioning rule: do not claim parity with Picus / SafeBreach / Cymulate / AttackIQ in customer material until the factory produces measured numbers.
