# Threat Content Factory (TCF)

Goal: turn threat intelligence into governed, validated, signed, executable Audspect content — repeatably and measurably (Threat-to-Content Velocity).

Principle: the Content Registry is the system of record for executable threat content and its lifecycle; the existing intelligence tables remain the system of record for threat intelligence.

| Phase | Scope | Spec | Status |
|---|---|---|---|
| 1 | Content Registry — identity, immutable versions, provenance snapshots, origin/trust/lifecycle, runtime gate, run → version linkage | [2026-10-04-tcf-phase1-content-registry-design.md](../superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md) | Spec in review |
| 2–3 | Source ingestion, threat intelligence engine | Largely exists (MISP/OpenCTI/OTX/TAXII connectors, intelligence tables, threat prioritization) | — |
| 4 | Content reuse / composer | — | Not started |
| 5 | Safety engine (four-level scale) | — | Not started |
| 6 | Automated validation lab | — | Not started |
| 7 | Approval pipeline UI | — | Not started |
| 8 | Signing & distribution (incl. airgap signing gap) | — | Not started |
| 9 | Threat content scheduler | — | Not started |
| 10 | Customer threat exposure | — | Not started |
| 11 | Factory analytics (TCV, freshness, throughput, reuse) | — | Not started |
| 12 | Enterprise scale (offline, rollback, compatibility) | — | Not started |

Positioning rule: do not claim parity with Picus / SafeBreach / Cymulate / AttackIQ in customer material until the factory produces measured numbers.
