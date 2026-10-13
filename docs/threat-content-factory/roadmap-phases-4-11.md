# TCF Roadmap — Phases 4-11 Sequencing

**Status: provisional sequencing, not eight approved specifications.** Each phase gets its own spec → plan → implementation cycle (same convention as `docs/superpowers/plans/`), starting with Phase 11. Phase 5 and Phase 6 may move earlier if Phase 4's composition design reveals that safety enforcement or validation evidence is a prerequisite for safely generating candidates.

**Rule: every phase starts with a fresh code-backed gap analysis before design.** The inventory below is a snapshot taken 2026-10-13, not permission to rebuild a subsystem that already works — re-verify it against current code before scoping each phase's spec.

## Sequencing principle

Dependency-aware, risk-first, delivering measurable value early — not cheapest-first. Implementation cost is a tie-breaker, not the primary driver. Analytics comes before automation because it gives the measurements needed to judge whether the automation that follows actually works.

## Sequence and rationale

1. **Phase 11 — Factory analytics.** Start here. Low cost · high leverage. Aggregate existing lifecycle, validation, provenance, and TCV records into trustworthy metrics — the baseline for pipeline health, content throughput, and threat-to-content latency before investing in larger automation.
2. **Phase 8 — Signing and air-gap distribution hardening.** Low-to-medium cost · high integrity value. Close the known cosign gap in `packaging/airgap/*.sh`. Verify what is signed, what is verified, and when — test tampered bundles and missing signatures, not just successful imports.
3. **Phase 9 — Threat-triggered generation.** Medium cost · core automation. Connect new/changed canonical threats to candidate generation, with idempotency, retries, failure visibility, and loop prevention so repeated intel updates don't generate duplicate content.
4. **Phase 7 — Approval pipeline extensions.** Medium cost · governance. Extend the existing lifecycle state machine only where gaps are demonstrated. Ensure failed validation, approval identity, signing, and publication cannot be bypassed.
5. **Phase 10 — Customer-facing threat exposure.** Medium cost · visible customer value. Present threat relevance, affected techniques, evidence freshness, content availability, and validation status — clearly distinguishing observed evidence from inferred exposure and unknown coverage. Can be prototyped against existing evidence while the validation lab is still being designed, provided the UI labels evidence limitations honestly.
6. **Phase 4 — Content reuse and composition.** High cost · major capability expansion. Build the reusable composition layer that selects existing ART, Caldera, and Audspect behaviors before creating new candidates, enforcing provenance, compatibility, and safety constraints.
7. **Phase 5 — Safety engine extensions.** Dependent on composition requirements. Extend the current safety classifier to cover assembled content, not just individual scenarios. Preserve fail-closed execution and publication rules.
8. **Phase 6 — Automated validation lab.** High cost · infrastructure-heavy. The capability gap with the biggest implication for factory credibility. Build isolated execution infrastructure, telemetry collection, deterministic test cases, and evidence-backed validation.

## Dependency structure

```
              Phase 11: Analytics
                       |
Phase 8: Integrity ----+---- Phase 9: Automation
                       |             |
                       v             v
                Phase 7: Governance
                       |
                       v
             Phase 4: Composition
                       |
                       v
             Phase 5: Safety extension
                       |
                       v
             Phase 6: Validation lab
                       |
                       v
            Phase 10: Exposure presentation
```

This represents the broad dependency direction, not a claim that every phase must strictly wait for the previous one. Phase 10's exposure dashboard can be prototyped using existing evidence while the validation lab is being designed.

## Master table

| Phase | Current baseline (2026-10-13 inventory) | Gap to close | Dependencies | Deliverable | Exit criteria | Risk/cost | Status |
|---|---|---|---|---|---|---|---|
| 11 — Factory analytics | `content_version_events`, `content_validations`, `content_safety_verdicts`, TCV tables all hold raw data; `/api/analytics/*` exists for threat-intel summary/posture/IOCs but nothing aggregates factory pipeline health | Aggregation/dashboard layer over existing tables | None | Metrics: threats ingested/resolved; candidates generated/rejected/validated/published; median & P95 TCV; duplicate-generation rate; source-to-technique mapping coverage; validation results by content type. `NO_DATA` shown when underlying data doesn't exist yet, never a fabricated zero | Each metric traceable to a real query over existing tables; `NO_DATA` state verified for at least one metric with genuinely no data yet | Low cost / high leverage | Not started — next to spec |
| 8 — Signing & air-gap distribution hardening | Content signing (`AttachVendorSignature`/`TrustVendorSigned`) and platform release signing (cosign, GPG) both exist; `packaging/airgap/{pack,import,verify}.sh` has zero cosign integration | Wire cosign verification into the airgap pack/import/verify flow; confirm cosign's existing signing model actually covers the specific artifacts shipped inside an air-gap bundle (not just the outer release archive) | None | Airgap import refuses an unsigned or tampered bundle; a test suite proves tampered-bundle and missing-signature rejection, not just the successful-import path | Tampered-bundle test fails import; missing-signature test fails import; successful signed-bundle test still passes | Low-to-medium cost / high integrity value | Not started |
| 9 — Threat-triggered generation | Connector scheduler (`internal/connector/scheduler.go`) already polls MISP/OpenCTI/OTX on a cadence and resolves claims (TCF 2A-2C); no chain from "new/changed threat" to "candidate generation run" | Explicit trigger chain, idempotent (same threat-state change never double-generates), with retries and failure visibility, and loop prevention (generation never re-triggers its own source sync) | 11 (to measure duplicate-generation rate), 8 (generated content must still flow through the hardened signing path) | A changed/new canonical threat automatically produces (or attempts) exactly one generation run per state change | Re-running the same sync twice produces zero duplicate generation runs; a forced generation failure is visible in Phase 11's metrics | Medium cost / core automation | Not started |
| 7 — Approval pipeline extensions | `contentregistry/lifecycle.go`'s `CheckTransition` state machine (DRAFT→VALIDATING→VALIDATED→APPROVED→PUBLISHED/PUBLISHED_LOCAL) with human-actor gating and admin-only transitions already shipped | Extend ONLY where a demonstrated gap exists (e.g. multi-approver, SLA tracking) — do not rebuild the state machine | 9 (generation volume may surface gaps the current pipeline doesn't handle) | Each extension traces to a specific demonstrated gap, not speculative governance | Failed validation, approval identity, signing, and publication are each independently provable as non-bypassable | Medium cost / governance | Not started |
| 10 — Customer-facing threat exposure | Backend (`internal/evidence`, `internal/threatidentity`, `internal/tcv`) is most of the data model a threat-exposure feature needs; no customer-facing presentation layer exists | Exposure dashboard/API presenting relevance, affected techniques, evidence freshness, content availability, validation status | 11 (shares the "don't fabricate data" discipline), can prototype ahead of 6 | Observed evidence is visually/structurally distinct from inferred exposure and from unknown coverage — never collapsed into one undifferentiated score | A reviewer can tell, for any shown exposure claim, whether it is observed, inferred, or unknown, without reading source code | Medium cost / visible customer value | Not started |
| 4 — Content reuse and composition | `contentregistry` has version lineage (`RegisterGenerated`, `generation` jsonb, `generated_for` link) but nothing assembles a new scenario from existing validated technique-steps; `scenario/variant.go` is execution-time variance, not content composition | Real composition/template layer selecting existing ART/Caldera/Audspect behaviors before generating new candidates, with provenance, compatibility, and safety constraints enforced | 7 (composed content must flow through governance), 5 (composition's safety needs may force moving Phase 5 earlier) | A candidate can be assembled from ≥2 existing validated components with full provenance back to each source component | Provenance query for any composed candidate returns every source component; an incompatible/unsafe combination is refused before reaching the registry | High cost / major capability expansion | Not started |
| 5 — Safety engine extensions | `analyze.go`'s `safetyVerdict()` + `scenario.ResolveExecutionClass` classify destructiveness per individual scenario and already gate publish via `content_safety_verdicts` | Extend the classifier to reason about ASSEMBLED content (composition of parts), not just single scenarios, while preserving fail-closed behavior | 4 | A composed candidate's safety verdict accounts for the combined risk of its parts, not just each part in isolation | A candidate whose individual parts are each safe but whose combination is unsafe is still refused | Dependent on composition requirements | Not started |
| 6 — Automated validation lab | Not found in this checkout (Caldera integration is an execution engine, not an isolated auto-validation environment; compose files are deployment, not ephemeral test labs) | Isolated execution infrastructure, telemetry collection, deterministic test cases, evidence-backed validation, with an explicit validation contract distinguishing: (a) parses + passes static safety checks, (b) executed successfully in a controlled environment, (c) expected detection was observed, (d) detection outcome is unknown | 5 (validation needs a settled safety verdict to run against safely) | A content version's `VALIDATED` lifecycle state is backed by a documented validation contract stating exactly which of (a)-(d) it satisfies | Transitioning to `VALIDATED` without satisfying the contract's stated minimum is a hard refusal, not a soft warning | High cost / infrastructure-heavy | Not started |

## Adjustments baked into this sequencing

1. **Analytics metrics (Phase 11).** Threats ingested and resolved; candidates generated, rejected, validated, and published; median and P95 TCV; duplicate-generation rate; source-to-technique mapping coverage; validation results by content type. Only show a metric when its underlying data exists — use an explicit `NO_DATA` state when it doesn't, never a fabricated zero.
2. **Phase 8 is a release-integrity gate, not packaging polish.** A correctly generated scenario is insufficient if the customer cannot reliably verify the integrity and authenticity of the imported bundle. Verify that cosign's existing signing model is appropriate for the exact artifacts inside the air-gap bundle — do not assume signing the outer release archive automatically authenticates every imported content artifact under every verification path.
3. **Phase 6 must not let `VALIDATED` imply more than it proves.** Until automated validation exists, the factory must distinguish content that parses and passes static safety checks, content that has executed successfully in a controlled environment, content whose expected detection was observed, and content whose detection outcome is unknown. A transition to `VALIDATED` must not imply all four unless the validation contract explicitly establishes that.

## Next step

Fully specify Phase 11 via the normal brainstorming → spec → plan cycle.
