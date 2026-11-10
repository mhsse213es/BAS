# REQ-018 Content Velocity Commitment - Design (DRAFT, uncommitted)

**Status:** Draft for review. No target number is set. Nothing here is a customer-facing commitment yet.
**Supersedes:** the REQ-018 framing "publish a content-velocity SLA (2 -> 4)" as a fixed N-day promise.

## 1. Intent

Make content velocity a product commitment backed by measurement. Audspect first measures how fast a trusted advisory becomes validated, signed, executable content. Only after the factory consistently meets a measured target does a contractual SLA follow.

## 2. Commitment scope (what the target covers)

Five stages, each with a defined start and end event:

| # | Stage | Start | End | Measured today? |
|---|---|---|---|---|
| 1 | Advisory intake and relevance | advisory received from a trusted source (CERT-In, or FS-ISAC via TAXII) | advisory classified relevant or excluded | Partial. Intake exists; no relevance-classification event |
| 2 | Development | relevant advisory (`threat_eligible`) | scenario authored and mapped to advisory with sources (`content_created`) | Yes (`generation_*`, `content_created`) |
| 3 | Validation | content created | passed factory validation against the exact content version (`validated_coverage`) | Yes (`validation_dispatched`, `validation_resulted`, `validated_coverage`) |
| 4 | Packaging | validated content | included in a signed, integrity-verified offline bundle | **No event.** Bundle build and signing are not in the TCV ledger |
| 5 | Delivery | bundle signed | bundle made available through the agreed channel | **Out of Audspect's control for air-gapped sites** (see section 3) |

## 3. Two clocks, not one

- **Content-ready time:** advisory received to a validated, signed bundle exists. Audspect controls this clock. This is the commitment's measured target.
- **Customer-delivered time:** bundle signed to the customer confirming receipt through their transfer process. Audspect cannot control this for air-gapped sites. It is reported, never promised as a guarantee.

Any external statement must name the clock it refers to.

## 4. Exclusions (defined before measurement, not after)

An advisory is excluded from the target, and counted separately, if any of these hold:

1. **Relevance:** outside Audspect's supported threat scope or platforms.
2. **Insufficient technical detail:** the advisory does not give enough behaviour to build a safe, meaningful scenario.
3. **Unsupported platform:** the technique needs a platform Audspect does not validate.
4. **Validation environment unavailable:** the required lab or range is down.
5. **Third-party dependency:** the scenario needs a vendor or external service Audspect cannot reach.

Exclusions are reported as a count and a percentage of advisories. They are never silently dropped from the denominator.

## 5. Measurement baseline (before any number is chosen)

Collect across all actual eligible advisories over a defined window:

- Median and P95 time to content-ready, per stage and end to end.
- Percentage content-ready within each candidate target (for example 7, 14, 30 days). The candidates are inputs to the decision, not commitments.
- Percentage of advisories excluded, broken down by exclusion reason.
- Packaging and release delay (requires the new packaging event, section 6).
- Open-cohort count and oldest open age, so slow items are not hidden as censored.

The existing SLA projection (`internal/tcv/sla.go`: per-stage P50/P95, failed and open counts, bottleneck, incomplete-window flag) already produces most of this for stages 2-3. It is an internal projection and is not exposed to customers.

## 6. Gaps to close before measuring

1. **Packaging event.** Add `bundle_packaged` (and a signing/verification step) to the pipeline ledger so stage 4 is measured. Without it, content-ready time is unknown.
2. **Advisory intake and relevance event.** Add an intake event (source, received_at) and a relevance event (relevant or excluded, with reason) so stage 1 and the exclusion counts exist.
3. **Exclusion reason on rejection.** `rejected` events need a machine-readable reason from the exclusion list in section 4.
4. **Delivery is not instrumented by Audspect.** Record delivery only when the customer or transfer process confirms it. Do not infer it.

## 7. Decision gate for a target

A target number is adopted only when all are true:

- At least one full measurement window with a complete incomplete-window flag set to false.
- The factory meets the chosen target for the content-ready clock at the chosen percentile on that window.
- Exclusions are below an agreed threshold and each exclusion reason is recorded.
- Packaging and release delays are measured and included.

Until then, the external wording is "measured content-ready performance is reported on request," not a number.

## 8. Non-goals

- No fixed N-day customer SLA in this iteration.
- No promise of customer-delivered time for air-gapped sites.
- No change to Phase-2C TCV (`AggregateMetrics`); it stays byte-for-byte untouched, as the merged ledger requires.

## 9. Decisions (owner-approved recommendations)

1. **Baseline window:** the last 90 days of real eligible advisories. Re-measured each quarter.
2. **Sources for the first baseline:** CERT-In only. FS-ISAC is added once its TAXII intake is confirmed to deliver advisories with enough technical detail. Adding a source later starts a new baseline; it is never merged into an old one.
3. **Ownership of exclusions:** every exclusion is an analyst decision recorded with one reason from the section 4 list and a free-text note. The exclusion counts are reviewed by the owner monthly. "Insufficient technical detail" is never decided retroactively to improve the numbers. Once a reason is recorded it stays, and a later reversal is a new event.
