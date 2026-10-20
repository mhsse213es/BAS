# DLP Efficacy Metrics — Proposed Definitions (DRAFT, for approval)

Status: **proposed measurement contract**. None of the metrics below is
implemented, and nothing in this document is a measured product result.
Approval of this draft authorizes defining the schema and evidence
requirements. It does not authorize computing or publishing any metric
until the evidence and denominators it requires exist (see "Gate").

Relation to existing code: `dlpreport.PreventionByGroup` already computes a
*prevention rate* (blocked, quarantined or encrypted, over total records). It
is an enforcement-outcome count, not one of the five metrics below, and it
does not establish precision, recall or latency.

## 1. Principles

- **Unit of measurement:** one scored decision, i.e. one (scenario step,
  DLP expectation) pair with a verdict, as persisted in `dlp_evidence_records`.
- **Ground truth must be adjudicated, not inferred.** A sample's expected
  outcome comes from the scenario's declared expectation, and its actual
  outcome comes from evidence that meets the evidence requirements in §3.
  A verdict that is only the absence of evidence is never a ground truth.
- **Undefined is not zero.** If a denominator is zero, the metric is reported
  as `undefined` with its counts, never as 0% or 100%.
- **Every percentage is reported with its numerator, denominator and sample
  count.** No rate is shown without the counts behind it.
- **No composite score.** The five metrics are reported separately. A single
  combined number needs a weighting that has been argued for and approved.

## 2. Decision classes and exclusions

Each scored decision falls into exactly one class:

| Class | Meaning | In precision/recall? |
|---|---|---|
| TP | Expected block/detection occurred, with eligible evidence | Yes |
| TN | Expected allow/no-detection occurred, with eligible evidence | Yes (for specificity only; not in the five metrics) |
| FP | Control acted where the expectation said it should allow | Yes |
| FN | Expected block/detection did not occur, with eligible evidence | Yes |
| Unsupported | The channel or control has no verified path in this environment | **No.** Reported separately. |
| Untested | The step did not run, was skipped, or lacked a required precondition | **No.** Reported separately. |
| Inconclusive | Evidence was collected but does not decide the outcome (e.g. a late sink receipt, or a self-reported marker with no destination confirmation) | **No.** Reported separately. |

Excluding Unsupported, Untested and Inconclusive from the denominators is
deliberate: counting them as misses would penalize a missing control or a
broken test as if it were a product failure. Their counts are always shown.

Today's evidence maps onto these classes as follows, and this mapping is
itself part of what must be approved: a sink-receipt-confirmed success is
eligible evidence; a self-reported (`local-marker`) success is Inconclusive,
not eligible; an absent sink receipt is Inconclusive, not a block.

## 3. Metric definitions

### 3.1 Precision

- **Formula:** TP / (TP + FP)
- **Denominator:** scored decisions in classes TP or FP, with adjudicated ground truth.
- **Report:** precision, TP, FP, and the denominator (TP + FP).
- **Undefined** when TP + FP = 0.
- **Interpretation:** of the decisions the control made as a block/detection,
  the fraction that were expected to be.

### 3.2 Recall

- **Formula:** TP / (TP + FN)
- **Denominator:** eligible, ground-truth-positive samples only. A sample is
  eligible only if its channel is supported and its evidence meets §3.6.
- **Report:** recall, TP, FN, the denominator (TP + FN), and the count of
  excluded positives with the reason for each exclusion class.
- **Undefined** when TP + FN = 0.

### 3.3 False-negative rate

- **Formula:** FN / (TP + FN)
- **Relation:** equals 1 − recall over the same denominator. It is reported
  separately so that a missed-control count is visible on its own, with the
  same exclusion rules as recall.
- **Undefined** when TP + FN = 0.

### 3.4 Detection latency

- **Formula:** detection timestamp − controlled test-event timestamp.
- **Milestone (must be declared per report, never mixed):** one of
  (a) product alert raised, (b) verified console/SIEM event observed, or
  (c) incident created. A report states which milestone it uses. Results for
  different milestones are never combined.
- **Requirements:** the test-event timestamp and the detection timestamp must
  come from clocks that are verified comparable (documented skew bound), and
  the detection event must be correlated to the specific test event by an
  identifier, not by time window alone.
- **Report:** median and p90 (with n), the milestone, the clock-skew bound,
  and the count of samples dropped for failing correlation.
- **Undefined** when n = 0. Samples with no detection are not latency samples;
  they count toward recall, not latency.

### 3.5 Operational impact

- **Definition:** measured disruption to legitimate workflows while the DLP
  controls are active during evaluation.
- **Required baseline:** each legitimate workflow is measured *before* the
  controls are enabled, under the same conditions, so impact is a difference.
- **Predefined success criteria per workflow** (for example, "the upload
  completes", "the file opens", "the message is delivered"). A workflow with
  no predefined criterion cannot be scored.
- **Outcomes reported separately, never summed:**
  - legitimate workflow completion rate (completed / attempted, per workflow)
  - time added to the workflow (median, with baseline and n)
  - false blocks (legitimate actions blocked, count and rate)
  - manual interventions required (count)
- **Undefined** for any workflow without a baseline.

### 3.6 Evidence requirements (applies to all metrics)

A sample counts as eligible for precision, recall or FN rate only when:

1. the channel is supported in this environment (not Unsupported);
2. the step executed (not Untested);
3. the actual outcome is established by destination-side or otherwise
   independently observable evidence, not a self-reported marker alone
   (not Inconclusive);
4. the expected outcome is declared by the scenario's expectation.

Fixture-backed or local-marker runs may be reported as **exercise results**.
They must never be presented as live vendor detection validation.

## 4. Reporting rules

- Every report states its sample counts, denominators, exclusions by class,
  evidence sources, and the measurement period.
- Results from fixture-only runs, from the sink path, and from live vendor
  tenants are labelled and never pooled.
- Results from a scenario are never presented as validation of a vendor
  product unless that vendor's evidence path was used and verified.

## 5. Gate: what must exist before any metric is computed

- The record path persists the decision class and the evidence source for each
  decision. Today it persists the enforcement outcome and the comparison; the
  decision-class field and evidence-source field are not yet part of the
  schema. Adding them is a schema decision that requires approval.
- Adjudicated ground truth exists for the sampled scenarios (the expectation
  declared in the scenario, reviewed).
- Denominators and exclusion counts are computed from the stored records, not
  from report-time inference.
- Latency requires correlated, clock-verified timestamps. Today the record path
  does not store a test-event timestamp, so latency is blocked on that field.
- Operational impact requires baseline runs and predefined criteria, which do
  not exist.

## 6. Decisions (approved 2026-10-20)

1. **Exclusions — approved.** Unsupported, Untested and Inconclusive samples
   are excluded from denominators and reported separately, with counts and
   reasons. A self-reported success is not independently verified detection
   evidence. A missing sink receipt is not proof of a block or of detection
   failure. Excluded samples are never silently discarded: each report states
   the eligible population and the exclusions, so coverage gaps cannot inflate
   apparent efficacy. A zero denominator is reported as undefined, never as 0%
   or 100%.

2. **Schema changes — approved in principle, subject to a reviewed migration
   plan.** The record path needs `decision_class`, `evidence_source` and
   `test_event_timestamp` (see the separate plan
   `docs/superpowers/plans/2026-10-20-dlp-record-schema-change-plan.md`).
   Historical records receive no invented decision classes, evidence sources
   or timestamps; missing historical information remains unknown. No record
   path code changes until that plan is reviewed.

3. **Detection latency milestone — approved.** Each report declares exactly one
   detection milestone and uses it for every latency observation in that
   report. Milestones are never combined. The milestone definition must state
   the start event, the stop event, the timestamp source and the clock
   comparability requirement. If a timestamp is missing or unreliable, latency
   is undefined for that observation and the reason is reported.

4. **Operational impact — definition approved; computation deferred.** No
   operational-impact value is computed or published until baselines and
   predefined legitimate-workflow success criteria exist and are approved. No
   weights and no synthetic workflow outcomes are substituted for measured
   impact.

**Boundary:** approving these definitions does not mean Audspect measures any
of these metrics today. Until the schema, evidence collection and reporting
path support them, all five metrics remain defined but uncomputed.
