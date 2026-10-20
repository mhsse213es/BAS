# API BAS timing policy for expensive-request scenarios

Status: **approved** (decisions 1-7). Open questions below remain open and do not block the policy. Nothing here
changes existing thresholds or verdicts.

## Problem

A timing verdict is only as stable as the machine it runs on. On a shared machine, background load moves
medians and spread from run to run, so a fixed millisecond threshold can flip between PASS and FAIL. ABUSE-002
is timing-graded today. Its verdicts were stable in 5 of 5 runs per build on one machine, which is local evidence
only.

## Decisions proposed

1. **Work units decide where the product has them.** An expensive-request scenario should be graded on a
   deterministic work count the lab reports (items, rows, bytes, queries). That count is the same on every machine.
   Timing corroborates it and does not decide alone. A work-unit breach forces FAIL (already the rule for ABUSE-002).
2. **Thresholds come from the product requirement, not from measurements.** The ceiling is the business budget
   (for example, "no request above 250 ms"). The minimum ratio is the smallest effect worth reporting. Neither is
   chosen after seeing results. Changing one requires a new calibration version, and the reason is written in the
   record.
3. **No timing verdict without a qualifying record.** A scenario's thresholds must match a calibration record for
   the machine that runs it, field for field. Without a match the grade is ERROR (`CALIBRATION_MISMATCH`), never PASS.
   Records stay write-once and versioned, as now.
4. **Noise is INCONCLUSIVE, never a verdict.** Excessive spread on the baseline gates every verdict. Excessive spread
   on the attack gates only a FAIL: a PASS needs every round under the ceiling and a stable baseline, so one outlier
   cannot flip it. INCONCLUSIVE is a valid, reported result. It is not counted as validated.
5. **Repeatability before a claim.** A timing scenario is fixture-validated only after at least 5 runs per build on a
   qualified machine, with identical verdicts. The claim names the machine profile. Five runs on one machine do not
   show stability across machines or workloads.
6. **Quiet conditions and a recorded profile.** Timing runs record the machine fingerprint and the load at the time.
   Heavy timing runs go to staging, per the team's existing rule.
7. **Reporting stays separate.** Timing verdicts appear in the exploitability count with their machine profile.
   Their INCONCLUSIVE count is reported next to the validated count, not folded into it.

## What this does not decide

- The ceiling and minimum-ratio values for each scenario. Those are product decisions and need an owner.
- Whether staging hardware is the qualifying profile. That needs a decision on which machine is the reference.
- Whether ABUSE-002 moves to work-unit grading now. Proposed: yes, with timing kept as corroboration, as a
  separate change with its own record.

## Open questions (not yet decided)

1. Who sets the ceiling for each expensive-request scenario?
2. Is staging the reference machine, or the developer machine, for qualifying records?
3. Should ABUSE-002 be re-graded on work units in its own change, leaving its timing record in place?

## Execution status

Gated on the three decisions below. No new timing scenario and no new timing-based validation claim until they are recorded.

| Step | State | Finding |
|---|---|---|
| 1. Requirement owner and ABUSE-002 ceiling rationale | **Blocked** | No requirement owner is named. The 250 ms ceiling is documented in the QA log as chosen between the vulnerable median (about 1,340 ms) and the fixed refusal (under 1 ms). That is derived from observed measurements, which decision 1 rules out. The ceiling is provisional until an owner documents a requirement-based rationale. |
| 2. Qualify a staging reference machine | **Blocked** | No staging machine is qualified or recorded as controlled. The only calibration record was taken on `lab-i5-8250u-win10-go1.26.8`, a developer workstation. It does not qualify any other machine. |
| 3. Work-unit metric for ABUSE-002 | **Exists, with a caveat** | The lab reports `work_units` as periods multiplied by a constant (`lab.go`, `reportWorkPerPeriod`), and the grader enforces `max_work_units: 24000`. The count is self-reported by the product handler. It reflects the declared cost of the request and is not an independent measurement of work done. |
| 4. Implement scenario changes | **Not started** | Waits on steps 1 to 3. |
| 5. Five-run repeatability on qualified machine | **Not possible yet** | Waits on step 2. The five-run result for ABUSE-002 is local evidence on the developer workstation. |

### Decisions needed

1. Name the requirement owner for expensive-request ceilings. Until then, mark ABUSE-002's timing-based validation provisional, or leave the scenario ungraded on timing.
2. Confirm whether a controlled staging machine can be the reference. If not, defer qualification.
3. Decide whether ABUSE-002 is graded on work units, with timing kept as historical corroboration. The work-unit count is self-reported, so the decision should weigh that.

## Decisions recorded

1. **Ceiling.** No timing-based validation claim until the ceiling has a requirement-based rationale approved by a
   product or security requirement owner. No owner is formally assigned yet. That is an unresolved ownership decision,
   not an assumption that engineering measurements establish the requirement. The 250 ms ceiling is **provisional**.
   The observed 1,340 ms vulnerable result and sub-1 ms fixed refusal are not justification for it. Where no defensible
   requirement exists, the scenario is left ungraded on timing.
2. **Reference machine.** A controlled staging machine may be the reference. It needs a documented, reproducible
   configuration, a recorded fingerprint and load conditions, a qualified calibration record, the approved threshold,
   and five-run repeatability. Until a qualified machine exists, timing-based validation is blocked. The developer
   workstation's record is diagnostic evidence only.
3. **Work units.** The current `work_units` value is a declared request-cost input bound. It is not a measure of
   actual work performed, so it is not the primary grade. The 24,000 limit stays as a clearly labelled request-cost
   assertion. Timing stays as historical corroboration. Replacing timing with work-unit grading needs a metric of
   deterministic work performed, or independently verified resource consumption, as a separate design and
   implementation change.

## Enforcement

- ABUSE-002 carries `timing_claim: provisional` with the reason. The contract accepts the flag only on a timing
  scenario with a reason. Coverage evaluates the scenario but does not count it as validated. The measured report
  shows it under "Provisional", with the reason.
- Validated is 71 of 72 on the measured run. Exploitability validity of ABUSE-002 is unchanged. Only the validated
  claim is withheld.
- No new timing scenario is started, and no timing-based validation claim is made, until decisions 1 and 2 are met.
