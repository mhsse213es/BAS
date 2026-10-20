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
