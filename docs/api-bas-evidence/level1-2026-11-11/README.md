# API BAS Level 1 evidence: lab validation of all catalogued scenarios

Run date: 11 November 2026. Code: `origin/main` at `511306fb` (the simulation runbook commit; no later commit had landed when the run started).

Command, from `orchestrator/`:

    go test ./internal/apibas/runner/ -run 'TestPhase28_MeasuredCoverage$' -count=1 -v -timeout 25m

Two runs, both passed (exit 0, about 65 seconds each).

## Files

- `level1-measured-coverage.txt`: the summary output of the first run.
- `level1-run-with-per-scenario-dump.txt`: the output of the second run, which also wrote one verdict line per scenario.
- `per-scenario.jsonl`: 151 lines, one per catalogued scenario, with the vulnerable and fixed outcomes (`Result`, `Exploitability`, `Control`, `Detection`, `Confidence`, `Reason`).

## How the per-scenario file was made

The test keeps the per-scenario verdicts in memory and does not write them out. The second run used a temporary change, not committed, that appends each scenario's outcome to the file named in `APIBAS_L1_DUMP`. The committed test code is unchanged. The verdicts come from the same lab and grader as the summary, but the dump itself is not part of the repository.

## Results

| Class | Count | Scenarios |
|---|---|---|
| Catalogued | 151 | all catalogue files |
| Validated (vulnerable FAIL exploited, fixed PASS enforced) | 148 | |
| Provisional (verdicts valid, timing claim not approved) | 1 | API-BAS-ABUSE-002 |
| Workflow-verified (simulated receiver, not in validated) | 1 | API-BAS-REPORT-001 |
| Unevaluated (no valid verdict) | 1 | API-BAS-REPORT-002 |
| Errors (execution or environment) | 0 | |
| Unsupported (no adapter) | 0 | |

From `per-scenario.jsonl`: 149 scenarios have the expected pattern (vulnerable FAIL exploited, fixed PASS enforced). That is the 148 validated plus ABUSE-002. REPORT-001 is PASS with control not applicable in the vulnerable build (no exploitability applies to a reporting obligation) and PASS enforced in the fixed build. REPORT-002 is SKIPPED with reason `deadline_not_defined_by_provision` in both builds.

Detection, reported separately from exploitability:

| Build | Detected | Not detected | Inconclusive | Not evaluated |
|---|---|---|---|---|
| Vulnerable | 93 | 22 | 1 | 35 |
| Fixed | 78 | 37 | 1 | 35 |

The 35 not-evaluated scenarios have no detection block. That is counted as not evaluated, not as a miss.

## What this does not show

- It shows the scenarios and the grader against the built-in lab only. It says nothing about a customer's API or about the product's job path.
- Detection is fixture-based. There is no live SIEM.
- Gaps the tool lists as open: native gRPC over HTTP/2 (only JSON transcoding has an adapter), WebSocket frame behaviour (only the handshake), certificate revocation (not tested).
