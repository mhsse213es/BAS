# ABUSE-002 second-machine validation runbook

Status: cross-machine validation pending. ABUSE-002 is provisionally validated on one
machine (label `lab-i5-8250u-win10`, calibration v5). It must not be treated as
validated until this runbook passes on a second, materially different machine.

## Rules

- Do not change any threshold, alpha, minimum ratio, noise floor, attack band or
  minimum sample count after seeing the second machine's results. If separation fails,
  investigate the fixture or the measurement method, and record the investigation.
- A failed qualification on the second machine is a valid outcome. Record it.
- Keep the calibration record of the second machine as its own version. Do not
  overwrite v5.

## Prerequisites on the second machine

- Same repository revision as `main` (commit at or after `04489f10`).
- Go toolchain matching `go.mod`, and the Windows (or Linux) build of `apibas-lab`
  and `apibas-runner` from `orchestrator/cmd`.
- Environment variables for the lab: `APIBAS_CUSTOMER_A_TOKEN`,
  `APIBAS_CUSTOMER_B_TOKEN`, `APIBAS_CUSTOMER_A_REVOKED_TOKEN`,
  `APIBAS_LAB_ADMIN_TOKEN`. Use random values, not committed ones.
- No other heavy load on the machine during measurement.

## Step 1: capture the fingerprint and confirm the original calibration is rejected

Start the vulnerable lab and run ABUSE-002 once, without calibrating:

    apibas-lab -mode vulnerable -fixture orders-two-tenant -addr 127.0.0.1:8099
    apibas-runner -target http://127.0.0.1:8099 -scenario API-BAS-ABUSE-002 -machine second-machine-label

Expected: `timing_verdict` is `ERROR/REQUALIFICATION_REQUIRED`, with a detail naming
the fingerprint. Save the full JSON output.

Also record the fingerprint the machine reports, by running the calibration in step 2
(its `profile.fingerprint` appears in the record).

## Step 2: explicitly calibrate this environment

Start both labs, then calibrate. The second machine gets its own label; the label is
display-only.

    apibas-lab -mode vulnerable -fixture orders-two-tenant -addr 127.0.0.1:8099
    apibas-lab -mode fixed      -fixture orders-two-tenant -addr 127.0.0.1:8100
    apibas-runner -target http://127.0.0.1:8099 -fixed-target http://127.0.0.1:8100 \
      -scenario API-BAS-ABUSE-002 -calibrate -machine <second-machine-label>

The command prints `qualified`, every refusal reason, the separation (`p`, `ratio`,
both medians), and the version it wrote. Record all of it.

If the record is unqualified, stop here, keep the record, and report the reasons.
Do not adjust the catalog to qualify.

## Step 3: adopt the new version only if it qualified

If `qualified: true`, set `calibration.version` and `calibration.baseline_ms` in
`orchestrator/internal/apibas/catalog/API-BAS-ABUSE-002.yaml` to the printed values,
then rebuild and commit the new record file.

Note that the catalog is shared. A second machine's record is one record in the
catalog's history, so the catalog can point to only one version at a time. Each machine
needs its own record, and runs on the other machine are refused until that machine's
record is in use. Record the cross-machine result in the QA log rather than in the
catalog.

## Step 4: run both variants under equivalent conditions

With the record adopted:

    apibas-runner -target http://127.0.0.1:8099 -scenario API-BAS-ABUSE-002 -machine <label>   # vulnerable lab
    apibas-runner -target http://127.0.0.1:8100 -scenario API-BAS-ABUSE-002 -machine <label>   # fixed lab

Repeat each run at least three times, on separate lab restarts, and record each
`timing_verdict`.

## Step 5: acceptance

The second environment passes only if all of the following hold:

- The vulnerable build returns `decision:FAIL` on every repeat.
- The fixed build returns `decision:PASS` on every repeat.
- The calibration record is qualified, and its separation p-value and ratio meet the
  declared alpha and minimum ratio.
- Every refusal reason from step 1 and step 2 is recorded, including any
  `CAL_*` reasons.

If any repeat fails, record the result as it is. Do not rerun until it passes.

## What to report back

- Machine description: CPU model, memory, OS build, Go version, and the fingerprint
  attributes from the calibration record.
- Every refusal reason from step 1 and step 2, verbatim.
- For the calibration: the vulnerable and fixed median and CV, the p-value, the ratio,
  and the number of samples.
- The `timing_verdict` of every repeat in step 4.
- The calibration record file name and version.
