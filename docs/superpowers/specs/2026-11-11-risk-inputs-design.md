# Risk inputs for the estimated annual loss (REQ-052): storage and access design

Status: DRAFT. Not approved. No storage, API or UI has been built. Decisions 1 to 4 below are open.

## Intent
The board one-pager shows an estimated annual loss range (`internal/riskquant`, `RenderBoardOnePager`). The figure needs customer-entered frequency and loss-per-event inputs. This document defines where those inputs live, who may change them, how changes are recorded, and which exposures count toward a report.

## Constraints from the existing system
- On-prem only, single tenant. Postgres, not SQL Server.
- Settings pattern in use: the report branding is a singleton row (`report_branding`). Reads are viewer-level (`GET /api/report/branding`), writes are admin-gated (`PUT`, permission `CanUpdateConnectorConfig`), and every write is audit-logged through `h.auditLog`.
- A report is attested over its canonical JSON (`Attest`). Anything placed on `FullReport` is covered by the attestation, so the loss figure's inputs are tamper-evident once they are in the report.
- Findings are keyed by ATT&CK technique ID (`FullReport.TopFindings[].TechniqueID`).

## Proposed design

**Storage.** Two tables.
- `risk_exposure_input`: one current row per technique ID. Columns: `technique_id` (primary key), `label`, `freq_low`, `freq_likely`, `freq_high`, `mag_low`, `mag_likely`, `mag_high`, `updated_by`, `updated_at`, `version`. Bounds are checked by `riskquant.Compute` on write as well as on read.
- `risk_exposure_input_history`: append-only. Each write stores the full prior row and the new row, with the actor and timestamp. This is the change record an examiner would ask for.
- Currency is one value for the deployment, in a singleton `risk_settings` row. A report carries one currency.

**Reads.** Viewer-level, like branding. `GET /api/risk/inputs` and `GET /api/risk/inputs/history`.

**Writes.** `PUT /api/risk/inputs/{technique_id}` and `DELETE` (which clears the inputs, so the exposure becomes unquantified again). Each write validates with `riskquant`, writes the current row and a history row in one transaction, and calls `h.auditLog`. The write permission is decided in Decision 1.

**Report wiring.** At report build time: load the inputs, select the exposures to count (Decision 2), call `riskquant.Compute`, and set `FullReport.RiskQuantification`. The attestation then covers the figure and its inputs as they were at that time.

**Failure behaviour.** If the input store is unreadable, the report builds without the loss card and says why. It never shows a figure built from partial inputs.

## Open decisions

1. **Who may enter and change inputs.** Options: (a) admin only, the same gate as report branding; (b) a new dedicated permission for a risk owner, granted to admin by default. Recommendation: (b), since frequency and loss estimates are a risk-owner decision and should not ride on connector-config rights.

2. **Which exposures count toward the figure.** Options: (a) only techniques that are open findings in the report being built; (b) every technique that has inputs, whether or not it failed in this run. Recommendation: (a). It matches the approved scope ("translate open gaps"). Under (b), a stale input for a technique that passed this run would be counted as open.

3. **History.** Options: (a) full append-only history table, as above; (b) audit-log entries carrying before and after values only. Recommendation: (a). The audit log is for events, and reconstructing a value at a past date is harder from it.

4. **Currency.** Options: (a) one currency per deployment; (b) a currency per report. Recommendation: (a), which keeps the total meaningful. Mixed-currency totals would need an exchange-rate source, and that is out of scope.

## Not in this design
- Currency conversion, Monte Carlo simulation, or any statistical confidence interval. The method is a bounded range from customer inputs, as stated in `riskquant`.
- Default inputs of any kind. Exposures without inputs stay unquantified.
- A UI for entry. It follows once the API is approved.

## Tests this design would need
- Write validation rejects what `riskquant` rejects.
- Every write produces exactly one history row carrying the prior values.
- A DELETE returns the exposure to unquantified, and it drops out of the total.
- Under Decision 2(a), an input for a technique absent from the report's findings does not change the figure.
- The RBAC matrix (`rbac_matrix_test.go`) lists each new route with its tier.
- The attestation changes when an input changes and stays the same when it does not.
