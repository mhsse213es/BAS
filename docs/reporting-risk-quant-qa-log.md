# Financial risk quantification (REQ-052): QA log

## Scope delivered
- `orchestrator/internal/riskquant`: pure calculation. Annualised loss expectancy (frequency x loss per event) as a low / likely / high range per open exposure, with totals.
- Every frequency and magnitude is customer-entered. There are no default money figures or frequencies. An exposure without both is listed as unquantified and is excluded from totals; it is never counted as zero.
- Invalid input (negative, non-finite, unordered bounds, empty currency or ID) is an error, not dropped.
- Every Summary carries `Method` and `Limitations`: the figure is not a probability or a confidence interval, and exposures are treated as independent.

## Not delivered (decisions pending)
- Board one-pager and PDF integration: not wired. The render path is `reporting/board_report.go`.
- Storage and API for customer inputs: no table, endpoint or RBAC yet. Who may enter and change frequencies and magnitudes, and how changes are audited, is an open decision.
- Mapping from `FullReport.TopFindings` to exposure IDs: not built. Exposures are keyed by ATT&CK technique ID for now.
- Currency conversion and multiple currencies per model: not supported; one currency per Summary.

## Tests
- `go test ./internal/riskquant/` passes (5 tests). Red first: the package build failed before implementation.
- Covered: per-bound multiplication; totals over quantified exposures only; unquantified exposures listed, not zeroed; invalid-input errors (negative, NaN, Inf, unordered bounds, empty ID, empty currency); zero frequency quantified as zero; method and limitations present.
- `go vet ./internal/riskquant/` clean.

## Not verified
- No board report renders the figure. No customer has entered real inputs. The method has not been reviewed by a risk or finance specialist.

## Update: risk inputs built (approved design, 2026-11-11)
Decisions applied: dedicated permission `risk-inputs:manage` (admin by default); only open findings in the report count; full append-only history; one currency per deployment, stored explicitly with no default.

Built:
- Schema: `risk_settings` (currency, CHECK three upper-case letters), `risk_exposure_input` (CHECKs reject negative, NaN, infinite and unordered values even if the app is bypassed), `risk_exposure_input_history` (previous and new values, actor, time). The runtime role is revoked UPDATE and DELETE on the history table (app_role.go).
- Store `internal/riskinputs`: every set or clear runs in one transaction with a row lock; history records prior and new values.
- Selection `ExposuresForReport`: one exposure per distinct open finding; inputs for techniques not open are ignored.
- API: GET /api/risk/inputs and /{technique}/history (any signed-in user); PUT /api/risk/currency and PUT/DELETE /api/risk/inputs/{technique} (risk-inputs:manage). Every write is audit-logged.
- Report: on-demand and scheduled board reports attach the figure only when a currency is set and at least one open finding has inputs. Otherwise the card stays hidden.
- Attestation: `RiskQuantification` is part of FullReport, so it is in the canonical JSON that Attest covers. Each item carries the inputs it was computed from.

Tests run (all pass): `internal/riskinputs` (5 store tests against Postgres; 2 selection tests), `internal/riskquant` (6), `internal/auth` (permission matrix), `internal/api` risk tests (9 handler tests, real DB) and the RBAC matrix, `internal/reporting` (board card present and absent), `go build ./...`.

Not verified:
- The append-only guarantee is enforced by a REVOKE for the runtime role. No test yet connects as the runtime role and tries UPDATE/DELETE on the history table. This must be added.
- Attestation coverage is by construction (the field is in the canonical struct). No test changes an input and checks that the attested digest changes for the same totals.
- Reads are open to any signed-in user, matching the board figure that viewers already see. Confirm this before release.
- No UI for entry; the API only.
- The client ID recorded as actor is the user ID from the token, not a display name.
- The method has not been reviewed by a risk or finance specialist. No customer has entered real values.
