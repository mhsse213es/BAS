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
