# dlpreport §7 Metrics (Prevention Effectiveness and Control Coverage) — Design Spec

## Intent

Closes the first two of `dlp.txt` §7's five named metrics that can be computed from the existing §6 `Record` type:

> **Prevention effectiveness.** Proportion of applicable prohibited actions demonstrably blocked or contained, measured against independently verified attempts. Report by channel, data class, policy and severity.
>
> **Unknown results must not count as successful prevention.** Similarly, a test that was never executable must not be counted as a failed DLP control.

## Scope limits, stated up front

§7's other three metrics cannot be computed honestly from `Record` today, and this slice does not attempt them:

- **Classification quality (precision, recall, false-negative rate).** `Record.Classification` collapses false positives and false negatives into one `Incorrect` value. Precision and recall need the confusion matrix, which `Record` does not carry. Reporting them from `Record` would invent numbers.
- **Detection and investigation (latency, completeness).** Needs timestamps and telemetry timing, which `Record` does not carry.
- **Operational impact (false-positive rate, legitimate-workflow success, override frequency).** Needs legitimate-workflow outcomes, which `Record` does not carry.

Those are named gaps, not silent omissions.

## Why the grouping key is caller-supplied

§7 asks for reporting "by channel, data class, policy and severity." `Record` has no channel, data-class, policy or severity field, and this slice does not add them, because that would widen the §6 contract. Instead, `PreventionByGroup` takes a `key func(Record) string`, and the caller decides the grouping. The function never reads a field that does not exist.

## Definitions

Prevention is counted from `Record.Enforcement`:

| Enforcement | Counted as |
|-------------|-----------|
| `Blocked`, `Quarantined`, `Encrypted` | Prevented |
| `Allowed` | Allowed (prevention failed) |
| `Overridden` | Overridden (prevention bypassed by a user) |
| `Challenged` | Challenged (not prevented) |
| `Unknown`, empty, or any unrecognized value | Unknown |

- `Challenged` is NOT counted as prevented. A challenge is only prevention if the user declines, and that outcome is not in this vocabulary. Counting it as prevented would inflate the rate.
- Unrecognized values fall to Unknown, never to Prevented.

**Rate** = Prevented / Total, where Total includes Unknown. This is the conservative choice: an unresolved result lowers the rate rather than being dropped. Unknown is also reported on its own so a reader can see how much of the rate rests on missing evidence.

## Coverage

A group is measurable when it has at least one record whose enforcement is not Unknown. A group with only Unknown records is reported with `Measurable: 0` and a rate of zero, so it cannot read as a passing or failing control. `dlp.txt` §7's "identify channels with no measurable coverage" is answered by the `Measurable` count.

## Goals

1. `PreventionStats` struct: `Total`, `Prevented`, `Allowed`, `Overridden`, `Challenged`, `Unknown`, `Measurable`, and `Rate float64`.
2. `PreventionByGroup(records []Record, key func(Record) string) map[string]PreventionStats`.
3. `classifyEnforcement(EnforcementOutcome)` as a private switch, so the mapping table is the only place it is defined.

## Non-goals

- No precision, recall, or false-negative rate.
- No detection latency, operational-impact, or control-consistency-variance metrics.
- No new fields on `Record`.
- No wiring into the run or report pipeline.

## Anti-goals

- Must never count Unknown or an unrecognized enforcement value as Prevented.
- Must never count Challenged as Prevented.
- Must never drop a record from Total, which would inflate the rate.
- Must never return a non-zero rate for a group with `Measurable == 0`.
