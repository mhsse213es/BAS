# Security Configuration & Identity Posture Collection — Design

**Status:** Approved for planning
**Sub-project:** 2 of 6 in the Endpoint Health & Remediation initiative (1: Endpoint Risk & Remediation View — done; 3: Patch Management Data; 4: One-Click Remediation Execution; 5: BAS-Verified Remediation; 6: Enterprise ops tail)
**Source:** User's Endpoint Health & Remediation proposal, this conversation, 2026-08-02, refined through a code-research fork plus detailed user architecture review of the initial draft

## Problem

Sub-project 1 shipped `internal/endpointrisk` with 5 real categories and 4 "Not yet collected" placeholders: Security Configuration, Identity, Patch Management, Application Risk. Research this session found the agent already has a fully generic `executor: local` primitive (`agent/simulate.go:248`, "the agent has no framework knowledge — it only sees executor + command") and a working precedent, `scenarios/cis-ubuntu-l1.yaml`, which already collects Linux security-configuration/identity-shaped data (firewall, SSH hardening, password policy) but has no category home for it. Windows has no equivalent scenario at all. This sub-project fills in the first two placeholder categories with real evidence — no new agent code required, only new scenario content plus server-side classification and aggregation.

## Goals

1. A new Windows `local_check` scenario covering the core BFSI-relevant Security Configuration + Identity checks.
2. A stable, ATT&CK-independent identity for each check (`check_id`), so taxonomy and reporting don't misrepresent configuration checks as MITRE techniques.
3. Wire both the new Windows scenario and the existing `cis-ubuntu-l1.yaml` into real `Security Configuration` / `Identity` categories in `internal/endpointrisk`.
4. Richer per-finding detail (expected/observed, pass state, timestamps, reference) and richer trend (new/resolved findings, not just a score delta) — extending `Finding` and `EndpointHealth.Trend` for all consumers, not just these two categories.

## Non-goals

- No new agent code — every check runs through the existing `executor: local` primitive.
- No auto-run/scheduling of the new scenario. Manual execution only, exactly like every other scenario today. (The user's longer-term idea — a rule-based Campaign framework that could later dispatch "run once on new agent" / weekly / monthly scenario sets — is explicitly deferred; noted for the roadmap, not built here.)
- No merge of this taxonomy into `internal/controlhealth`'s `categories.yaml`. A separate, structurally parallel taxonomy lives in `internal/endpointrisk` so the already-shipped, already-tested `controlhealth` package is untouched.
- No Patch Management or Application Risk work (Sub-project 3), even though `scenarios/os-patch-posture.yaml` already exists and is a strong head start for that later sub-project.
- No remediation execution (Sub-project 4) or BAS-verified remediation (Sub-project 5).

## 1. Stable check identity: `check_id`, ATT&CK as optional metadata

Configuration checks are not MITRE techniques. `cis-ubuntu-l1.yaml` already stretches `technique_id` for this purpose (three unrelated kernel checks all tagged `T1055`); doing the same for `BitLocker enabled` (no honest ATT&CK fit) would produce a misleading mapping in reports. Instead:

- **`scenario.Step` gets a new optional field**: `CheckID string` (`yaml:"check_id,omitempty" json:"checkId,omitempty"`), added at `orchestrator/internal/scenario/types.go:120` alongside the existing fields. `technique_id` stays on the step, now explicitly optional metadata for checks that don't need it (e.g. BitLocker omits it).
- **`models.SimulationResult` gets a matching new field**: `CheckID string` (`json:"checkId,omitempty"`), added to `orchestrator/internal/models/schema.go:36`'s struct.
- **`scenario.Interpret`** (`orchestrator/internal/scenario/interpreter.go:56`) copies `step.CheckID` straight through into the returned `SimulationResult`. This is the only place that needs to change to thread the field end-to-end — every other consumer of `SimulationResult` already ignores unknown-to-them fields.
- Existing scenarios (including `cis-ubuntu-l1.yaml`) are unaffected — `CheckID` is empty for them, and the new taxonomy simply won't match empty-`CheckID` results, so they continue contributing only to Compliance (via `technique_id`) exactly as today. Backfilling `check_id` onto the relevant `cis-ubuntu-l1.yaml` steps is done as part of Task work in this sub-project (see §7) so Linux gets real Security Configuration/Identity data too, per the already-approved "wire up both OSes" decision.

## 2. New scenario: `scenarios/windows-security-config.yaml`

`local_check: true`, `supported_os: [windows]`, executor `local` (PowerShell), same structure as `cis-ubuntu-l1.yaml`. `technique_id` is populated only where a check genuinely maps to a technique; `framework: custom` throughout.

| check_id | Category | technique_id (optional) |
|---|---|---|
| `windows-firewall-enabled` | security-configuration | T1562.004 |
| `windows-defender-realtime` | security-configuration | T1562.001 |
| `windows-bitlocker-enabled` | security-configuration | *(none — no honest ATT&CK fit)* |
| `windows-rdp-nla-required` | security-configuration | T1021.001 |
| `windows-smbv1-disabled` | security-configuration | T1021.002 |
| `windows-guest-account-disabled` | identity | T1078 |
| `windows-local-admin-count` | identity | T1078.003 |
| `windows-password-min-length` | identity | T1110 |
| `windows-password-max-age` | identity | T1110 |
| `windows-account-lockout-threshold` | identity | T1110 |

Exact PowerShell commands are pinned at plan-writing time (each is a one-line `Get-NetFirewallProfile`/`Get-MpComputerStatus`/`Get-BitLockerVolume`/registry or `net accounts` style read, consistent with `interpretCustom`'s pass/fail parsing).

## 3. Taxonomy: `internal/endpointrisk/categories.yaml` + `taxonomy.go`

A smaller sibling of `controlhealth`'s pattern (`internal/controlhealth/mapper.go`), not a shared file — separate package, separate embed, zero risk to `controlhealth`. Keyed by `check_id`, not `technique_id`:

```yaml
checks:
  - check_id: windows-firewall-enabled
    category: security-configuration
    weight: 1.0
  - check_id: windows-bitlocker-enabled
    category: security-configuration
    weight: 1.0
  # ... one entry per check in both windows-security-config.yaml and the
  # backfilled subset of cis-ubuntu-l1.yaml
```

`weight` is a real, used field (not a placeholder) — see §5. Category values are free strings (already `security-configuration` / `identity`, but nothing in the taxonomy loader hardcodes just these two), so adding `patch-management` or `application-risk` check entries later (Sub-project 3) needs no taxonomy code change.

```go
type Taxonomy struct{ /* checkID -> {category, weight} */ }
func NewTaxonomy() (*Taxonomy, error)
func (t *Taxonomy) CategoryForCheck(checkID string) (category string, weight float64, ok bool)
```

`NewTaxonomy` returns an error on malformed YAML or an unknown/empty category — same fail-fast contract as `controlhealth.NewMapper`.

## 4. `Finding` and `PostureCheckInput` — extended, shared

`internal/endpointrisk/types.go`'s `Finding` gains fields used by posture-check findings; every existing finding builder (attack-path, detection, vulnerability, compliance, BAS-readiness) leaves them zero-valued — purely additive, no behavior change for the 5 already-shipped categories:

```go
type Finding struct {
    ID               string     `json:"id,omitempty"`          // check_id, when this finding came from a posture check
    Title            string     `json:"title"`
    Description      string     `json:"description,omitempty"` // what the check verifies
    Severity         string     `json:"severity"`
    Risk             string     `json:"risk"`
    AffectedStandard string     `json:"affectedStandard,omitempty"`
    Remediation      string     `json:"remediation"`
    Reference        string     `json:"reference,omitempty"`   // e.g. "Microsoft Security Baseline"
    Expected         string     `json:"expected,omitempty"`
    Observed         string     `json:"observed,omitempty"`
    Passed           bool       `json:"passed"`
    LastObserved     *time.Time `json:"lastObserved,omitempty"`
    LastPassed       *time.Time `json:"lastPassed,omitempty"`
}
```

Per the user's explicit call: **do not** create `SecurityConfigInput`/`IdentityInput` types — one generic type serves both categories, since they're structurally identical:

```go
type PostureCheckInput struct {
    Score     int       // 0-100, weighted pass rate (see §5)
    Passed    int        // unweighted count, for "10/12 checks passed" display
    Failed    int
    Total     int
    Findings  []Finding  // one per currently-failing check_id, ID = check_id
    Collected bool
}
```

## 5. Aggregation: `postureCheckInput`

One shared function in `orchestrator/internal/api/endpointrisk_aggregations.go`, parameterized by target category (mirrors `complianceInput`'s existing per-agent pattern):

```go
func (h *Handler) postureCheckInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult, category string) endpointrisk.PostureCheckInput
```

Logic:
1. Filter `allResults` to rows with a non-empty `CheckID` whose taxonomy category matches `category` (unmapped/unknown `check_id` values are skipped, not errored — a check can exist in a scenario before its taxonomy entry is added).
2. Group by `check_id`; within `asOf`-filtered rows, keep the most recent result per `check_id` (`ExecutedAt`) as that check's current state — same "latest wins" convention `aggregateAgentResults` already establishes upstream.
3. `Total`/`Passed`/`Failed` are unweighted counts of latest-per-check results (`Result == models.ResultPass` vs. not). `Score` is the **weighted** pass rate: `100 * sum(weight of passed checks) / sum(weight of all checks)`, using each check's `weight` from the taxonomy (default 1.0 today — every check is equal-weighted in V1, but the field is real and consumed now, not a placeholder for later).
4. `Collected = Total > 0`.
5. `Findings`: one per currently-failing `check_id`, in scenario-declaration order. `LastObserved` = that check's latest `ExecutedAt` (within `asOf`). `LastPassed` = the most recent `ExecutedAt` among **all** historical rows (not just latest, still `<= asOf`) for that `check_id` where `Result == Pass`, or `nil` if it has never passed. `Expected`/`Observed`/`Description`/`Reference`/`Remediation` are populated from static per-check text keyed by `check_id` (a small lookup table alongside the scenario, not derived from raw command output).

`securityConfigInput`/`identityInput` become one-line wrappers: `h.postureCheckInput(ctx, agentID, asOf, allResults, "security-configuration")` / `"identity"`.

## 6. `ComputeHealth` — refactored inputs, weighted categories, richer trend

Adding two new categories to the existing 6-positional-parameter signature (already at its ergonomic limit) is a good time to bundle inputs into a struct — every call site is being touched anyway to add the two new values:

```go
type HealthInputs struct {
    Compliance     ComplianceInput
    BAS            BASReadinessInput
    SecurityConfig PostureCheckInput
    Identity       PostureCheckInput
}

func ComputeHealth(agentID string, profile exposure.AssetExposureProfile, now, past HealthInputs) EndpointHealth
```

`GetAgentRisk` and `GetAgentRiskSummary` (`orchestrator/internal/api/endpointrisk_handlers.go`) build `now`/`past HealthInputs` instead of 4 separate local variables, then call `endpointrisk.ComputeHealth(agentID, profile, now, past)`.

Security Configuration and Identity move out of the static `notYetCollectedCategories` list into real `CategoryScore` blocks, built exactly like the existing `compCat`/`basCat` pattern (score/deficit/findings from `Collected`). Only `CategoryPatchManagement` and `CategoryApplicationRisk` remain in `notYetCollectedCategories` after this sub-project.

**Trend** extends from a bare string to a struct, and from 2 evidence-row categories to 4 (Security Config and Identity are exactly as `asOf`-filterable as Compliance/BAS — flat `SimulationResult` rows filtered by `ExecutedAt`):

```go
type TrendDetail struct {
    Direction        string    `json:"direction"` // Improving | Stable | Declining | InsufficientData
    NewFindings      []Finding `json:"newFindings,omitempty"`
    ResolvedFindings []Finding `json:"resolvedFindings,omitempty"`
}
```

`Direction` keeps the existing banded compare-not-delta approach (`healthBand`), now averaged across whichever of the 4 evidence-row categories are `Collected`. `NewFindings`/`ResolvedFindings` are computed **only** from Security Configuration + Identity's `Findings` (`ID`-set diff between `now` and `past`) — Compliance and BAS-Readiness findings aren't stably keyed per-item the same way (a compliance finding's identity today is control-text-derived, not a check_id), so they stay covered by `Direction` only, exactly as they were in Sub-project 1. This mirrors how §6 of the Sub-project 1 spec already scoped trend deliberately rather than faking coverage it can't honestly provide.

`EndpointHealth.Trend` changes type from `string` to `TrendDetail`. `AgentRiskRow.Trend` (the fleet-list row) stays a plain `string` — set from `health.Trend.Direction` — since the fleet list is a summary and doesn't need per-finding diffs.

## 7. Changes to already-shipped Sub-project 1 code

Explicit list, since this sub-project modifies code that shipped and was tested this session, not just adds new files:

- `internal/scenario/types.go` — add `Step.CheckID` (additive).
- `internal/models/schema.go` — add `SimulationResult.CheckID` (additive).
- `internal/scenario/interpreter.go` — copy `step.CheckID` through (additive, one line).
- `internal/endpointrisk/types.go` — extend `Finding` (additive fields only), replace `Trend string` with `TrendDetail` on `EndpointHealth` (**breaking JSON shape change** — `"trend"` goes from a string to an object), add `PostureCheckInput`, add `HealthInputs`.
- `internal/endpointrisk/health.go` — `ComputeHealth` signature changes (struct params instead of 6 positional), Security Config/Identity move from placeholder to real, `computeTrend` rewritten for `TrendDetail` + 4 inputs.
- `internal/api/endpointrisk_handlers.go` — `GetAgentRisk`/`GetAgentRiskSummary` build `HealthInputs` and call the new `ComputeHealth` signature; `AgentRiskRow.Trend` reads `health.Trend.Direction`.
- `internal/api/endpointrisk_aggregations.go` — add `postureCheckInput` + two thin wrappers.
- `scenarios/cis-ubuntu-l1.yaml` — backfill `check_id` on the subset of steps that map to Security Configuration/Identity (firewall, SSH hardening, password policy, empty-password accounts). Existing `technique_id`/`framework` fields untouched, so Compliance's existing consumption of this scenario is unaffected.
- **Frontend** (`orchestrator/wwwroot/index.html`): `_riskTrendBadge` (fleet table) keeps reading a plain string — now `row.trend` (already a string via `AgentRiskRow`), no change needed there. `renderAgtRisk` (per-agent drill-down, added in Sub-project 1) currently reads `health.trend` as a string for its trend badge — this needs updating to read `health.trend.direction`, plus new rendering for `health.trend.newFindings`/`resolvedFindings` (a short "2 new, 1 resolved" line). Also render the new `Finding` fields (`expected`/`observed`/`lastObserved`) on category-card findings where present.

## 8. Testing

- `internal/scenario`: extend `interpreter_test.go` (or nearest existing test) to confirm `Interpret` copies `CheckID` through unchanged.
- `internal/endpointrisk`: extend `health_test.go` — weighted score computation, pass/fail/total counts, `TrendDetail` direction banding across 4 inputs, `NewFindings`/`ResolvedFindings` diffing (including the empty-diff and all-new/all-resolved edge cases), unmapped `check_id` handling, zero-weight-sum guard.
- `internal/endpointrisk`: new `taxonomy_test.go` — malformed YAML, unknown category value, duplicate `check_id`, empty taxonomy.
- `internal/api`: extend `endpointrisk_aggregations_test.go` — `postureCheckInput` with: empty scenario results, duplicate runs (newest wins), historical `asOf` (a check that passed then later failed — confirm `asOf` before the failure still reads pass), unknown/unmapped `check_id` (skipped, doesn't error), a Windows-only check against a Linux agent's results (no match, `Collected:false`), `LastPassed` correctly `nil` for a check that has only ever failed.
- `internal/api`: extend `endpointrisk_handlers_test.go`'s category-count assertion (9 total categories: now 7 collected + 2 placeholder, was 5 + 4) and add a mixed Windows/Linux fleet test to `GetAgentRiskSummary`.
- Frontend: `node --check` on the extracted inline script (established convention), manual review of the updated trend/finding rendering; full browser QA stays on the existing deferred-QA backlog.

## Out of scope / noted for later

- **Campaign framework** (rule-based scenario dispatch — "Run Once on new agents", weekly/monthly/quarterly recurring scans): the user's proposed long-term replacement for any enroll-triggered or scheduled execution. Explicitly not built here; V1 stays fully manual-execution, matching every other scenario.
- **Category weighting beyond per-check weight**: check-level `weight` is real and used (§5); category-level weighting (e.g. Security Config counting for more than Identity in the overall Health Score) is unchanged from Sub-project 1's equal-20%-per-category default — no new field added for that until there's a real tuning need.
