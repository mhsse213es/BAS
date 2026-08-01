# Control Taxonomy & Control Health Foundation — Design

**Status:** Approved for planning
**Sub-project:** 1 of 5 in the Control Effectiveness Assurance Layer initiative (2: Executive Security Validation Dashboard, 3: Compliance Drift Detection, 4: Remediation Validation, 5: Risk Register Integration — all depend on this one)
**Source:** `bas_audit.txt` (repo root) + user's prioritized roadmap and architecture review, this conversation, 2026-08-01

## Problem

Audspect already has evidence-based compliance-framework mapping (`internal/compliance/mapper.go`, 7 frameworks) and detection-evidence capture (`internal/verification`, SIEM/EDR-connector-backed). But there is no control-category taxonomy anywhere in the codebase — `internal/analytics/` is organized by data source (compliance, campaigns, risk, exposure), not by the control categories executives and auditors actually think in (Endpoint Protection, Identity & Access, Email Security, ...). Without that grouping, there is nothing to build an executive-facing health view, drift detection, or risk-register linkage on top of. This sub-project builds that missing foundation: a technique-to-category taxonomy and a Control Health engine that computes each category's health from live evidence.

## Goals

1. A curated taxonomy mapping ATT&CK technique IDs to 10 control categories, supporting multiple categories per technique (primary + secondary), not a forced one-to-one mapping.
2. A `internal/controlhealth` package computing, per category: independent Prevention Health and Detection Health, a coverage-gated Overall Health, a coverage percentage, and a trend — all from evidence that already exists (`models.SimulationResult`, `internal/verification`).
3. One new read-only API endpoint exposing this, fleet-wide.

## Non-goals

- No frontend/dashboard changes — that's Sub-project 2, which consumes this endpoint.
- No drift detection / auto-generated findings on regression — Sub-project 3.
- No gating of finding remediation on re-verification — Sub-project 4.
- No risk register — Sub-project 5.
- Per-agent/per-asset health drill-down — V1 is fleet-wide only; the data model doesn't preclude it later, but no endpoint exposes it now.
- Secondary category mappings are stored and indexed (so a technique can be looked up against every category it touches) but the health *rollup* in V1 only uses each technique's primary category. Drill-down UI that shows "this technique also touches Application Control and Detection & Response" is Sub-project 2's decision to make, not built here.

## 1. Taxonomy data model

New embedded YAML, following `internal/compliance/mappings/*.yaml`'s precedent exactly:

```yaml
# internal/controlhealth/categories.yaml
categories:
  - id: endpoint-protection
    name: Endpoint Protection
  - id: identity-access
    name: Identity & Access Management
  - id: email-security
    name: Email Security
  - id: network-security
    name: Network Security
  - id: data-protection
    name: Data Protection
  - id: privileged-access
    name: Privileged Access
  - id: cloud-security
    name: Cloud Security
  - id: detection-response
    name: Detection & Response
  - id: application-control
    name: Application Control
  - id: backup-recovery
    name: Backup & Recovery

techniques:
  - id: T1003
    primary: identity-access
    secondary: [privileged-access, endpoint-protection]
  - id: T1059
    primary: endpoint-protection
    secondary: [application-control, detection-response]
  - id: T1566
    primary: email-security
    secondary: [detection-response]
  - id: T1041
    primary: data-protection
    secondary: [network-security]
  # ... curated per-technique, base technique IDs (no sub-technique suffix),
  # matched against results the same way compliance.Mapper does (see §2).
```

A technique can belong to many categories (secondary), but has exactly one **primary** category — the one the executive rollup (Sub-project 2) reads by default. This avoids the "forced single category" problem the user flagged: a technique's full control impact is preserved and queryable, without every category's health being diluted by every tangentially-related technique.

```go
// internal/controlhealth/types.go
type CategoryDef struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}
type TechniqueMapping struct {
	ID        string   `yaml:"id"`
	Primary   string   `yaml:"primary"`
	Secondary []string `yaml:"secondary"`
}
```

```go
// internal/controlhealth/mapper.go
type Mapper struct {
	categories map[string]CategoryDef       // categoryID -> def
	primary    map[string][]string          // categoryID -> []techniqueID (primary only)
	techToAll  map[string][]string          // techniqueID -> []categoryID (primary+secondary)
	techToPrimary map[string]string         // techniqueID -> categoryID
}
func NewMapper() (*Mapper, error)
func (m *Mapper) Categories() []CategoryDef
func (m *Mapper) PrimaryTechniques(categoryID string) []string
func (m *Mapper) CategoriesForTechnique(techID string) (primary string, all []string)
```

## 2. Evidence streams

**Prevention Health** reuses `models.SimulationResult` with the exact same pass/fail classification `compliance.buildResultIndexes` already uses (`internal/compliance/mapper.go:395-410`): `ResultPass` and `ResultBlocked` count as passed, `ResultFail` counts as failed, `ResultSkipped` and `ResultError` are excluded entirely (not a security outcome). Technique matching supports both exact (`T1059.001`) and base (`T1059`) IDs, same dual-index (`exactIdx`/`baseIdx`) pattern as the compliance mapper.

**Detection Health** reuses `internal/verification.Record` (`internal/verification/store.go:75-93`) — the same store SP3/Purple-Team-Packs already writes to via SIEM/EDR connectors. Only records with `WorkflowState == StateApproved` and `Active == true` count (matching that package's own documented convention that "only an Approved attestation feeds Coverage"). `Result == ResultDetected` counts as passed, `ResultNotDetected` as failed, `ResultNotApplicable` is excluded. `internal/verification.Store` doesn't currently expose a "all records for a set of technique IDs within a window" query — `internal/controlhealth` adds its own lightweight direct read (a new small query, not a `Store` method), the same way `internal/pathcorrelation/runlookup.go`'s `SQLRunLookup` already reads verification data directly rather than going through `Store`.

## 3. Rollup and Health computation

For a category, using its **primary**-mapped technique list and a lookback window (default 30 days, `?windowDays=` overridable on the endpoint):

- **MappedTechniques** = count of techniques whose primary category is this one.
- **ValidatedTechniques** = of those, how many have at least one Prevention *or* Detection result within the window.
- **Coverage** = `ValidatedTechniques / MappedTechniques * 100`, rounded.
- **Prevention Health** = weakest-link over each mapped technique's *most recent* Prevention result within the window: `fail` if any technique's latest result is fail; `pass` if every technique with a result passed; `unknown` if no technique has any result.
- **Detection Health** = the same weakest-link rule, applied to Detection results.
- **EvidenceCount** = total individual Prevention + Detection result records considered (not deduplicated by technique — this is a raw evidence-volume count, matching `bas_audit.txt`'s "147 successful validations, 2 failures" framing).

**Overall Health** — coverage-gated, per the user's exact table plus the coverage floor they required:

```
if preventionHealth == unknown:
    Overall = Unknown
elif coverage < 20:
    Overall = Unknown          // too little evidence to claim anything
elif preventionHealth == pass:
    Overall = coverage >= 70 ? Healthy : PartiallyValidated
elif preventionHealth == fail and detectionHealth == pass:
    Overall = Degraded
elif preventionHealth == fail and detectionHealth == fail:
    Overall = Critical
else: // preventionHealth == fail, detectionHealth == unknown (never verified either way)
    Overall = Degraded
```

Two things in this table are my proposed defaults, not something you specified, and are worth confirming once you see them against real data:
- The 20% / 70% coverage thresholds (named Go constants `coverageUnknownFloor`, `coverageHealthyFloor`).
- The `prevention fail + detection unknown` case (a known prevention gap that's never been checked for detection) — your table didn't cover this combination. I mapped it to `Degraded` rather than `Critical`, reasoning that "never verified" shouldn't score as badly as "verified and confirmed failing." If you'd rather this case read as `Critical` (treat unverified detection as a failure, not a neutral) or as its own `Unknown` state, say so and I'll change it before writing the plan.

**Trend** compares `OverallHealth` computed as-of now vs. as-of 7 days ago (the health function takes an `asOf time.Time` cutoff and only considers evidence timestamped at or before it — a pure, testable parameter, no new snapshot table needed). Health states rank `Healthy > PartiallyValidated > Degraded > Critical`; if either side is `Unknown`, Trend is `InsufficientData`; otherwise `Improving` / `Stable` / `Declining` by rank comparison. This computes trend from the *state*, not raw pass-rate, per your correction — a 95%→96% pass-rate wobble inside "Critical" no longer reads as improving.

## 4. API

```
GET /api/controlhealth/summary?windowDays=30
```

```json
{
  "categories": [
    {
      "id": "endpoint-protection",
      "name": "Endpoint Protection",
      "preventionHealth": "pass",
      "detectionHealth": "pass",
      "overallHealth": "Healthy",
      "coverage": 74,
      "validatedTechniques": 31,
      "mappedTechniques": 42,
      "evidenceCount": 618,
      "trend": "Stable",
      "lastValidated": "2026-07-31T10:00:00Z"
    }
  ]
}
```

Fleet-wide only (no `agentId` filter in V1, consistent with the Executive Dashboard's existing fleet-wide framing). Read-only, Viewer+ role, matching every other `/api/*/summary` endpoint's access convention in this codebase.

## 5. Testing

- `mapper_test.go`: `NewMapper()` loads and indexes correctly; a technique's primary/secondary lookup round-trips; embedded YAML parses without error.
- `health_test.go`: table-driven tests covering every branch of the Overall Health logic in §3 (all Prevention×Detection×Coverage combinations), plus the weakest-link rollup (one fail among many passes → category fails) and the trend rank comparison (including the `Unknown` → `InsufficientData` case).
- No frontend changes in this sub-project.
