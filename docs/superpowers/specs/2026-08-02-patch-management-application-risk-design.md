# Patch Management & Application Risk — Design

**Status:** Approved for planning
**Sub-project:** 3 of 6 in the Endpoint Health & Remediation initiative (1: Endpoint Risk & Remediation View — done; 2: Security Configuration & Identity Posture Collection — done; 4: One-Click Remediation Execution; 5: BAS-Verified Remediation; 6: Enterprise ops tail)
**Source:** This conversation, 2026-08-02, grounded via a code-research fork plus detailed user architecture review of the initial draft

## Problem

`internal/endpointrisk` still carries two placeholder categories: Patch Management and Application Risk (`notYetCollectedCategories` in `health.go`). Research this session found `scenarios/os-patch-posture.yaml` already exists but has a real bug — it mixes Windows-only PowerShell and Linux-only shell steps under one `supported_os: [windows, linux]` scenario with no per-step OS gating, so running it produces failure noise on the wrong OS. Application Risk has **zero** existing structured data — only a raw, unparsed "Installed Software" recon payload (`internal/db/postgres.go:714`) that isn't wired to anything.

## Goals

1. Fix and extend Patch Management using Sub-project 2's proven pattern (check_id, taxonomy, `PostureCheckInput`).
2. Build Application Risk from scratch: a new installed-software inventory check, server-side parsing, a curated EOL/risk catalog, and a distinct severity-weighted scoring model.
3. Both remaining placeholder categories in `internal/endpointrisk` become real.

## Non-goals

- No remediation execution (Sub-project 4) — findings describe the problem, not a fix mechanism.
- No external software-intelligence feed (CPE/NVD/vendor APIs) — the EOL catalog is a small, hand-curated, embedded V1 list, explicitly not exhaustive.
- No structured JSON output from the installed-software check — V1 stays delimited text (`Name|Version` per line), parsed server-side. Structured JSON output is a noted future direction, not built now.
- No per-entry configurable severity weights in the catalog — a single shared risk-tier → deduction table (critical/high/medium/low) is used for all entries in V1.
- No auto-run/scheduling — both new scenarios are manually executed, matching every other scenario (per Sub-project 2's established convention and the deferred Campaign-framework idea).

## 1. Track A: Patch Management

Retire `scenarios/os-patch-posture.yaml`, replaced by two OS-specific scenarios (mirroring Sub-project 2's Windows/Linux split):

- `scenarios/windows-patch-posture.yaml` — `supported_os: [windows]`, `Get-HotFix`-based last-patch-date check.
- `scenarios/linux-patch-posture.yaml` — `supported_os: [linux]`, pending-security-update count (`apt`/`dnf`) + last-patch-age-by-file-mtime checks.

Each step gets a `check_id` (e.g. `windows-last-patch-age`, `linux-pending-security-updates`, `linux-last-patch-age`) and a `category: patch-management` entry in `internal/endpointrisk/categories.yaml`. No new Go code: `postureCheckInput`/`PostureCheckInput` (Sub-project 2) already do everything Patch Management needs — it's a fixed pass/fail checklist exactly like Security Configuration/Identity. `patchManagementInput` is a one-line wrapper, same shape as `securityConfigInput`/`identityInput`.

## 2. Track B: Application Risk

### 2a. Evidence-size schema fix (prerequisite)

`RawOutput` is hard-truncated to 3000 chars (`interpreter.go:70`) — too small for a full installed-software list. Fix generically, not just for this one check:

- `scenario.Step` gains `MaxOutputBytes int` (`yaml:"max_output_bytes,omitempty"`), default 0 meaning "use the existing 3000 default" — every current scenario is unaffected.
- `models.SimulationResult` gains `Truncated bool` and `OriginalOutputBytes int` (`json:"truncated,omitempty"` / `json:"originalOutputBytes,omitempty"`) so truncation is visible to parsers/UI instead of silent.
- `scenario.Interpret` uses `step.MaxOutputBytes` when > 0, else 3000, and records whether the combined output actually exceeded that limit.
- The installed-software scenarios set `max_output_bytes: 20000`.

### 2b. Installed-software inventory scenarios

- `scenarios/windows-installed-software.yaml` — one step, `check_id: windows-installed-software`, PowerShell enumerating both `Uninstall` registry hives, emitting `DisplayName|DisplayVersion` one per line.
- `scenarios/linux-installed-software.yaml` — one step, `check_id: linux-installed-software`, `dpkg-query -W -f='${Package}|${Version}\n'` (Debian-family; `rpm -qa --qf` as a documented alternative for RPM-family, V1 ships the `dpkg` form since the existing Linux scenarios already target Ubuntu).

These are inventory dumps, not pass/fail checks — `technique_id: T1082` (System Information Discovery, matching the existing seeded payload's own technique), no PASS:/FAIL: convention needed; `interpretCustom`'s exit-code-0-is-pass default is irrelevant here since this check's *result* (pass/fail) isn't used — only its `RawOutput` is consumed.

### 2c. Parsing

New `internal/api/appliskinventory.go` (or a function in `endpointrisk_aggregations.go` if small enough — decided at plan time): `parseInstalledSoftware(rawOutput string) []endpointrisk.InstalledApp{Name, Version}` — splits on newlines, splits each line on `|`, skips malformed lines rather than erroring (evidence from a real machine is messy; a handful of bad lines shouldn't lose the rest).

### 2d. EOL/risk catalog

New `internal/endpointrisk/eol_catalog.yaml` + `eol.go`, embedded like `categories.yaml`/`taxonomy.go`:

```yaml
software:
  - id: flash
    vendor: Adobe
    product: Flash Player
    match: ["Adobe Flash Player"]
    risk: critical
    reason: End of life -- no longer receives security updates.
    recommendation: Remove Adobe Flash Player immediately.
    reference: "https://www.adobe.com/products/flashplayer/end-of-life.html"

  - id: java8
    vendor: Oracle
    product: Java
    match: ["Java(TM) 8", "JRE 8", "JDK 8", "Java 8"]
    version_max: "8"
    risk: high
    reason: End of public support for Java 8.
    recommendation: Upgrade to a supported Java LTS release (17 or newer).
```

~20-30 entries covering: Adobe Flash, Internet Explorer, Java 6/7/8, Python 2, Microsoft Office 2010/2013, .NET Framework 3.5/4.0, Silverlight, and a few other well-known EOL products. `version_max` is optional and only checked when the installed version string parses as a simple `major` or `major.minor` number — anything unparseable falls back to name-only matching (never blocks a match, only sometimes prevents a false positive).

`Catalog.Lookup(appName, appVersion string) (entry CatalogEntry, ok bool)`: normalizes `appName` (lowercase, strip `(TM)`/`®`/extra whitespace) before testing each entry's `match` patterns as case-insensitive substrings.

### 2e. Scoring

New type, deliberately distinct from `PostureCheckInput` (different problem domain — an open-ended scan, not a fixed checklist):

```go
type ApplicationRiskInput struct {
	Score       int // 0-100, severity-weighted deduction from 100
	AppsScanned int
	Findings    []Finding // one per unique matched catalog id, deduplicated
	Collected   bool
}
```

Deduction weights (shared constant table, not per-entry): `critical: 25, high: 15, medium: 5, low: 2`. Score starts at 100, subtracts each **unique matched catalog `id`**'s weight once regardless of how many installed apps matched it (e.g. three Java 8 components all matching `id: java8` deduct once, not three times), floors at 0.

### 2f. Aggregation

`applicationRiskInput(ctx, agentID, asOf, allResults) endpointrisk.ApplicationRiskInput` in `internal/api`: finds the most recent `windows-installed-software`/`linux-installed-software` result (asOf-filtered, whichever check_id is present for that agent's OS), parses it, looks up every parsed app against the catalog, deduplicates by catalog id, builds `Finding`s (`ID` = catalog id, `Title`/`Risk`/`Remediation`/`Reference` from the catalog entry, `Observed` = the actual installed name/version that matched), computes the score.

## 3. Wiring into `ComputeHealth`

`HealthInputs` grows from 4 to 6 fields:

```go
type HealthInputs struct {
	Compliance     ComplianceInput
	BAS            BASReadinessInput
	SecurityConfig PostureCheckInput
	Identity       PostureCheckInput
	PatchManagement PostureCheckInput
	ApplicationRisk ApplicationRiskInput
}
```

`CategoryPatchManagement` and `CategoryApplicationRisk` move out of `notYetCollectedCategories` (which becomes empty — every one of the original 9 categories is now real-or-uncollected, none are permanent placeholders) into real `CategoryScore` blocks, following the exact `secCat`/`idCat` pattern from Sub-project 2.

**Trend** extends its new/resolved-findings diff pool from 2 categories (SecurityConfig + Identity) to 4 (+ PatchManagement + ApplicationRisk) — both are stably keyed (`check_id` / catalog `id`) the same way, so the diff generalizes cleanly. `trendInputScore` extends to average across up to 6 collected inputs instead of 4.

## 4. UI surfaces

No new tabs — Patch Management and Application Risk render through the existing `_riskCategoryCard`/`renderAgtRisk` machinery from Sub-project 1/2 automatically, since they become ordinary real `CategoryScore` entries. Application Risk's findings naturally show `Observed` (the matched app/version) and `Reference` (catalog URL) via the finding-field rendering Sub-project 2 already added.

## 5. Testing

- `internal/scenario`: `MaxOutputBytes` override behavior in `Interpret` (uses step's value when set, 3000 default otherwise; `Truncated`/`OriginalOutputBytes` populated correctly).
- `internal/endpointrisk`: catalog loading (malformed YAML, duplicate id, unknown risk tier), `Lookup` matching (exact match, case-insensitive, version_max gating, unparseable-version fallback, no match), `ComputeHealth` with the two new categories present/absent, trend diff across all 4 stably-keyed categories.
- `internal/api`: `parseInstalledSoftware` (empty input, malformed lines skipped, normal input), `applicationRiskInput` (no results, unmapped check_id, historical asOf, dedup-by-catalog-id-not-by-row), `patchManagementInput` (thin wrapper, same test shape as `securityConfigInput`).
- Frontend: `node --check` only, per established convention — no new rendering code needed since both categories reuse existing card/finding rendering.
