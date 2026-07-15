# SP4 Exposure Explorer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An asset-centric "how exposed is this box" API + UI: for every host (enrolled agent or attack-path-discovered-only), aggregate ATT&CK techniques threatening it, SP3 detection coverage, CVE/KEV/EPSS exposure, threat-group attribution, findings history, and a prioritized remediation list into one composite Exposure Score.

**Architecture:** New `internal/exposure` package — a pure aggregator over `internal/attackpath`, `internal/pathcorrelation`, `internal/relationships`, `internal/reporting/attackdata`, and two small direct-SQL readers (`cves`/`cve_epss`/`findings`/`agents`), with zero new DB tables. One `Build()` call computes every asset's profile in one pass (one graph build, one `Correlate()`, one batched CVE enrichment, one batched findings query — never N+1 per asset), returning an `*AssetGraph` with cheap `Summaries()`/`Profile(hostKey)` accessors. Exposed via `GET /api/exposure/assets` (index) and `GET /api/exposure/assets/{hostKey}` (detail), and a new "Exposure Explorer" dashboard tab.

**Tech Stack:** Go, PostgreSQL (pgx/pgxpool), chi router, testcontainers-go (`postgres:16-alpine`, Docker Desktop required), vanilla JS/HTML in `wwwroot/index.html`.

## Global Constraints

- **Deviation from the spec, made during planning (documented here, not silent):** the spec's `FindingsContext.Findings []findings.FindingRef` is replaced with `[]FindingSummary`, a small new type defined in `internal/exposure/types.go` with proper `json` tags and an `id` field. `findings.FindingRef` has no json tags (fields serialize in PascalCase, inconsistent with this API's camelCase convention) and carries no finding ID for UI drill-down. `internal/exposure` does not import `internal/findings` at all — it queries the `findings` table directly, same pattern as SP3's `SQLRunLookup` querying `verification_history` directly.
- **Deviation from the spec's literal `BuildProfile`/`BuildSummaries` shape:** the spec sketched two separate top-level functions; this plan replaces them with a single `Build()` call returning an `*AssetGraph` with `Summaries()`/`Profile()` accessors, so per-asset computation (CVE enrichment, findings) happens exactly once per request regardless of whether the caller wants the index, the detail view, or both. Same net API shape (`GET /api/exposure/assets`, `GET /api/exposure/assets/{hostKey}`), different internal wiring.
- Per-asset `AttackPathScore`/`DetectionCoverageScore` in this package are **derived risk proxies computed here**, not the fleet-wide `attackpath.Summary.AttackPathScore` / SP3 `AttackPathCorrelation.Score` reused verbatim — see the spec's "Per-asset AttackPathScore / DetectionCoverageScore" section for the exact formulas. Every task below implements those exact formulas; do not substitute the fleet-wide numbers.
- Garble/json-tag-map rule (from `project_garble_reflection` memory): not directly relevant here since v1 has no report-section integration, but every new exported type still needs complete `json` tags for the API's own JSON responses.
- `gofmt -w` the exact files a task touches, then `gofmt -l` to confirm — never a whole-directory sweep. Pre-existing CRLF `gofmt -l` noise on untouched files elsewhere in the repo is expected, not a regression (confirmed in SP2/SP3 validation).
- Docker Desktop must be running for any test touching a package's shared testcontainer (`internal/exposure`'s own `TestMain`, or `internal/api`'s existing one).
- KEV determination is `cves.source = 'cisa-kev'` (confirmed precedent: `internal/reporting/engine.go:3124`), **not** a non-null `date_added` check.
- Only `technique_cve_relationships` rows with `status = 'Active'` and `effective_confidence IN ('High','Medium')` count as authoritative CVE links (documented convention in `internal/relationships/store.go`, mirrored by the same precedent query above). Never treat a `Proposed`/`Deprecated`/`Disputed`/`Retired` relationship as real exposure.

## File structure

| File | Responsibility |
|---|---|
| `internal/exposure/types.go` | All exported types + `RelationshipLookup`/`FindingsLookup`/`CVEEnricher` interfaces (new package) |
| `internal/exposure/cve.go` | CVE severity formula + `vulnerabilitiesForTechniques` (pure, no DB) |
| `internal/exposure/sql.go` | `SQLCVEEnricher`, `SQLFindingsLookup` (direct SQL against `cves`/`cve_epss`/`findings`) |
| `internal/exposure/riskscore.go` | Asset union/dedup + per-asset `AttackPathRisk`/`DetectionRisk` derivation (pure, no DB) |
| `internal/exposure/build.go` | `Build()` entry point + `AssetGraph.Summaries()`/`.Profile()` |
| `internal/api/exposure_handlers.go` | `GET /api/exposure/assets`, `GET /api/exposure/assets/{hostKey}` |
| `internal/api/routes.go` | Modify: register the two new routes |
| `internal/api/rbac_matrix_test.go` | Modify: add the two new RBAC entries |
| `orchestrator/cmd/server/wwwroot/index.html` | Modify: new "Exposure Explorer" nav tab (index table + detail drawer) |

---

### Task 1: `internal/exposure` — core types + CVE severity logic

**Files:**
- Create: `orchestrator/internal/exposure/types.go`
- Create: `orchestrator/internal/exposure/cve.go`
- Test: `orchestrator/internal/exposure/cve_test.go`

**Interfaces:**
- Consumes: `relationships.Relationship` (`internal/relationships`, fields `CVEID`, `Status`, `EffectiveConfidence`), `relationships.StatusActive`, `relationships.ConfidenceHigh`, `relationships.ConfidenceMedium` (all already exported).
- Produces: every type in the File Structure table's `types.go` row, plus `cveSeverity(cvss float64, kev bool, epss float64) float64` and `vulnerabilitiesForTechniques(ctx, techniqueIDs []string, rels RelationshipLookup, enricher CVEEnricher) (map[string][]CVEExposure, error)` — later tasks call both by these exact names.

- [ ] **Step 1: Write `types.go`**

```go
// orchestrator/internal/exposure/types.go

// Package exposure is the SP4 Exposure Explorer: an asset-centric aggregator
// over the attack-path graph (internal/attackpath), detection coverage
// (internal/pathcorrelation), the CVE Relationship Store
// (internal/relationships), and ATT&CK threat-intel enrichment
// (internal/reporting/attackdata). It is a pure consumer — it owns no DB
// tables and never modifies any of those subsystems' own state.
package exposure

import (
	"context"

	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/relationships"
)

// AssetIdentity is who/what this asset is.
type AssetIdentity struct {
	HostKey    string `json:"hostKey"`
	Label      string `json:"label"`
	Managed    bool   `json:"managed"`
	AgentID    string `json:"agentId,omitempty"`
	OS         string `json:"os,omitempty"`
	IP         string `json:"ip,omitempty"`
	CrownJewel string `json:"crownJewel,omitempty"`
	Segment    string `json:"segment,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`
}

// ScoreBreakdown — all fields 0-100, higher = safer. AttackPathScore and
// DetectionCoverageScore here are ASSET-SCOPED derived values computed by
// this package (see riskscore.go), NOT the fleet-wide numbers from
// attackpath.Summary / pathcorrelation.AttackPathCorrelation.
type ScoreBreakdown struct {
	ExposureScore          int `json:"exposureScore"`
	AttackPathScore        int `json:"attackPathScore"`
	DetectionCoverageScore int `json:"detectionCoverageScore"`
	VulnerabilityScore     int `json:"vulnerabilityScore"`
}

// AttackPathContext is this asset's position in the attack-path graph.
// DistanceToNearestCrownJewel is -1 when no crown jewel is reachable FROM
// this asset (distinct from 0, which means this asset IS a crown jewel).
type AttackPathContext struct {
	Reachable                   bool    `json:"reachable"`
	OnShortestDAPath            bool    `json:"onShortestDaPath"`
	DistanceToNearestCrownJewel int     `json:"distanceToNearestCrownJewel"`
	IsChokePoint                bool    `json:"isChokePoint"`
	ChokePointCoverage          float64 `json:"chokePointCoverage,omitempty"`
}

// DetectionContext is the subset of SP3's annotated edges that touch this
// asset (From or To), plus a count rollup.
type DetectionContext struct {
	Edges   []pathcorrelation.AnnotatedEdge `json:"edges"`
	Covered int                             `json:"covered"`
	Partial int                             `json:"partial"`
	Gap     int                             `json:"gap"`
	Unknown int                             `json:"unknown"`
}

// CVEExposure is one CVE reached via an Active, High/Medium-confidence
// technique-CVE relationship for a technique threatening this asset.
type CVEExposure struct {
	CVEID       string  `json:"cveId"`
	CVSS        float64 `json:"cvss,omitempty"`
	KEV         bool    `json:"kev"`
	EPSSScore   float64 `json:"epssScore,omitempty"`
	TechniqueID string  `json:"techniqueId"`
	Severity    float64 `json:"severity"`
}

// FindingSummary is the API-facing projection of one open finding row.
// Deliberately NOT findings.FindingRef — see the plan's Global Constraints.
type FindingSummary struct {
	ID            string `json:"id"`
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Tactic        string `json:"tactic"`
	Severity      string `json:"severity"`
	ExposureState string `json:"exposureState"`
}

// FindingsContext is this asset's finding history. Collected is false for
// discovered-only (unmanaged) assets — an honest "not enrolled" state, never
// a fabricated empty list rendered as if it were a real zero.
type FindingsContext struct {
	Collected     bool             `json:"collected"`
	OpenCount     int              `json:"openCount"`
	CriticalCount int              `json:"criticalCount"`
	Findings      []FindingSummary `json:"findings,omitempty"`
}

// ThreatGroupExposure is one ATT&CK group attributed to one or more
// techniques threatening this asset.
type ThreatGroupExposure struct {
	GroupName    string   `json:"groupName"`
	TechniqueIDs []string `json:"techniqueIds"`
}

// AssetExposureProfile is the full per-asset detail payload.
type AssetExposureProfile struct {
	Asset           AssetIdentity                     `json:"asset"`
	Scores          ScoreBreakdown                    `json:"scores"`
	AttackPath      AttackPathContext                 `json:"attackPath"`
	Detection       DetectionContext                  `json:"detection"`
	Vulnerabilities []CVEExposure                     `json:"vulnerabilities"`
	Findings        FindingsContext                   `json:"findings"`
	ThreatIntel     []ThreatGroupExposure              `json:"threatIntel"`
	Recommendations []pathcorrelation.PrioritizedGap  `json:"recommendations"`
}

// AssetSummary is the lightweight index row for GET /api/exposure/assets.
type AssetSummary struct {
	Asset                  AssetIdentity `json:"asset"`
	ExposureScore          int           `json:"exposureScore"`
	AttackPathScore        int           `json:"attackPathScore"`
	DetectionCoverageScore int           `json:"detectionCoverageScore"`
	WorstCVESeverity       float64       `json:"worstCveSeverity,omitempty"`
	KEVExposed             bool          `json:"kevExposed"`
	OpenFindingsCount      int           `json:"openFindingsCount"`
}

// AgentRow is the minimal projection of the `agents` table Build needs to
// extend the asset union beyond the attack-path graph's own host nodes.
type AgentRow struct {
	AgentID  string
	Hostname string
	IP       string
	OS       string
}

// RelationshipLookup is the slice of the Relationship Store this package
// needs. *relationships.Store satisfies it directly; tests substitute a fake.
type RelationshipLookup interface {
	ForTechnique(ctx context.Context, techniqueID string) ([]relationships.Relationship, error)
}

// CVEMeta is CVSS/KEV/EPSS metadata for one CVE.
type CVEMeta struct {
	CVSS      float64
	KEV       bool
	EPSSScore float64
}

// CVEEnricher batch-resolves CVE IDs to CVSS/KEV/EPSS metadata. SQLCVEEnricher
// (sql.go) is the production implementation; tests use a fake.
type CVEEnricher interface {
	Enrich(ctx context.Context, cveIDs []string) (map[string]CVEMeta, error)
}

// FindingsLookup reads open findings, grouped by agent ID, in one batched
// call. SQLFindingsLookup (sql.go) is the production implementation; tests
// use a fake.
type FindingsLookup interface {
	AllOpenFindings(ctx context.Context) (map[string][]FindingSummary, error)
}
```

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/exposure/cve_test.go
package exposure

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/relationships"
)

type fakeRelLookup struct{ byTech map[string][]relationships.Relationship }

func (f *fakeRelLookup) ForTechnique(_ context.Context, techID string) ([]relationships.Relationship, error) {
	return f.byTech[techID], nil
}

type fakeEnricher struct{ meta map[string]CVEMeta }

func (f *fakeEnricher) Enrich(_ context.Context, ids []string) (map[string]CVEMeta, error) {
	out := map[string]CVEMeta{}
	for _, id := range ids {
		if m, ok := f.meta[id]; ok {
			out[id] = m
		}
	}
	return out, nil
}

func TestCVESeverity_KEVAddsFlatBonusEvenWithoutCVSS(t *testing.T) {
	noKEV := cveSeverity(0, false, 0)
	withKEV := cveSeverity(0, true, 0)
	if noKEV != 0 {
		t.Fatalf("no CVSS/KEV/EPSS should be 0, got %v", noKEV)
	}
	if withKEV != 25 {
		t.Fatalf("KEV-only severity = %v, want 25", withKEV)
	}
}

func TestCVESeverity_MaxInputsCapAt100(t *testing.T) {
	if got := cveSeverity(10, true, 1); got != 100 {
		t.Fatalf("max severity = %v, want 100", got)
	}
}

func TestVulnerabilitiesForTechniques_FiltersInactiveAndLowConfidence(t *testing.T) {
	rels := &fakeRelLookup{byTech: map[string][]relationships.Relationship{
		"T1190": {
			{CVEID: "CVE-2024-0001", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceHigh},
			{CVEID: "CVE-2024-0002", Status: relationships.StatusDeprecated, EffectiveConfidence: relationships.ConfidenceHigh},
			{CVEID: "CVE-2024-0003", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceLow},
		},
	}}
	enricher := &fakeEnricher{meta: map[string]CVEMeta{
		"CVE-2024-0001": {CVSS: 9.8, KEV: true, EPSSScore: 0.9},
	}}

	out, err := vulnerabilitiesForTechniques(context.Background(), []string{"T1190"}, rels, enricher)
	if err != nil {
		t.Fatalf("vulnerabilitiesForTechniques: %v", err)
	}
	got := out["T1190"]
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 CVE (deprecated + low-confidence filtered out), got %+v", got)
	}
	if got[0].CVEID != "CVE-2024-0001" || got[0].Severity <= 0 {
		t.Fatalf("unexpected CVE entry: %+v", got[0])
	}
}

func TestVulnerabilitiesForTechniques_NilDependenciesReturnEmpty(t *testing.T) {
	out, err := vulnerabilitiesForTechniques(context.Background(), []string{"T1190"}, nil, nil)
	if err != nil {
		t.Fatalf("vulnerabilitiesForTechniques: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty map with nil deps, got %+v", out)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/exposure/... -run TestCVESeverity -v`
Expected: FAIL — `cveSeverity undefined`.

- [ ] **Step 4: Implement `cve.go`**

```go
// orchestrator/internal/exposure/cve.go
package exposure

import (
	"context"
	"sort"

	"github.com/audspect/bas/internal/relationships"
)

// Per-CVE severity weights (0-100 total): CVSS dominates, KEV (actively
// exploited) is a large flat bonus even when CVSS is unknown, EPSS
// (exploit-probability) contributes the smallest, most volatile term.
const (
	cveWeightCVSS = 60.0
	cveWeightKEV  = 25.0
	cveWeightEPSS = 15.0
)

// cveSeverity is the per-design-spec per-CVE severity formula.
func cveSeverity(cvss float64, kev bool, epss float64) float64 {
	sev := (cvss/10)*cveWeightCVSS + epss*cveWeightEPSS
	if kev {
		sev += cveWeightKEV
	}
	if sev > 100 {
		sev = 100
	}
	if sev < 0 {
		sev = 0
	}
	return sev
}

// vulnerabilitiesForTechniques returns, per technique ID, the CVEs reached
// via an Active, High/Medium-confidence relationship (the Relationship
// Store's documented scoring convention), enriched with CVSS/KEV/EPSS. One
// batched CVEEnricher call covers every technique passed in — never one
// query per technique. nil rels or nil enricher returns an empty map
// (nil-safe, matches this codebase's optional-subsystem convention).
func vulnerabilitiesForTechniques(ctx context.Context, techniqueIDs []string, rels RelationshipLookup, enricher CVEEnricher) (map[string][]CVEExposure, error) {
	if rels == nil || enricher == nil {
		return map[string][]CVEExposure{}, nil
	}

	type pair struct{ techID, cveID string }
	var pairs []pair
	cveSet := map[string]bool{}
	for _, t := range techniqueIDs {
		relList, err := rels.ForTechnique(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, r := range relList {
			if r.Status != relationships.StatusActive {
				continue
			}
			if r.EffectiveConfidence != relationships.ConfidenceHigh && r.EffectiveConfidence != relationships.ConfidenceMedium {
				continue
			}
			pairs = append(pairs, pair{t, r.CVEID})
			cveSet[r.CVEID] = true
		}
	}
	if len(pairs) == 0 {
		return map[string][]CVEExposure{}, nil
	}

	cveIDs := make([]string, 0, len(cveSet))
	for id := range cveSet {
		cveIDs = append(cveIDs, id)
	}
	sort.Strings(cveIDs)

	meta, err := enricher.Enrich(ctx, cveIDs)
	if err != nil {
		return nil, err
	}

	out := map[string][]CVEExposure{}
	for _, p := range pairs {
		m := meta[p.cveID]
		out[p.techID] = append(out[p.techID], CVEExposure{
			CVEID:       p.cveID,
			CVSS:        m.CVSS,
			KEV:         m.KEV,
			EPSSScore:   m.EPSSScore,
			TechniqueID: p.techID,
			Severity:    cveSeverity(m.CVSS, m.KEV, m.EPSSScore),
		})
	}
	return out, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exposure/... -v`
Expected: PASS — all 4 tests.

- [ ] **Step 6: Format, build, vet**

Run: `cd orchestrator && gofmt -w internal/exposure/types.go internal/exposure/cve.go internal/exposure/cve_test.go && gofmt -l internal/exposure && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 7: Commit and push**

```bash
cd orchestrator
git add internal/exposure/types.go internal/exposure/cve.go internal/exposure/cve_test.go
git commit -m "feat(exposure): add core types and CVE severity aggregation

New internal/exposure package (SP4 Exposure Explorer): all API-facing
types plus the per-CVE severity formula (CVSS/KEV/EPSS weighted) and
vulnerabilitiesForTechniques, which batches Relationship Store lookups
and CVE enrichment into one query each regardless of technique count."
git push
```

---

### Task 2: `internal/exposure` — SQL-backed CVE enrichment and findings lookup

**Files:**
- Create: `orchestrator/internal/exposure/sql.go`
- Test: `orchestrator/internal/exposure/sql_test.go`

**Interfaces:**
- Consumes: `CVEMeta`, `FindingSummary`, `CVEEnricher`, `FindingsLookup` (Task 1).
- Produces: `SQLCVEEnricher{db}` + `NewSQLCVEEnricher(db) *SQLCVEEnricher` (satisfies `CVEEnricher`), `SQLFindingsLookup{db}` + `NewSQLFindingsLookup(db) *SQLFindingsLookup` (satisfies `FindingsLookup`) — later tasks call these constructors by these exact names.

This is the first DB-touching test file in this new package — it declares the package's `TestMain`/`sharedDB`, following `testutil.MustSharedTestDB()`'s documented pattern (same as SP3's `internal/pathcorrelation/runlookup_test.go`).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/exposure/sql_test.go
package exposure

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestSQLCVEEnricher_JoinsKEVAndEPSS(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ('CVE-2024-9001', 9.8, 'cisa-kev')`)
		mustExec(t, pool, `INSERT INTO cve_epss (cve_id, epss_score, percentile) VALUES ('CVE-2024-9001', 0.87, 0.99)`)
		mustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ('CVE-2024-9002', 4.0, 'nvd')`)
		// CVE-2024-9002 has no cve_epss row — Enrich must not fail, just default to 0.

		enricher := NewSQLCVEEnricher(pool)
		meta, err := enricher.Enrich(context.Background(), []string{"CVE-2024-9001", "CVE-2024-9002", "CVE-2024-NOPE"})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(meta) != 2 {
			t.Fatalf("expected 2 entries (unknown CVE absent), got %+v", meta)
		}
		m1 := meta["CVE-2024-9001"]
		if !m1.KEV || m1.CVSS != 9.8 || m1.EPSSScore != 0.87 {
			t.Fatalf("CVE-2024-9001 = %+v, want KEV=true CVSS=9.8 EPSS=0.87", m1)
		}
		m2 := meta["CVE-2024-9002"]
		if m2.KEV || m2.CVSS != 4.0 || m2.EPSSScore != 0 {
			t.Fatalf("CVE-2024-9002 = %+v, want KEV=false CVSS=4.0 EPSS=0 (no epss row)", m2)
		}
	})
}

func TestSQLCVEEnricher_EmptyInputReturnsEmptyMap(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		enricher := NewSQLCVEEnricher(pool)
		meta, err := enricher.Enrich(context.Background(), nil)
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		if len(meta) != 0 {
			t.Fatalf("expected empty map, got %+v", meta)
		}
	})
}

func TestSQLFindingsLookup_GroupsByAgentSortedBySeverity(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			VALUES ('exp-fa-01', 'EXPFA01', '10.0.0.9', 'Windows 11', 'idle', 'active', NOW())`)
		mustExec(t, pool, `INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name, tactic,
			severity, exposure_state, status, source_type, first_seen, last_seen)
			VALUES ('exp-f-1', 'exp-fa-01', 'T1059.001', 'prevention', 'PowerShell', 'execution',
			'Medium', 'Detected', 'open', 'simulation', NOW(), NOW())`)
		mustExec(t, pool, `INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name, tactic,
			severity, exposure_state, status, source_type, first_seen, last_seen)
			VALUES ('exp-f-2', 'exp-fa-01', 'T1078', 'prevention', 'Valid Accounts', 'defense-evasion',
			'Critical', 'Missed', 'open', 'simulation', NOW(), NOW())`)
		mustExec(t, pool, `INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name, tactic,
			severity, exposure_state, status, source_type, first_seen, last_seen)
			VALUES ('exp-f-3', 'exp-fa-01', 'T1021.002', 'prevention', 'SMB', 'lateral-movement',
			'High', 'Missed', 'resolved', 'simulation', NOW(), NOW())`)

		lookup := NewSQLFindingsLookup(pool)
		out, err := lookup.AllOpenFindings(context.Background())
		if err != nil {
			t.Fatalf("AllOpenFindings: %v", err)
		}
		list := out["exp-fa-01"]
		if len(list) != 2 {
			t.Fatalf("expected 2 open findings (resolved one excluded), got %+v", list)
		}
		if list[0].Severity != "Critical" {
			t.Fatalf("expected Critical severity first, got %+v", list[0])
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/exposure/... -run 'TestSQLCVEEnricher|TestSQLFindingsLookup' -v`
Expected: FAIL — `NewSQLCVEEnricher undefined`, `NewSQLFindingsLookup undefined`.

- [ ] **Step 3: Implement `sql.go`**

```go
// orchestrator/internal/exposure/sql.go
package exposure

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SQLCVEEnricher is the production CVEEnricher: batched join against cves +
// cve_epss. KEV membership is cves.source='cisa-kev' (see Global Constraints
// in the plan for why, not a non-null date_added check).
type SQLCVEEnricher struct{ db *pgxpool.Pool }

func NewSQLCVEEnricher(db *pgxpool.Pool) *SQLCVEEnricher { return &SQLCVEEnricher{db: db} }

func (e *SQLCVEEnricher) Enrich(ctx context.Context, cveIDs []string) (map[string]CVEMeta, error) {
	if len(cveIDs) == 0 {
		return map[string]CVEMeta{}, nil
	}
	rows, err := e.db.Query(ctx, `
		SELECT c.cve_id, COALESCE(c.cvss,0), (c.source = 'cisa-kev'), COALESCE(ep.epss_score,0)
		FROM cves c
		LEFT JOIN cve_epss ep ON ep.cve_id = c.cve_id
		WHERE c.cve_id = ANY($1)`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CVEMeta{}
	for rows.Next() {
		var id string
		var m CVEMeta
		if rows.Scan(&id, &m.CVSS, &m.KEV, &m.EPSSScore) != nil {
			continue
		}
		out[id] = m
	}
	return out, rows.Err()
}

// SQLFindingsLookup is the production FindingsLookup: one query, grouped by
// agent in Go (findings has no natural GROUP BY shape for a row-list result).
type SQLFindingsLookup struct{ db *pgxpool.Pool }

func NewSQLFindingsLookup(db *pgxpool.Pool) *SQLFindingsLookup { return &SQLFindingsLookup{db: db} }

func (l *SQLFindingsLookup) AllOpenFindings(ctx context.Context) (map[string][]FindingSummary, error) {
	rows, err := l.db.Query(ctx, `
		SELECT id, agent_id, technique_id, technique_name, tactic, severity, exposure_state
		FROM findings WHERE status='open'
		ORDER BY agent_id, CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]FindingSummary{}
	for rows.Next() {
		var agentID string
		var f FindingSummary
		if rows.Scan(&f.ID, &agentID, &f.TechniqueID, &f.TechniqueName, &f.Tactic, &f.Severity, &f.ExposureState) != nil {
			continue
		}
		out[agentID] = append(out[agentID], f)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass (Docker must be running)**

Run: `cd orchestrator && go test ./internal/exposure/... -v`
Expected: PASS — all Task 1 + Task 2 tests.

- [ ] **Step 5: Format, build, vet**

Run: `cd orchestrator && gofmt -w internal/exposure/sql.go internal/exposure/sql_test.go && gofmt -l internal/exposure && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit and push**

```bash
cd orchestrator
git add internal/exposure/sql.go internal/exposure/sql_test.go
git commit -m "feat(exposure): add SQL-backed CVE enrichment and findings lookup

SQLCVEEnricher batches CVSS/KEV/EPSS lookup against cves+cve_epss;
SQLFindingsLookup reads every open finding in one query, grouped by
agent in Go. Both mirror SP3's SQLRunLookup precedent of querying the
relevant table directly rather than going through another package."
git push
```

---

### Task 3: `internal/exposure` — asset union and per-asset risk derivation

**Files:**
- Create: `orchestrator/internal/exposure/riskscore.go`
- Test: `orchestrator/internal/exposure/riskscore_test.go`

**Interfaces:**
- Consumes: `attackpath.Graph` (`Nodes`, `Node`, `ShortestPath`, all exported), `attackpath.Summary` (`ShortestDAPath`, `CrownJewels`, `ChokePoints`, `MaxBlastEntry`, `ReachableCrownJewels()`, all exported), `attackpath.HostKey`, `attackpath.NormalizeHostKey`, `attackpath.KindHost`, `pathcorrelation.AttackPathCorrelation` (`Paths`, `ChokePoints`, both `[]AnnotatedPath`/`[]AnnotatedChokePoint`), `pathcorrelation.AnnotatedEdge`, `pathcorrelation.VerifiedCovered/Partial/Gap/Unknown` (all exported from SP3).
- Produces: `assetNode{hostKey, nodeID string; agent *AgentRow}`, `unionAssets(g *attackpath.Graph, agents []AgentRow) []assetNode`, `attackPathContext(g, s, nodeID string) (AttackPathContext, float64)` (float64 = AttackPathRisk 0-100), `detectionContext(corr pathcorrelation.AttackPathCorrelation, nodeID string) (DetectionContext, float64)` (float64 = DetectionRisk 0-100) — Task 4 calls all of these by these exact names.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/exposure/riskscore_test.go
package exposure

import (
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func daFixtureGraph() (*attackpath.Graph, attackpath.Summary) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{{From: "WS01", To: "FILE01", Kind: attackpath.EdgeSMB}}},
		{AgentID: "file01", Source: "sharphound",
			Nodes: []attackpath.Node{
				{ID: "FILE01", Kind: attackpath.KindHost, Role: attackpath.RoleServer, CrownJewel: "FileServer"},
				{ID: "svc", Kind: attackpath.KindUser, Label: "svc-backup"},
				{ID: "DA", Kind: attackpath.KindGroup, Label: "Domain Admins", HighValue: true},
			},
			Edges: []attackpath.Edge{
				{From: "FILE01", To: "svc", Kind: attackpath.EdgeHasSession},
				{From: "svc", To: "DA", Kind: attackpath.EdgeMemberOf},
			}},
	}
	return attackpath.BuildGraphAndAnalyze(cols, nil)
}

func TestUnionAssets_DedupsGraphHostAndAgentByHostKey(t *testing.T) {
	g, _ := daFixtureGraph()
	agents := []AgentRow{{AgentID: "a1", Hostname: "WS01"}, {AgentID: "a2", Hostname: "UNRELATED"}}

	assets := unionAssets(g, agents)

	var sawWS01Merged, sawUnrelated, sawFile01Unmanaged bool
	for _, a := range assets {
		switch a.hostKey {
		case "WS01":
			if a.nodeID == "" || a.agent == nil {
				t.Fatalf("WS01 should have both a graph node and an agent, got %+v", a)
			}
			sawWS01Merged = true
		case "UNRELATED":
			if a.nodeID != "" {
				t.Fatalf("UNRELATED should have no graph node, got %+v", a)
			}
			sawUnrelated = true
		case "FILE01":
			if a.agent != nil {
				t.Fatalf("FILE01 should be unmanaged (no agent), got %+v", a)
			}
			sawFile01Unmanaged = true
		}
	}
	if !sawWS01Merged || !sawUnrelated || !sawFile01Unmanaged {
		t.Fatalf("expected WS01 merged, UNRELATED agent-only, FILE01 graph-only; got %+v", assets)
	}
}

func TestAttackPathContext_HostOnDAPathGetsMaxRisk(t *testing.T) {
	g, s := daFixtureGraph()
	// WS01 is the entry host; the DA path runs WS01->FILE01->svc->DA.
	ctx, risk := attackPathContext(g, s, "WS01")
	if !ctx.Reachable {
		t.Fatalf("WS01 should be reachable: %+v", ctx)
	}
	if risk != 100 {
		t.Fatalf("host on the shortest DA path should have risk 100, got %v", risk)
	}
}

func TestAttackPathContext_UnknownNodeIsNotReachable(t *testing.T) {
	g, s := daFixtureGraph()
	ctx, risk := attackPathContext(g, s, "")
	if ctx.Reachable || risk != 0 {
		t.Fatalf("empty nodeID should be unreachable with 0 risk, got ctx=%+v risk=%v", ctx, risk)
	}
}

func TestDetectionContext_AveragesAcrossTouchingEdgesOnly(t *testing.T) {
	g, s := daFixtureGraph()
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(nil, g, s, paths, pathcorrelation.DefaultEdgeTechniqueMapper{}, //nolint:staticcheck // nil ctx ok, no I/O in this fixture's RunLookup
		&nilRunLookup{}, &nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}

	dc, risk := detectionContext(corr, "FILE01")
	if len(dc.Edges) == 0 {
		t.Fatalf("FILE01 should have at least one touching edge")
	}
	if risk <= 0 {
		t.Fatalf("with no verified detections anywhere, risk should be > 0, got %v", risk)
	}

	_, noEdgesRisk := detectionContext(corr, "does-not-exist")
	if noEdgesRisk != 0 {
		t.Fatalf("a node with zero touching edges should have risk 0, got %v", noEdgesRisk)
	}
}
```

- [ ] **Step 2: Add two tiny fakes this test file needs (same file, appended)**

`pathcorrelation.Correlate` needs a `RunLookup`/`RuleLibrary`; this test only cares about which edges touch a node, not verification data, so use no-op fakes. Add `"context"` and `"github.com/audspect/bas/internal/rulelib"` to the test file's imports, and change the `Correlate` call in `TestDetectionContext_AveragesAcrossTouchingEdgesOnly` (Step 1) to pass `context.Background()` as its first argument instead of `nil`:

```go
type nilRunLookup struct{}

func (nilRunLookup) VerifiedDetection(_ context.Context, _, _ string) (pathcorrelation.VerificationResult, bool, error) {
	return pathcorrelation.VerificationResult{}, false, nil
}

type nilRuleLibrary struct{}

func (nilRuleLibrary) RulesByTechnique(_ string) []rulelib.Rule { return nil }
```

These two fakes (`nilRunLookup`, `nilRuleLibrary`) are defined once here and reused by Task 4's `build_test.go` in the same package — do not redefine them there.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/exposure/... -run 'TestUnionAssets|TestAttackPathContext|TestDetectionContext' -v`
Expected: FAIL — `unionAssets undefined`, `attackPathContext undefined`, `detectionContext undefined`.

- [ ] **Step 4: Implement `riskscore.go`**

```go
// orchestrator/internal/exposure/riskscore.go
package exposure

import (
	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// assetNode pairs a normalized host key with its optional graph node ID
// (empty when this asset was only ever seen via an enrolled agent, never in
// the attack-path graph) and optional agent row.
type assetNode struct {
	hostKey string
	nodeID  string
	agent   *AgentRow
}

// unionAssets merges attack-path graph host nodes with enrolled agents,
// deduplicated by attackpath.NormalizeHostKey / attackpath.HostKey (same
// normalization the attackpath package itself uses for asset tagging).
func unionAssets(g *attackpath.Graph, agents []AgentRow) []assetNode {
	idx := map[string]*assetNode{}
	var order []string
	for _, n := range g.Nodes() {
		if n.Kind != attackpath.KindHost {
			continue
		}
		k := attackpath.HostKey(n)
		if k == "" {
			continue
		}
		if _, ok := idx[k]; !ok {
			order = append(order, k)
			idx[k] = &assetNode{hostKey: k}
		}
		idx[k].nodeID = n.ID
	}
	for i := range agents {
		a := &agents[i]
		k := attackpath.NormalizeHostKey(a.Hostname)
		if k == "" {
			continue
		}
		if _, ok := idx[k]; !ok {
			order = append(order, k)
			idx[k] = &assetNode{hostKey: k}
		}
		idx[k].agent = a
	}
	out := make([]assetNode, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	return out
}

// attackPathRisk is the per-design-spec per-asset formula (0-100, higher =
// more exposed). nodeID == "" (asset never seen in the attack-path graph)
// returns (0, false) — v1 cannot distinguish "definitely safe" from "no
// data yet"; callers must render Reachable=false distinctly from a genuine
// low-risk reachable asset.
func attackPathRisk(g *attackpath.Graph, s attackpath.Summary, nodeID string) (risk float64, reachable bool) {
	if nodeID == "" {
		return 0, false
	}
	for _, e := range s.ShortestDAPath {
		if e.From == nodeID || e.To == nodeID {
			return 100, true
		}
	}
	for _, cj := range s.ReachableCrownJewels() {
		if cj.Node == nodeID {
			return 90, true
		}
	}
	if s.MaxBlastEntry == "" {
		return 0, false
	}
	if s.MaxBlastEntry == nodeID {
		return 100, true
	}
	path := g.ShortestPath(s.MaxBlastEntry, nodeID)
	if len(path) == 0 {
		return 0, false
	}
	risk = 100 - 15*float64(len(path))
	if risk < 20 {
		risk = 20
	}
	return risk, true
}

// attackPathContext builds the per-asset AttackPathContext alongside its
// AttackPathRisk (computed once, not duplicated).
func attackPathContext(g *attackpath.Graph, s attackpath.Summary, nodeID string) (AttackPathContext, float64) {
	risk, reachable := attackPathRisk(g, s, nodeID)
	ctx := AttackPathContext{Reachable: reachable, DistanceToNearestCrownJewel: -1}
	if nodeID == "" {
		return ctx, risk
	}
	for _, e := range s.ShortestDAPath {
		if e.From == nodeID || e.To == nodeID {
			ctx.OnShortestDAPath = true
			break
		}
	}
	best := -1
	for _, cj := range s.CrownJewels {
		if !cj.Reachable {
			continue
		}
		if nodeID == cj.Node {
			best = 0
			break
		}
		if p := g.ShortestPath(nodeID, cj.Node); len(p) > 0 && (best == -1 || len(p) < best) {
			best = len(p)
		}
	}
	ctx.DistanceToNearestCrownJewel = best
	for _, cp := range s.ChokePoints {
		if cp.Node == nodeID {
			ctx.IsChokePoint = true
			ctx.ChokePointCoverage = cp.Coverage
			break
		}
	}
	return ctx, risk
}

type edgeKey struct {
	from, to string
	kind     attackpath.EdgeKind
}

// detectionEdgesForAsset collects every AnnotatedEdge across corr's paths
// and choke points whose From or To equals nodeID, deduplicated.
func detectionEdgesForAsset(corr pathcorrelation.AttackPathCorrelation, nodeID string) []pathcorrelation.AnnotatedEdge {
	seen := map[edgeKey]bool{}
	var out []pathcorrelation.AnnotatedEdge
	add := func(e pathcorrelation.AnnotatedEdge) {
		if e.Edge.From != nodeID && e.Edge.To != nodeID {
			return
		}
		k := edgeKey{e.Edge.From, e.Edge.To, e.Edge.Kind}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, e)
	}
	for _, p := range corr.Paths {
		for _, e := range p.Edges {
			add(e)
		}
	}
	for _, cp := range corr.ChokePoints {
		for _, e := range cp.IncomingEdges {
			add(e)
		}
	}
	return out
}

// detectionRiskFactor mirrors SP3's gapFactor scale (Gap=1.0, Unknown=0.6,
// Partial=0.4, Covered=0.0) — duplicated here deliberately (a 4-line
// switch) rather than exporting pathcorrelation's unexported constants, to
// keep the two packages decoupled per the established dependency boundary
// (nothing points back into pathcorrelation from exposure).
func detectionRiskFactor(v pathcorrelation.VerifiedStatus) float64 {
	switch v {
	case pathcorrelation.VerifiedGap:
		return 1.0
	case pathcorrelation.VerifiedUnknown:
		return 0.6
	case pathcorrelation.VerifiedPartial:
		return 0.4
	default:
		return 0.0
	}
}

// detectionContext builds the per-asset DetectionContext and its 0-100
// DetectionRisk as an AVERAGE across this asset's own touching edges —
// deliberately different from SP3's per-path weakest-link scoring (see the
// design spec's rationale: a per-asset rollup of independent incoming edges
// is better read as "how many of the ways in are covered").
func detectionContext(corr pathcorrelation.AttackPathCorrelation, nodeID string) (DetectionContext, float64) {
	edges := detectionEdgesForAsset(corr, nodeID)
	dc := DetectionContext{Edges: edges}
	var weighted float64
	for _, e := range edges {
		switch e.Status.Verified {
		case pathcorrelation.VerifiedCovered:
			dc.Covered++
		case pathcorrelation.VerifiedPartial:
			dc.Partial++
		case pathcorrelation.VerifiedGap:
			dc.Gap++
		default:
			dc.Unknown++
		}
		weighted += detectionRiskFactor(e.Status.Verified)
	}
	if len(edges) == 0 {
		return dc, 0
	}
	return dc, 100 * weighted / float64(len(edges))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exposure/... -v`
Expected: PASS — all Task 1-3 tests.

- [ ] **Step 6: Format, build, vet**

Run: `cd orchestrator && gofmt -w internal/exposure/riskscore.go internal/exposure/riskscore_test.go && gofmt -l internal/exposure && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 7: Commit and push**

```bash
cd orchestrator
git add internal/exposure/riskscore.go internal/exposure/riskscore_test.go
git commit -m "feat(exposure): add asset union and per-asset risk derivation

unionAssets merges attack-path graph hosts with enrolled agents,
deduped by normalized host key. attackPathContext/detectionContext
derive per-asset AttackPathRisk/DetectionRisk from data already
computed by attackpath/pathcorrelation — deliberately NOT the
fleet-wide scores, so every asset's composite score actually differs."
git push
```

---

### Task 4: `internal/exposure` — the `Build()` entry point

**Files:**
- Create: `orchestrator/internal/exposure/build.go`
- Test: `orchestrator/internal/exposure/build_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-3, plus `attackdata.Lookup(techID string) *attackdata.Enrichment` (`internal/reporting/attackdata`, `Enrichment.Groups []string`, already exported), `pathcorrelation.PrioritizedGap` (`Edge`, already exported).
- Produces: `func Build(ctx context.Context, g *attackpath.Graph, s attackpath.Summary, corr pathcorrelation.AttackPathCorrelation, rels RelationshipLookup, enricher CVEEnricher, findingsLookup FindingsLookup, agents []AgentRow) (*AssetGraph, error)`, `(*AssetGraph) Profile(hostKey string) (AssetExposureProfile, bool)`, `(*AssetGraph) Summaries() []AssetSummary` — Task 5 (API handler) calls all three by these exact names.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/exposure/build_test.go
package exposure

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/relationships"
	"github.com/audspect/bas/internal/rulelib"
)

func buildDaFixtureCorrelation(t *testing.T) (*attackpath.Graph, attackpath.Summary, pathcorrelation.AttackPathCorrelation) {
	t.Helper()
	g, s := daFixtureGraph()
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, paths, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	return g, s, corr
}

func TestBuild_EmptyInputsProduceNoAssets(t *testing.T) {
	g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, nil, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	ag, err := Build(context.Background(), g, s, corr, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(ag.Summaries()) != 0 {
		t.Fatalf("expected 0 assets, got %d", len(ag.Summaries()))
	}
}

func TestBuild_HostOnDAPath_LowExposureScore(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	rels := &fakeRelLookup{byTech: map[string][]relationships.Relationship{}}
	ag, err := Build(context.Background(), g, s, corr, rels, &fakeEnricher{meta: map[string]CVEMeta{}}, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	profile, ok := ag.Profile("WS01")
	if !ok {
		t.Fatalf("expected a profile for WS01")
	}
	if profile.Scores.AttackPathScore != 0 {
		t.Fatalf("host on the shortest DA path should have AttackPathScore 0, got %d", profile.Scores.AttackPathScore)
	}
	if profile.Scores.ExposureScore >= 50 {
		t.Fatalf("a host on the DA path with zero detection coverage should score low, got %d", profile.Scores.ExposureScore)
	}
}

func TestBuild_ManagedOnlyAsset_FindingsCollectedTrue(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	agents := []AgentRow{{AgentID: "agent-x", Hostname: "STANDALONE-BOX"}}
	findingsLookup := &fakeFindingsLookup{byAgent: map[string][]FindingSummary{
		"agent-x": {{ID: "f1", TechniqueID: "T1059", Severity: "Critical"}},
	}}
	ag, err := Build(context.Background(), g, s, corr, nil, nil, findingsLookup, agents)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	profile, ok := ag.Profile("STANDALONE-BOX")
	if !ok {
		t.Fatalf("expected a profile for STANDALONE-BOX")
	}
	if !profile.Findings.Collected || profile.Findings.OpenCount != 1 || profile.Findings.CriticalCount != 1 {
		t.Fatalf("unexpected findings context: %+v", profile.Findings)
	}
	if profile.AttackPath.Reachable {
		t.Fatalf("a host never seen in the attack-path graph should not be marked reachable: %+v", profile.AttackPath)
	}

	unmanaged, ok := ag.Profile("FILE01")
	if !ok {
		t.Fatalf("expected a profile for FILE01")
	}
	if unmanaged.Findings.Collected {
		t.Fatalf("a discovered-only asset should have Findings.Collected=false, got %+v", unmanaged.Findings)
	}
}

func TestBuild_VulnerabilityWorstCVEDominates(t *testing.T) {
	g, s, corr := buildDaFixtureCorrelation(t)
	// EdgeSMB (WS01->FILE01) maps to T1021.002.
	rels := &fakeRelLookup{byTech: map[string][]relationships.Relationship{
		"T1021.002": {
			{CVEID: "CVE-MILD", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceHigh},
			{CVEID: "CVE-SEVERE", Status: relationships.StatusActive, EffectiveConfidence: relationships.ConfidenceHigh},
		},
	}}
	enricher := &fakeEnricher{meta: map[string]CVEMeta{
		"CVE-MILD":   {CVSS: 2.0},
		"CVE-SEVERE": {CVSS: 9.8, KEV: true, EPSSScore: 0.95},
	}}
	ag, err := Build(context.Background(), g, s, corr, rels, enricher, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	profile, ok := ag.Profile("WS01")
	if !ok {
		t.Fatalf("expected a profile for WS01")
	}
	if len(profile.Vulnerabilities) != 2 {
		t.Fatalf("expected both CVEs listed, got %+v", profile.Vulnerabilities)
	}
	if profile.Scores.VulnerabilityScore > 20 {
		t.Fatalf("worst CVE (severe) should dominate VulnerabilityScore, got %d", profile.Scores.VulnerabilityScore)
	}
}
```

`build_test.go` does not need to import `"github.com/audspect/bas/internal/rulelib"` itself — `nilRunLookup`/`nilRuleLibrary` are already defined once in `riskscore_test.go` (Task 3) and reused here via `buildDaFixtureCorrelation`, same package.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/exposure/... -run TestBuild -v`
Expected: FAIL — `Build undefined`.

- [ ] **Step 3: Implement `build.go`**

```go
// orchestrator/internal/exposure/build.go
package exposure

import (
	"context"
	"sort"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// AssetGraph is the result of one Build() call: every asset's profile,
// computed once. Summaries()/Profile() are cheap accessors — Build() is the
// only expensive call (one CVE enrichment batch, one findings batch,
// regardless of asset count).
type AssetGraph struct {
	profiles map[string]AssetExposureProfile
	order    []string
}

// Build computes every asset's AssetExposureProfile in one pass over an
// already-built graph/summary/correlation (same "caller builds it once"
// convention as SP3's API handler). nil rels/enricher/findingsLookup are
// safe — those sections of every profile are simply left at their zero
// value, matching this API's nil-safe-optional-subsystem convention.
func Build(ctx context.Context, g *attackpath.Graph, s attackpath.Summary,
	corr pathcorrelation.AttackPathCorrelation, rels RelationshipLookup,
	enricher CVEEnricher, findingsLookup FindingsLookup, agents []AgentRow) (*AssetGraph, error) {

	assets := unionAssets(g, agents)

	type partial struct {
		asset   assetNode
		detect  DetectionContext
		detRisk float64
		apCtx   AttackPathContext
		apRisk  float64
		techIDs []string
	}
	partials := make([]partial, 0, len(assets))
	allTechIDs := map[string]bool{}
	for _, a := range assets {
		dc, detRisk := detectionContext(corr, a.nodeID)
		apCtx, apRisk := attackPathContext(g, s, a.nodeID)
		techSet := map[string]bool{}
		for _, e := range dc.Edges {
			for _, t := range e.Status.Techniques {
				techSet[t.TechniqueID] = true
				allTechIDs[t.TechniqueID] = true
			}
		}
		techIDs := make([]string, 0, len(techSet))
		for t := range techSet {
			techIDs = append(techIDs, t)
		}
		sort.Strings(techIDs)
		partials = append(partials, partial{asset: a, detect: dc, detRisk: detRisk, apCtx: apCtx, apRisk: apRisk, techIDs: techIDs})
	}

	techIDList := make([]string, 0, len(allTechIDs))
	for t := range allTechIDs {
		techIDList = append(techIDList, t)
	}
	sort.Strings(techIDList)
	cveByTech, err := vulnerabilitiesForTechniques(ctx, techIDList, rels, enricher)
	if err != nil {
		return nil, err
	}

	var findingsByAgent map[string][]FindingSummary
	if findingsLookup != nil {
		findingsByAgent, err = findingsLookup.AllOpenFindings(ctx)
		if err != nil {
			return nil, err
		}
	}

	ag := &AssetGraph{profiles: map[string]AssetExposureProfile{}}
	for _, p := range partials {
		profile := AssetExposureProfile{
			Asset:      AssetIdentity{HostKey: p.asset.hostKey},
			AttackPath: p.apCtx,
			Detection:  p.detect,
		}
		if p.asset.nodeID != "" {
			if n, ok := g.Node(p.asset.nodeID); ok {
				profile.Asset.Label = n.Label
				profile.Asset.CrownJewel = n.CrownJewel
				profile.Asset.Segment = n.Segment
				profile.Asset.HighValue = n.HighValue
			}
		}
		if p.asset.agent != nil {
			profile.Asset.Managed = true
			profile.Asset.AgentID = p.asset.agent.AgentID
			profile.Asset.OS = p.asset.agent.OS
			profile.Asset.IP = p.asset.agent.IP
			if profile.Asset.Label == "" {
				profile.Asset.Label = p.asset.agent.Hostname
			}
		}
		if profile.Asset.Label == "" {
			profile.Asset.Label = p.asset.hostKey
		}

		seen := map[string]bool{}
		var vulns []CVEExposure
		worst := 0.0
		for _, t := range p.techIDs {
			for _, cve := range cveByTech[t] {
				if seen[cve.CVEID] {
					continue
				}
				seen[cve.CVEID] = true
				vulns = append(vulns, cve)
				if cve.Severity > worst {
					worst = cve.Severity
				}
			}
		}
		profile.Vulnerabilities = vulns

		groupTechs := map[string]map[string]bool{}
		var groupOrder []string
		for _, t := range p.techIDs {
			e := attackdata.Lookup(t)
			if e == nil {
				continue
			}
			for _, gName := range e.Groups {
				if groupTechs[gName] == nil {
					groupTechs[gName] = map[string]bool{}
					groupOrder = append(groupOrder, gName)
				}
				groupTechs[gName][t] = true
			}
		}
		sort.Strings(groupOrder)
		for _, gName := range groupOrder {
			techs := make([]string, 0, len(groupTechs[gName]))
			for t := range groupTechs[gName] {
				techs = append(techs, t)
			}
			sort.Strings(techs)
			profile.ThreatIntel = append(profile.ThreatIntel, ThreatGroupExposure{GroupName: gName, TechniqueIDs: techs})
		}

		if p.asset.agent != nil {
			profile.Findings.Collected = true
			list := findingsByAgent[p.asset.agent.AgentID]
			profile.Findings.Findings = list
			profile.Findings.OpenCount = len(list)
			for _, f := range list {
				if f.Severity == "Critical" {
					profile.Findings.CriticalCount++
				}
			}
		}

		if p.asset.nodeID != "" {
			for _, gp := range corr.Gaps {
				if gp.Edge.From == p.asset.nodeID || gp.Edge.To == p.asset.nodeID {
					profile.Recommendations = append(profile.Recommendations, gp)
				}
			}
		}

		attackPathScore := clamp100(100 - int(p.apRisk+0.5))
		detectionScore := clamp100(100 - int(p.detRisk+0.5))
		vulnScore := clamp100(100 - int(worst+0.5))
		exposureRisk := 0.40*p.apRisk + 0.35*p.detRisk + 0.25*worst
		exposureScore := clamp100(100 - int(exposureRisk+0.5))
		profile.Scores = ScoreBreakdown{
			ExposureScore:          exposureScore,
			AttackPathScore:        attackPathScore,
			DetectionCoverageScore: detectionScore,
			VulnerabilityScore:     vulnScore,
		}

		ag.profiles[p.asset.hostKey] = profile
		ag.order = append(ag.order, p.asset.hostKey)
	}
	return ag, nil
}

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// Profile returns the profile for hostKey (must already be normalized —
// API handlers use attackpath.NormalizeHostKey before calling this).
func (ag *AssetGraph) Profile(hostKey string) (AssetExposureProfile, bool) {
	p, ok := ag.profiles[hostKey]
	return p, ok
}

// Summaries returns the lightweight index row for every asset, in Build's
// stable asset-union order.
func (ag *AssetGraph) Summaries() []AssetSummary {
	out := make([]AssetSummary, 0, len(ag.order))
	for _, k := range ag.order {
		p := ag.profiles[k]
		var worst float64
		var kev bool
		for _, v := range p.Vulnerabilities {
			if v.Severity > worst {
				worst = v.Severity
			}
			if v.KEV {
				kev = true
			}
		}
		out = append(out, AssetSummary{
			Asset:                  p.Asset,
			ExposureScore:          p.Scores.ExposureScore,
			AttackPathScore:        p.Scores.AttackPathScore,
			DetectionCoverageScore: p.Scores.DetectionCoverageScore,
			WorstCVESeverity:       worst,
			KEVExposed:             kev,
			OpenFindingsCount:      p.Findings.OpenCount,
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exposure/... -v`
Expected: PASS — all Task 1-4 tests.

- [ ] **Step 5: Format, build, vet**

Run: `cd orchestrator && gofmt -w internal/exposure/build.go internal/exposure/build_test.go && gofmt -l internal/exposure && go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit and push**

```bash
cd orchestrator
git add internal/exposure/build.go internal/exposure/build_test.go
git commit -m "feat(exposure): add the Build() entry point and AssetGraph

Build() ties riskscore.go/cve.go together into one pass over the
asset union: per-asset AttackPathRisk/DetectionRisk, batched CVE
enrichment, batched findings, threat-group attribution via
attackdata.Lookup, and the weighted ExposureScore composite
(0.40 AttackPath + 0.35 Detection + 0.25 Vulnerability). AssetGraph's
Summaries()/Profile() are cheap accessors over this single pass."
git push
```

---

### Task 5: API — `GET /api/exposure/assets` and `GET /api/exposure/assets/{hostKey}`

**Files:**
- Create: `orchestrator/internal/api/exposure_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/exposure_handlers_test.go`

**Interfaces:**
- Consumes: `h.db`, `h.rules *rulelib.Engine`, `h.relationships *relationships.Store` (both already on `Handler`), `h.loadAttackPathCollections(r)`, `h.loadAssetTags(r)` (already in `attackpath_handlers.go`), `attackpath.BuildGraphAndAnalyze`, `attackpath.NormalizeHostKey`, `pathcorrelation.DefaultPaths`/`Correlate`/`DefaultEdgeTechniqueMapper{}`/`NewSQLRunLookup`/`RuleLibrary`, `exposure.Build`/`NewSQLCVEEnricher`/`NewSQLFindingsLookup`/`AgentRow`. The existing package-level helper `withURLParam` (`internal/api/event_handlers_test.go`) is reused, not redefined.
- Produces: `func (h *Handler) GetExposureAssets(w, r)`, `func (h *Handler) GetExposureAsset(w, r)`, routes `GET /api/exposure/assets` and `GET /api/exposure/assets/{hostKey}` (tier `tierAny`).

- [ ] **Step 1: Write the failing test**

This package already has its own `TestMain`/shared testcontainer (`internal/api/testmain_test.go`, package-level `var sharedDB *testutil.TestDB`) — reuse it directly, do not declare a second `TestMain`.

```go
// orchestrator/internal/api/exposure_handlers_test.go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetExposureAssets_NoData_ReturnsEmptyList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetExposureAssets(rec, httptest.NewRequest(http.MethodGet, "/api/exposure/assets", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty asset list with no agents/collections, got %d", len(out))
		}
	})
}

func TestGetExposureAsset_ManagedAgent_Returns200WithManagedTrue(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO agents (agent_id, hostname, ip_address, os_version, status, state, last_update)
			 VALUES ('exp-h-agent', 'EXPHOST01', '10.0.0.5', 'Windows 11', 'idle', 'active', NOW())`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/exposure/assets/EXPHOST01", nil), "hostKey", "EXPHOST01")
		h.GetExposureAsset(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		asset, _ := out["asset"].(map[string]any)
		if asset["managed"] != true {
			t.Fatalf("expected asset.managed=true, got %v", out["asset"])
		}
	})
}

func TestGetExposureAsset_UnknownHost_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/exposure/assets/NOPE", nil), "hostKey", "NOPE")
		h.GetExposureAsset(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
```

`t.Context()` is available — this repo's `go.mod` targets Go 1.26 (`t.Context()` was added in Go 1.24).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetExposureAsset -v`
Expected: FAIL — `h.GetExposureAssets undefined`.

- [ ] **Step 3: Implement the handler**

```go
// orchestrator/internal/api/exposure_handlers.go
package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// buildAssetGraph is the shared setup both exposure endpoints use: builds
// the attack-path graph, runs SP3 Correlate, loads enrolled agents, and
// calls exposure.Build. Nil-safe throughout — never errors on a missing
// optional subsystem (h.rules, h.relationships), matching this API's
// established convention.
func (h *Handler) buildAssetGraph(r *http.Request) (*exposure.AssetGraph, error) {
	cols := h.loadAttackPathCollections(r)
	g, s := attackpath.BuildGraphAndAnalyze(cols, h.loadAssetTags(r))

	// h.rules is a *rulelib.Engine; a nil pointer passed directly into an
	// interface parameter would be a non-nil interface wrapping nil (Go's
	// typed-nil trap) — guard explicitly, same as pathcorrelation_handlers.go.
	var rules pathcorrelation.RuleLibrary
	if h.rules != nil {
		rules = h.rules
	}
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(
		r.Context(), g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{},
		pathcorrelation.NewSQLRunLookup(h.db),
		rules,
	)
	if err != nil {
		return nil, err
	}

	var rels exposure.RelationshipLookup
	if h.relationships != nil {
		rels = h.relationships
	}

	agents, err := h.loadAgentRows(r.Context())
	if err != nil {
		return nil, err
	}

	return exposure.Build(r.Context(), g, s, corr, rels,
		exposure.NewSQLCVEEnricher(h.db), exposure.NewSQLFindingsLookup(h.db), agents)
}

func (h *Handler) loadAgentRows(ctx context.Context) ([]exposure.AgentRow, error) {
	rows, err := h.db.Query(ctx, `SELECT agent_id, hostname, ip_address, os_version FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.AgentRow
	for rows.Next() {
		var a exposure.AgentRow
		if rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS) != nil {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetExposureAssets returns the fleet asset index — SP4. Read-only (Viewer+).
// GET /api/exposure/assets
func (h *Handler) GetExposureAssets(w http.ResponseWriter, r *http.Request) {
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, ag.Summaries())
}

// GetExposureAsset returns one asset's full profile — SP4. Read-only (Viewer+).
// GET /api/exposure/assets/{hostKey}
func (h *Handler) GetExposureAsset(w http.ResponseWriter, r *http.Request) {
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := attackpath.NormalizeHostKey(chi.URLParam(r, "hostKey"))
	profile, ok := ag.Profile(key)
	if !ok {
		jsonError(w, "asset not found", http.StatusNotFound)
		return
	}
	respond(w, profile)
}
```

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, add right after the SP3 correlation route:

```go
		r.Get("/api/attackpath/correlation", h.GetAttackPathCorrelation)
		r.Get("/api/exposure/assets", h.GetExposureAssets)
		r.Get("/api/exposure/assets/{hostKey}", h.GetExposureAsset)
```

- [ ] **Step 5: Add the RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, add right after `{http.MethodGet, "/api/attackpath/correlation", tierAny, ""},`:

```go
	{http.MethodGet, "/api/exposure/assets", tierAny, ""},
	{http.MethodGet, "/api/exposure/assets/{hostKey}", tierAny, ""},
```

- [ ] **Step 6: Run tests to verify they pass (Docker must be running)**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetExposureAsset|TestRBACMatrix_NoDrift' -v`
Expected: PASS.

- [ ] **Step 7: Format, build, vet**

Run: `cd orchestrator && gofmt -l internal/api internal/exposure && go build ./... && go vet ./...`
Expected: no `gofmt -l` output for files this task touched (pre-existing CRLF noise elsewhere is expected).

- [ ] **Step 8: Commit and push**

```bash
cd orchestrator
git add internal/api/exposure_handlers.go internal/api/exposure_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): add SP4 Exposure Explorer asset index and detail endpoints

GET /api/exposure/assets (Viewer+) and GET /api/exposure/assets/{hostKey}
build the fleet attack-path graph + SP3 correlation exactly like the
existing attack-path endpoints, load enrolled agents, and run
exposure.Build. Nil-safe for h.rules/h.relationships; 404s cleanly for
an unknown host key."
git push
```

---

### Task 6: UI — "Exposure Explorer" dashboard tab

**Files:**
- Modify: `orchestrator/cmd/server/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET /api/exposure/assets` (array of `AssetSummary` JSON), `GET /api/exposure/assets/{hostKey}` (one `AssetExposureProfile` JSON) — Task 5. Reuses existing global helpers already defined in this file: `apicall(path)` (fetch wrapper — session-cookie auth via `credentials:'same-origin'`, auto-redirects to login on 401, returns a `Promise` of parsed JSON — see `index.html:4604`), `x(s)` (HTML-escapes a string — `index.html:9777`; every interpolated string value MUST go through this, no exceptions, since these are unescaped `innerHTML` template strings), `apCard(label, val, col, sub)` and `apColor(score)` (existing 0-100 score-card/color helpers, already used by the Attack Path tab — `index.html:3977-3987`).
- Produces: a new nav tab `data-tab="exposure"`, functions `loadExposureAssets()`, `openExposureDetail(hostKey)`, `closeExposureDetail()` — self-contained, nothing later depends on these names.

**Before writing any code, confirm the exact line numbers below still match** (the file may have shifted slightly): `grep -n 'data-tab="attackpath"' cmd/server/wwwroot/index.html`, `grep -n 'id="tab-attackpath"' cmd/server/wwwroot/index.html`, `grep -n '^function activateTab' cmd/server/wwwroot/index.html`, `grep -n '^function showTab' cmd/server/wwwroot/index.html`, `grep -n '^var TAB_TITLES' cmd/server/wwwroot/index.html`, `grep -n 'id="agent-detail-overlay"' cmd/server/wwwroot/index.html`. Use the actual current line numbers to navigate, not the ones cited here.

- [ ] **Step 1: Add the nav item**

Inside the `Visibility` nav group, add right after the Attack Paths nav item's closing `</div>` (found via `grep -n 'data-tab="attackpath"' cmd/server/wwwroot/index.html`, then read a few lines past it to find the containing `<div class="nav-item" data-tab="attackpath" ...>...</div>` block's end):

```html
        <div class="nav-item" data-tab="exposure" onclick="showTab('exposure')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.2"/>
          </svg>
          Exposure Explorer
        </div>
```

- [ ] **Step 2: Register the tab in `activateTab`'s hardcoded tab list and `TAB_TITLES`**

`activateTab(name)` (around `index.html:3614`) shows/hides `#tab-*` divs by iterating a **hardcoded array of tab names** — a new tab that is not in this array will never display, regardless of whether its markup and nav item exist. Find:

```javascript
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','integrations'].forEach(function(t) {
```

and add `'exposure'` to the array (anywhere in the list, e.g. right after `'attackpath'`):

```javascript
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','integrations'].forEach(function(t) {
```

Also add a title entry to `TAB_TITLES` (around `index.html:3487`) — find the object literal and add `exposure:'Exposure Explorer',` inside it, e.g. right after `em:'Endpoint Mastery'`:

```javascript
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer' };
```

- [ ] **Step 3: Add the tab content — index table**

Find the containing `<div id="tab-attackpath" style="display:none">...</div>` block (`grep -n 'id="tab-attackpath"' cmd/server/wwwroot/index.html`) and insert a new sibling `<div id="tab-exposure" style="display:none">...</div>` block immediately after its closing `</div>` — matching the plain top-level tab-div convention used by every other tab (no `class="tab-content"` — that class does not exist in this file):

```html
      <div id="tab-exposure" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Exposure Explorer</h1>
            <div style="font-size:0.8rem;color:var(--muted)">Per-asset attack-path exposure, detection coverage, CVE/KEV/EPSS risk, threat-group attribution, and findings — one composite Exposure Score per host.</div>
          </div>
          <button class="btn btn-outline btn-sm" onclick="loadExposureAssets()">Refresh</button>
        </div>
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr>
                <th>Host</th><th>Managed</th><th>Exposure</th><th>Attack Path</th><th>Detection</th>
                <th>Crown Jewel</th><th>Open Findings</th><th>KEV</th>
              </tr>
            </thead>
            <tbody id="exp-table-body"><tr><td colspan="8" class="empty">Loading…</td></tr></tbody>
          </table>
        </div>
      </div>
```

- [ ] **Step 4: Add the detail drawer markup**

Mirror the existing `agent-detail-overlay` drawer exactly (`grep -n 'id="agent-detail-overlay"' cmd/server/wwwroot/index.html` — insert this new block as a sibling right after that drawer's closing `</div>`):

```html
<div id="exposure-detail-overlay" class="drawer-overlay" onclick="if(event.target===this)closeExposureDetail()">
  <div class="drawer" style="width:640px;max-width:96vw">
    <div class="drawer-header">
      <h3 id="exp-detail-title">Asset</h3>
      <button class="drawer-close" onclick="closeExposureDetail()">&#10005;</button>
    </div>
    <div class="drawer-body" style="overflow-y:auto" id="exp-detail-body"></div>
  </div>
</div>
```

- [ ] **Step 5: Add the JS — load index, render detail**

Add near `apCard`/`apColor` (`grep -n "^function apCard" cmd/server/wwwroot/index.html`, insert after that function):

```javascript
function loadExposureAssets() {
  var body = document.getElementById('exp-table-body');
  body.innerHTML = '<tr><td colspan="8" class="empty">Loading…</td></tr>';
  apicall('/api/exposure/assets').then(function(assets) {
    if (!assets || !assets.length) {
      body.innerHTML = '<tr><td colspan="8" class="empty">No assets found — enroll an agent or run attack-path collection.</td></tr>';
      return;
    }
    body.innerHTML = assets.map(function(a) {
      return '<tr style="cursor:pointer" onclick="openExposureDetail(\'' + x(a.asset.hostKey) + '\')">' +
        '<td style="font-weight:600">' + x(a.asset.label) + '</td>' +
        '<td>' + (a.asset.managed ? '<span class="badge">Managed</span>' : '<span class="badge" style="color:var(--muted)">Discovered</span>') + '</td>' +
        '<td style="color:' + apColor(a.exposureScore) + ';font-weight:700">' + a.exposureScore + '</td>' +
        '<td>' + a.attackPathScore + '</td>' +
        '<td>' + a.detectionCoverageScore + '</td>' +
        '<td>' + (a.asset.crownJewel ? '<span class="badge" style="color:var(--warning);border-color:var(--warning)">' + x(a.asset.crownJewel) + '</span>' : '') + '</td>' +
        '<td>' + a.openFindingsCount + '</td>' +
        '<td>' + (a.kevExposed ? '<span class="badge" style="color:var(--danger);border-color:var(--danger)">KEV</span>' : '') + '</td>' +
        '</tr>';
    }).join('');
  }).catch(function(e) {
    body.innerHTML = '<tr><td colspan="8" class="empty" style="color:var(--danger)">Failed to load: ' + x(e.message) + '</td></tr>';
  });
}

function _expGapPriorityColor(p) {
  return p === 'Critical' ? 'var(--danger)' : p === 'High' ? '#f0883e' : p === 'Medium' ? 'var(--warning)' : 'var(--success)';
}

function openExposureDetail(hostKey) {
  document.getElementById('exp-detail-title').textContent = hostKey;
  var body = document.getElementById('exp-detail-body');
  body.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  document.getElementById('exposure-detail-overlay').classList.add('open');
  apicall('/api/exposure/assets/' + encodeURIComponent(hostKey)).then(function(p) {
    var h = '<div class="kpi-row" style="margin-bottom:1rem">' +
      apCard('Exposure Score', p.scores.exposureScore + '<span style="font-size:0.9rem;color:var(--muted)">/100</span>', apColor(p.scores.exposureScore), 'higher is safer') +
      apCard('Attack Path', p.scores.attackPathScore, apColor(p.scores.attackPathScore), '') +
      apCard('Detection', p.scores.detectionCoverageScore, apColor(p.scores.detectionCoverageScore), '') +
      apCard('Vulnerability', p.scores.vulnerabilityScore, apColor(p.scores.vulnerabilityScore), '') +
      '</div>';

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Prioritized Recommendations</div>';
    if (p.recommendations && p.recommendations.length) {
      h += '<div class="tbl-wrap" style="margin-bottom:1rem"><table><thead><tr><th>From</th><th>Via</th><th>To</th><th>Priority</th><th>Reason</th></tr></thead><tbody>';
      p.recommendations.forEach(function(g) {
        h += '<tr><td>' + x(g.edge.from) + '</td><td>' + x(g.edge.kind) + '</td><td>' + x(g.edge.to) + '</td>' +
          '<td style="font-weight:700;color:' + _expGapPriorityColor(g.priority) + '">' + x(g.priority) + '</td>' +
          '<td style="color:var(--muted);font-size:0.8rem">' + x(g.reason) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div class="tiny muted" style="margin-bottom:1rem">No gaps on this asset&apos;s attack paths.</div>';
    }

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Vulnerabilities</div>';
    if (p.vulnerabilities && p.vulnerabilities.length) {
      h += '<div class="tbl-wrap" style="margin-bottom:1rem"><table><thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>Technique</th></tr></thead><tbody>';
      p.vulnerabilities.forEach(function(v) {
        h += '<tr><td>' + x(v.cveId) + '</td><td>' + (v.cvss || '—') + '</td><td>' + (v.kev ? 'Yes' : '') + '</td>' +
          '<td>' + (v.epssScore || '—') + '</td><td>' + x(v.techniqueId) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div class="tiny muted" style="margin-bottom:1rem">No mapped CVEs.</div>';
    }

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Findings</div>';
    if (!p.findings.collected) {
      h += '<div class="tiny muted" style="margin-bottom:1rem">Not enrolled — no scan history.</div>';
    } else if (p.findings.findings && p.findings.findings.length) {
      h += '<div class="tbl-wrap" style="margin-bottom:1rem"><table><thead><tr><th>Technique</th><th>Severity</th><th>State</th></tr></thead><tbody>';
      p.findings.findings.forEach(function(f) {
        h += '<tr><td>' + x(f.techniqueName || f.techniqueId) + '</td><td>' + x(f.severity) + '</td><td>' + x(f.exposureState) + '</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div class="tiny muted" style="margin-bottom:1rem">No open findings.</div>';
    }

    h += '<div style="font-weight:700;color:var(--text);margin-bottom:0.4rem">Threat Groups</div>';
    if (p.threatIntel && p.threatIntel.length) {
      h += p.threatIntel.map(function(g) { return '<span class="badge" style="margin:2px">' + x(g.groupName) + '</span>'; }).join('');
    } else {
      h += '<div class="tiny muted">No attributed threat groups.</div>';
    }

    body.innerHTML = h;
  }).catch(function(e) {
    body.innerHTML = '<div class="empty" style="color:var(--danger)">Failed to load: ' + x(e.message) + '</div>';
  });
}

function closeExposureDetail() {
  document.getElementById('exposure-detail-overlay').classList.remove('open');
}
```

- [ ] **Step 6: Wire the tab into `showTab`'s existing load-on-open dispatch**

In `showTab(name)` (around `index.html:3625`), add a line alongside the other tabs' on-open data loads, e.g. right after `if (name === 'attackpath') loadAttackPath();`:

```javascript
  if (name === 'exposure') loadExposureAssets();
```

- [ ] **Step 7: Manual smoke check**

Since this is a UI change, per the project's testing standard: start the server locally (`cd orchestrator && go run ./cmd/server`), log in, click "Exposure Explorer" in the sidebar, and confirm: the tab actually displays (this is the step that would have caught the missing `activateTab` array entry if Step 2 had been skipped), the index table renders (even empty, showing the "No assets found" state), and clicking a row (once at least one agent is enrolled) opens the detail overlay with all five sections rendering their real-or-empty state correctly, and closes via both the × button and clicking the backdrop. Check the browser console for JS errors. Fix any issue found before proceeding — do not mark this task done on faith.

- [ ] **Step 8: Commit and push**

```bash
cd orchestrator
git add cmd/server/wwwroot/index.html
git commit -m "feat(ui): add Exposure Explorer dashboard tab

New sidebar tab under Visibility: sortable asset index (Exposure/
AttackPath/Detection scores, crown-jewel/KEV badges) and a detail
overlay per asset (score cards, prioritized recommendations,
vulnerabilities, findings or 'not enrolled' state, threat groups).
Reuses this file's existing apicall/x/apCard/apColor helpers and the
established drawer-overlay pattern rather than inventing new ones."
git push
```

---

### Task 7: Full validation and final push

**Files:** none (verification only).

- [ ] **Step 1: Repo-wide format, build, vet**

Run: `cd orchestrator && gofmt -l internal/exposure internal/api cmd/server && go build ./... && go vet ./...`
Expected: `gofmt -l` prints nothing for any file this plan touched or created (pre-existing CRLF noise on untouched files elsewhere is expected, out of scope); build and vet both clean.

- [ ] **Step 2: Full Go test suite (Docker must be running)**

Run: `cd orchestrator && go test ./... 2>&1 | tail -100`
Expected: every package reports `ok` (or `[no test files]`); zero `FAIL` lines, including `internal/exposure` and `internal/api`.

- [ ] **Step 3: Scoped stress runs**

Run: `cd orchestrator && go test ./internal/exposure/... -count=10 -v 2>&1 | tail -100`
Expected: zero `FAIL` across all 10 iterations.

Run: `cd orchestrator && go test ./internal/api/... -count=5 -run 'TestGetExposureAsset|TestRBACMatrix_NoDrift' -v 2>&1 | tail -60`
Expected: zero `FAIL`.

- [ ] **Step 4: Confirm everything is pushed**

Run: `cd orchestrator && git status --short && git log --oneline -12`
Expected: working tree clean aside from pre-existing baseline untracked files (not created by this plan); all 6 feature commits from this plan visible, most recent first.

Run: `git status -sb | head -1`
Expected: `## main...origin/main` with no `[ahead N]`/`[behind N]` suffix.

- [ ] **Step 5: Manual smoke check (optional but recommended)**

If a local server + Postgres are available and Task 6's Step 6 smoke check has not already covered this: start the server, enroll or simulate at least one asset (an agent row plus, ideally, some attack-path collection data), and confirm `GET /api/exposure/assets` and `GET /api/exposure/assets/{hostKey}` return the expected JSON shape end to end.
