# Endpoint Risk & Remediation View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Risk & Remediation" tab to the Agents section — a fleet-wide list of agents ranked by a computed Health Score, and a per-agent drill-down with categorized, evidence-backed findings, an attack-path chain narrative, and a deficit-ranked action plan.

**Architecture:** A new pure package `internal/endpointrisk` combines an already-existing `exposure.AssetExposureProfile` (per-agent CVE/attack-path/detection data, zero new collection) with two small new per-agent aggregations in `internal/api` (a Compliance rollup and a BAS Readiness aggregation, both built by reusing the existing `h.aggregateAgentResults` helper) into one `EndpointHealth` result, exposed via two new read endpoints. The frontend adds a small sub-tab switcher to the Agents section (mirroring the existing `setDashView` pattern) and a new tab in the existing per-agent detail drawer.

**Tech Stack:** Go, PostgreSQL (`pgxpool`), vanilla ES5 JavaScript in `orchestrator/wwwroot/index.html` (no build step, no frontend test framework — matches this file's existing convention).

## Global Constraints

- No new agent-side data collection. Security Configuration, Identity, Patch Management, and Application Risk categories render as "Not yet collected" placeholders — never a fabricated score or finding.
- No remediation execution of any kind in this sub-project (no one-click fixes).
- `CriticalityRisk` (from `exposure.Scores`) is never folded into the Health Score — it's a separate sort/priority signal, not a health measure.
- Trend covers only the Compliance and BAS Readiness categories in V1 (both derived from flat, timestamp-filterable `models.SimulationResult` rows); Exposure/Attack-Path/Detection Health are current-value-only — see spec §6 for why.
- Action Plan ranks by category-level deficit (`100 - categoryScore`), never a fabricated per-finding "risk reduction %".
- "Estimated Time," "Requires Reboot," and "Can Audspect Fix" are not shown on any finding in this sub-project.
- Spec reference: `docs/superpowers/specs/2026-08-01-endpoint-risk-remediation-view-design.md`.

---

### Task 1: `internal/endpointrisk` — types and pure health computation

**Files:**
- Create: `orchestrator/internal/endpointrisk/types.go`
- Create: `orchestrator/internal/endpointrisk/health.go`
- Test: `orchestrator/internal/endpointrisk/health_test.go`

**Interfaces:**
- Consumes: `exposure.AssetExposureProfile` (existing — `Scores{ExposureScore, AttackPathScore, DetectionCoverageScore, VulnerabilityScore, CriticalityRisk}`, `Vulnerabilities []exposure.CVEExposure{CVEID,CVSS,KEV,EPSSScore,TechniqueID,Severity}`, `AttackPath exposure.AttackPathContext{Reachable,OnShortestDAPath,DistanceToNearestCrownJewel,IsChokePoint}`, `Detection exposure.DetectionContext{Covered,Partial,Gap,Unknown}`, `Recommendations []pathcorrelation.PrioritizedGap{Edge{From,To,Kind},Priority,Reason,Remediation}`).
- Produces: `ComplianceInput{PercentByFramework map[string]float64, FailedFindings []Finding, Collected bool}`, `BASReadinessInput{TechniquesTested int, PassRate float64, LastExecutedAt *time.Time, Collected bool}` — the two shapes Task 2's aggregations must build. `ComputeHealth(agentID string, profile exposure.AssetExposureProfile, compliance ComplianceInput, bas BASReadinessInput, pastCompliance ComplianceInput, pastBAS BASReadinessInput) EndpointHealth` — the single exported entry point Task 3's handler calls.

- [ ] **Step 1: Write `types.go`**

```go
package endpointrisk

// Finding is one evidence-backed issue shown on a category card.
// EstimatedTime/RequiresReboot/CanAudspectFix are deliberately absent --
// this sub-project ships no remediation-execution mechanism, so there is
// nothing honest to say about how a fix would be applied yet.
type Finding struct {
	Title             string `json:"title"`
	Severity          string `json:"severity"` // Critical | High | Medium | Low
	Risk              string `json:"risk"`
	AffectedStandard  string `json:"affectedStandard,omitempty"`
	Remediation       string `json:"remediation"`
}

// CategoryScore is one category's contribution to the Health Score.
// Collected=false means no data source exists for this category yet
// (Security Configuration, Identity, Patch Management, Application Risk in
// V1) -- Score/Deficit/Findings are meaningless in that case and the
// frontend must render a "Not yet collected" placeholder instead of a 0.
type CategoryScore struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Collected bool      `json:"collected"`
	Score     int       `json:"score,omitempty"`   // 0-100, higher = safer
	Deficit   int       `json:"deficit,omitempty"` // 100 - Score
	Findings  []Finding `json:"findings,omitempty"`
}

// ActionItem is one row of the Recommended Action Plan: the worst finding
// in the category with the biggest deficit, not a fabricated per-finding
// risk-reduction percentage.
type ActionItem struct {
	CategoryID   string  `json:"categoryId"`
	CategoryName string  `json:"categoryName"`
	Deficit      int     `json:"deficit"`
	Finding      Finding `json:"finding"`
}

// AttackPathStep is one edge in the endpoint's attack-path chain narrative,
// rendered directly from exposure.Recommendations -- no new correlation
// logic.
type AttackPathStep struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// EndpointHealth is the full computed result for one agent.
type EndpointHealth struct {
	AgentID         string           `json:"agentId"`
	HealthScore     int              `json:"healthScore"`
	CriticalityRisk int              `json:"criticalityRisk"` // exposure.Scores.CriticalityRisk, sort/priority signal only -- never part of HealthScore
	Categories      []CategoryScore  `json:"categories"`
	ActionPlan      []ActionItem     `json:"actionPlan"`
	AttackPathChain []AttackPathStep `json:"attackPathChain"`
	Trend           string           `json:"trend"` // Improving | Stable | Declining | InsufficientData
}

// ComplianceInput is Task 2's compliance rollup output: one CompliancePercent
// per loaded framework, plus the real failed-control findings with their
// existing remediation text.
type ComplianceInput struct {
	PercentByFramework map[string]float64
	FailedFindings     []Finding
	Collected          bool
}

// BASReadinessInput is Task 2's BAS readiness aggregation output.
type BASReadinessInput struct {
	TechniquesTested int
	PassRate         float64 // 0-100
	LastExecutedAt   *time.Time
	Collected        bool
}
```

This needs `"time"` imported alongside the struct definitions above.

- [ ] **Step 2: Write `health.go`**

```go
package endpointrisk

import (
	"time"

	"github.com/audspect/bas/internal/exposure"
)

// Category IDs -- used both for the 5 collected categories (real score) and
// the 4 not-yet-collected placeholders, in the fixed display order the
// design spec's category table lists.
const (
	CategoryExposureAttackPath = "exposure-attackpath"
	CategoryDetectionHealth    = "detection-health"
	CategoryVulnerabilities    = "vulnerabilities"
	CategoryCompliance         = "compliance"
	CategoryBASReadiness       = "bas-readiness"
	CategorySecurityConfig     = "security-configuration"
	CategoryIdentity           = "identity"
	CategoryPatchManagement    = "patch-management"
	CategoryApplicationRisk    = "application-risk"
)

var notYetCollectedCategories = []struct{ ID, Name string }{
	{CategorySecurityConfig, "Security Configuration"},
	{CategoryIdentity, "Identity"},
	{CategoryPatchManagement, "Patch Management"},
	{CategoryApplicationRisk, "Application Risk"},
}

// ComputeHealth is pure -- no I/O -- so every combination is unit-testable
// without a database. pastCompliance/pastBAS are the same two inputs
// recomputed with evidence filtered to 7 days ago by the caller (Task 3);
// exposure-derived categories have no past counterpart, per spec §6, so
// trend only ever reflects Compliance + BAS Readiness.
func ComputeHealth(agentID string, profile exposure.AssetExposureProfile, compliance ComplianceInput, bas BASReadinessInput, pastCompliance ComplianceInput, pastBAS BASReadinessInput) EndpointHealth {
	exposureAttackPath := CategoryScore{
		ID: CategoryExposureAttackPath, Name: "Exposure / Attack Path", Collected: true,
		Score: mean2(profile.Scores.ExposureScore, profile.Scores.AttackPathScore),
	}
	exposureAttackPath.Deficit = 100 - exposureAttackPath.Score
	exposureAttackPath.Findings = attackPathFindings(profile)

	detection := CategoryScore{
		ID: CategoryDetectionHealth, Name: "Detection Health", Collected: true,
		Score: profile.Scores.DetectionCoverageScore,
	}
	detection.Deficit = 100 - detection.Score
	detection.Findings = detectionFindings(profile)

	vulns := CategoryScore{
		ID: CategoryVulnerabilities, Name: "Vulnerabilities", Collected: true,
		Score: profile.Scores.VulnerabilityScore,
	}
	vulns.Deficit = 100 - vulns.Score
	vulns.Findings = vulnerabilityFindings(profile)

	compCat := CategoryScore{ID: CategoryCompliance, Name: "Compliance", Collected: compliance.Collected}
	if compliance.Collected {
		compCat.Score = round(meanOf(compliance.PercentByFramework))
		compCat.Deficit = 100 - compCat.Score
		compCat.Findings = compliance.FailedFindings
	}

	basCat := CategoryScore{ID: CategoryBASReadiness, Name: "BAS Readiness", Collected: bas.Collected}
	if bas.Collected {
		basCat.Score = round(bas.PassRate)
		basCat.Deficit = 100 - basCat.Score
		basCat.Findings = basReadinessFindings(bas)
	}

	categories := []CategoryScore{exposureAttackPath, detection, vulns, compCat, basCat}
	for _, c := range notYetCollectedCategories {
		categories = append(categories, CategoryScore{ID: c.ID, Name: c.Name, Collected: false})
	}

	collectedScores := []int{}
	for _, c := range categories {
		if c.Collected {
			collectedScores = append(collectedScores, c.Score)
		}
	}

	return EndpointHealth{
		AgentID:         agentID,
		HealthScore:     round(meanInts(collectedScores)),
		CriticalityRisk: profile.Scores.CriticalityRisk,
		Categories:      categories,
		ActionPlan:      buildActionPlan(categories),
		AttackPathChain: buildAttackPathChain(profile),
		Trend:           computeTrend(compliance, bas, pastCompliance, pastBAS),
	}
}

func mean2(a, b int) int { return (a + b) / 2 }

func round(f float64) int {
	if f < 0 {
		return 0
	}
	return int(f + 0.5)
}

func meanOf(m map[string]float64) float64 {
	if len(m) == 0 {
		return 0
	}
	var sum float64
	for _, v := range m {
		sum += v
	}
	return sum / float64(len(m))
}

func meanInts(vs []int) float64 {
	if len(vs) == 0 {
		return 0
	}
	var sum int
	for _, v := range vs {
		sum += v
	}
	return float64(sum) / float64(len(vs))
}

// buildActionPlan ranks the collected categories by deficit, worst first,
// and surfaces each one's single worst finding (first in its Findings
// slice -- callers are responsible for ordering Findings worst-first when
// they build them, matching how exposure/pathcorrelation already rank
// their own output).
func buildActionPlan(categories []CategoryScore) []ActionItem {
	var out []ActionItem
	for _, c := range categories {
		if !c.Collected || c.Deficit <= 0 || len(c.Findings) == 0 {
			continue
		}
		out = append(out, ActionItem{
			CategoryID: c.ID, CategoryName: c.Name, Deficit: c.Deficit, Finding: c.Findings[0],
		})
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Deficit > out[i].Deficit {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func buildAttackPathChain(profile exposure.AssetExposureProfile) []AttackPathStep {
	var out []AttackPathStep
	for _, g := range profile.Recommendations {
		out = append(out, AttackPathStep{From: g.Edge.From, To: g.Edge.To, Kind: string(g.Edge.Kind), Reason: g.Reason})
	}
	return out
}

func attackPathFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	for _, g := range profile.Recommendations {
		out = append(out, Finding{
			Title: string(g.Priority) + ": " + g.Edge.From + " -> " + g.Edge.To,
			Severity: string(g.Priority), Risk: g.Reason, Remediation: g.Remediation,
		})
	}
	return out
}

func detectionFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	if profile.Detection.Gap > 0 {
		out = append(out, Finding{
			Title: "Detection gap on this endpoint", Severity: "High",
			Risk:        "No detection rule fired for a technique known to threaten this asset.",
			Remediation: "Add or tune a detection rule for the affected technique(s).",
		})
	}
	if profile.Detection.Unknown > 0 {
		out = append(out, Finding{
			Title: "Unverified detection coverage", Severity: "Medium",
			Risk:        "No verification evidence exists either way for a technique threatening this asset.",
			Remediation: "Run a verification pass (Detection Validation) against the affected technique(s).",
		})
	}
	return out
}

func vulnerabilityFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	for _, v := range profile.Vulnerabilities {
		sev := "Medium"
		switch {
		case v.KEV || v.CVSS >= 9:
			sev = "Critical"
		case v.CVSS >= 7:
			sev = "High"
		}
		out = append(out, Finding{
			Title: v.CVEID, Severity: sev,
			Risk:        cveRiskNarrative(v),
			Remediation: "Update the affected software to a patched version.",
		})
	}
	// worst-first, so buildActionPlan's Findings[0] is the worst CVE
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if severityRank(out[j].Severity) > severityRank(out[i].Severity) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "Critical":
		return 3
	case "High":
		return 2
	case "Medium":
		return 1
	default:
		return 0
	}
}

func cveRiskNarrative(v exposure.CVEExposure) string {
	if v.KEV {
		return v.CVEID + " is listed in CISA's Known Exploited Vulnerabilities catalog -- active exploitation confirmed in the wild."
	}
	return v.CVEID + " (CVSS " + ftoa1(v.CVSS) + ") threatens this asset via a technique in its attack surface."
}

func ftoa1(f float64) string {
	// avoids importing strconv/fmt for one call site's simple 1-decimal format
	i := int(f*10 + 0.5)
	return itoa(i/10) + "." + itoa(i%10)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func basReadinessFindings(bas BASReadinessInput) []Finding {
	if bas.PassRate >= 90 {
		return nil
	}
	return []Finding{{
		Title: "Low BAS pass rate on this endpoint", Severity: "Medium",
		Risk:        "Simulations against this endpoint have been failing more than expected.",
		Remediation: "Review recent failed simulation results and address the underlying control gaps.",
	}}
}

// healthBand is a coarse Good/Fair/Poor grouping used only for trend
// comparison, the same "compare bands, not raw deltas" approach Control
// Health Foundation's computeTrend already uses -- a 1-point wobble inside
// "Poor" must not read as Improving.
func healthBand(score float64) int {
	switch {
	case score >= 80:
		return 2
	case score >= 50:
		return 1
	default:
		return 0
	}
}

// computeTrend reflects only Compliance + BAS Readiness (see spec §6);
// Exposure/Attack-Path/Detection Health have no past counterpart to compare.
func computeTrend(compliance, pastCompliance ComplianceInput, bas, pastBAS BASReadinessInput) string {
	if !compliance.Collected && !bas.Collected {
		return "InsufficientData"
	}
	if !pastCompliance.Collected && !pastBAS.Collected {
		return "InsufficientData"
	}
	current := trendInputScore(compliance, bas)
	past := trendInputScore(pastCompliance, pastBAS)
	cb, pb := healthBand(current), healthBand(past)
	switch {
	case cb > pb:
		return "Improving"
	case cb < pb:
		return "Declining"
	default:
		return "Stable"
	}
}

func trendInputScore(compliance ComplianceInput, bas BASReadinessInput) float64 {
	var sum, n float64
	if compliance.Collected {
		sum += meanOf(compliance.PercentByFramework)
		n++
	}
	if bas.Collected {
		sum += bas.PassRate
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / n
}
```

Note: `computeTrend`'s signature above takes `(compliance, pastCompliance ComplianceInput, bas, pastBAS BASReadinessInput)` — fix the call site in `ComputeHealth` to match this exact parameter order: `computeTrend(compliance, pastCompliance, bas, pastBAS)`.

- [ ] **Step 3: Fix the `ComputeHealth` call to `computeTrend` to match the real parameter order**

In the `ComputeHealth` function written in Step 2, find:

```go
		Trend:           computeTrend(compliance, bas, pastCompliance, pastBAS),
```

Replace with:

```go
		Trend:           computeTrend(compliance, pastCompliance, bas, pastBAS),
```

- [ ] **Step 4: Write `health_test.go`**

```go
package endpointrisk

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

func TestComputeHealth_ScoresOnlyCollectedCategories(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{ExposureScore: 80, AttackPathScore: 60, DetectionCoverageScore: 90, VulnerabilityScore: 70, CriticalityRisk: 40},
	}
	compliance := ComplianceInput{Collected: false}
	bas := BASReadinessInput{Collected: false}
	got := ComputeHealth("agent-1", profile, compliance, bas, compliance, bas)

	// exposureAttackPath = mean(80,60) = 70; detection=90; vulns=70 -> mean(70,90,70) = 76.67 -> round 77
	if got.HealthScore != 77 {
		t.Errorf("HealthScore = %d, want 77", got.HealthScore)
	}
	if got.CriticalityRisk != 40 {
		t.Errorf("CriticalityRisk = %d, want 40 (not folded into HealthScore)", got.CriticalityRisk)
	}
	var sawCompliance, sawBAS bool
	for _, c := range got.Categories {
		if c.ID == CategoryCompliance {
			sawCompliance = true
			if c.Collected {
				t.Error("Compliance category should be Collected=false")
			}
		}
		if c.ID == CategoryBASReadiness {
			sawBAS = true
			if c.Collected {
				t.Error("BAS Readiness category should be Collected=false")
			}
		}
	}
	if !sawCompliance || !sawBAS {
		t.Error("expected both Compliance and BAS Readiness categories present even when uncollected")
	}
}

func TestComputeHealth_NotYetCollectedCategoriesAlwaysPresent(t *testing.T) {
	got := ComputeHealth("agent-1", exposure.AssetExposureProfile{}, ComplianceInput{}, BASReadinessInput{}, ComplianceInput{}, BASReadinessInput{})
	want := map[string]bool{CategorySecurityConfig: false, CategoryIdentity: false, CategoryPatchManagement: false, CategoryApplicationRisk: false}
	for _, c := range got.Categories {
		if _, ok := want[c.ID]; ok {
			if c.Collected {
				t.Errorf("category %s should be Collected=false", c.ID)
			}
			delete(want, c.ID)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing not-yet-collected categories: %v", want)
	}
}

func TestComputeHealth_ActionPlanRankedByDeficit(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Scores: exposure.ScoreBreakdown{ExposureScore: 90, AttackPathScore: 90, DetectionCoverageScore: 40, VulnerabilityScore: 95},
		Detection: exposure.DetectionContext{Gap: 1},
	}
	got := ComputeHealth("agent-1", profile, ComplianceInput{}, BASReadinessInput{}, ComplianceInput{}, BASReadinessInput{})
	if len(got.ActionPlan) == 0 {
		t.Fatal("expected at least one action item")
	}
	if got.ActionPlan[0].CategoryID != CategoryDetectionHealth {
		t.Errorf("top action = %s, want %s (biggest deficit: detection health at 60)", got.ActionPlan[0].CategoryID, CategoryDetectionHealth)
	}
}

func TestComputeHealth_AttackPathChainFromRecommendations(t *testing.T) {
	profile := exposure.AssetExposureProfile{
		Recommendations: []pathcorrelation.PrioritizedGap{
			{Edge: attackpathEdge("HOST-A", "HOST-B", "rdp"), Priority: "Critical", Reason: "RDP reachable", Remediation: "Disable RDP or require MFA"},
		},
	}
	got := ComputeHealth("agent-1", profile, ComplianceInput{}, BASReadinessInput{}, ComplianceInput{}, BASReadinessInput{})
	if len(got.AttackPathChain) != 1 {
		t.Fatalf("got %d chain steps, want 1", len(got.AttackPathChain))
	}
	if got.AttackPathChain[0].From != "HOST-A" || got.AttackPathChain[0].To != "HOST-B" {
		t.Errorf("chain step = %+v, want From=HOST-A To=HOST-B", got.AttackPathChain[0])
	}
}

func TestComputeTrend_BothCollected_BandComparison(t *testing.T) {
	now := ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 90}}
	nowBAS := BASReadinessInput{Collected: true, PassRate: 90}
	past := ComplianceInput{Collected: true, PercentByFramework: map[string]float64{"ISO": 40}}
	pastBAS := BASReadinessInput{Collected: true, PassRate: 40}
	got := computeTrend(now, past, nowBAS, pastBAS)
	if got != "Improving" {
		t.Errorf("computeTrend = %q, want Improving (band moved from Poor to Good)", got)
	}
}

func TestComputeTrend_NeitherCollected_InsufficientData(t *testing.T) {
	got := computeTrend(ComplianceInput{}, ComplianceInput{}, BASReadinessInput{}, BASReadinessInput{})
	if got != "InsufficientData" {
		t.Errorf("computeTrend = %q, want InsufficientData", got)
	}
}

func attackpathEdge(from, to, kind string) attackpathEdgeType {
	return attackpathEdgeType{From: from, To: to, Kind: attackpathEdgeKind(kind)}
}
```

`attackpathEdge`/`attackpathEdgeType`/`attackpathEdgeKind` above are placeholders for the real type — replace before running: import `"github.com/audspect/bas/internal/attackpath"` and use `attackpath.Edge{From: from, To: to, Kind: attackpath.EdgeKind(kind)}` directly in the test instead of the local helper function. Remove the `attackpathEdge` helper function entirely and change the test to:

```go
	profile := exposure.AssetExposureProfile{
		Recommendations: []pathcorrelation.PrioritizedGap{
			{Edge: attackpath.Edge{From: "HOST-A", To: "HOST-B", Kind: "rdp"}, Priority: "Critical", Reason: "RDP reachable", Remediation: "Disable RDP or require MFA"},
		},
	}
```

with `"github.com/audspect/bas/internal/attackpath"` added to the import block.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/endpointrisk/... -v` (from `orchestrator/`)
Expected: all tests PASS. No Docker required — everything in this package is a pure function.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/endpointrisk/types.go orchestrator/internal/endpointrisk/health.go orchestrator/internal/endpointrisk/health_test.go
git commit -m "feat(endpointrisk): add pure health-score computation"
```

---

### Task 2: Compliance and BAS Readiness aggregations

**Files:**
- Create: `orchestrator/internal/api/endpointrisk_aggregations.go`
- Test: `orchestrator/internal/api/endpointrisk_aggregations_test.go`

**Interfaces:**
- Consumes: `h.aggregateAgentResults(ctx, agentID) []models.SimulationResult` (existing, `handlers.go:3763`), `h.complianceMapper.Frameworks() []compliance.FrameworkMeta` and `.GenerateReport(results, fwID, agentID, "", "") (*compliance.ComplianceReport, error)` (existing), `models.ResultPass/ResultBlocked/ResultFail/ResultSkipped/ResultError` (existing).
- Produces: `(h *Handler) complianceInput(ctx context.Context, agentID string, asOf time.Time) endpointrisk.ComplianceInput`, `(h *Handler) basReadinessInput(ctx context.Context, agentID string, asOf time.Time) endpointrisk.BASReadinessInput` — both filter `h.aggregateAgentResults`' output to `ExecutedAt <= asOf` before use, which is what makes Task 3's "now" vs "7-days-ago" trend calls possible with a single shared results fetch per agent per request.

- [ ] **Step 1: Write `endpointrisk_aggregations.go`**

```go
package api

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/models"
)

// filterByAsOf returns only the results executed at or before asOf --
// what makes computing the same aggregation "now" and "7 days ago" from one
// shared results fetch possible, the same idea as controlhealth's asOf
// parameter but applied to an already-fetched slice instead of a SQL WHERE.
func filterByAsOf(results []models.SimulationResult, asOf time.Time) []models.SimulationResult {
	out := make([]models.SimulationResult, 0, len(results))
	for _, r := range results {
		if !r.ExecutedAt.After(asOf) {
			out = append(out, r)
		}
	}
	return out
}

// complianceInput builds one CompliancePercent per loaded framework plus
// the real failed-control findings (with their existing remediation text),
// mirroring complianceRows (handlers.go:3734) but returning
// endpointrisk.ComplianceInput instead of report rows.
func (h *Handler) complianceInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.ComplianceInput {
	if h.complianceMapper == nil {
		return endpointrisk.ComplianceInput{}
	}
	results := filterByAsOf(allResults, asOf)
	pct := map[string]float64{}
	var findings []endpointrisk.Finding
	for _, fw := range h.complianceMapper.Frameworks() {
		cr, err := h.complianceMapper.GenerateReport(results, fw.ID, agentID, "", "")
		if err != nil {
			continue
		}
		pct[fw.Name] = cr.Summary.CompliancePercent
		for _, ctrl := range cr.Controls {
			if ctrl.Status != "fail" {
				continue
			}
			for _, ev := range ctrl.Evidence {
				if ev.Result != "fail" {
					continue
				}
				findings = append(findings, endpointrisk.Finding{
					Title:            ctrl.Name,
					Severity:         "High",
					Risk:             "Control " + ctrl.ID + " (" + ctrl.Category + ") failed validation.",
					AffectedStandard: fw.Name + " " + ctrl.ID,
					Remediation:      ev.Remediation,
				})
			}
		}
	}
	return endpointrisk.ComplianceInput{PercentByFramework: pct, FailedFindings: findings, Collected: len(pct) > 0}
}

// basReadinessInput aggregates pass rate, technique count, and last-run
// timestamp directly from the agent's own result history -- no new SQL
// query, reusing the exact same aggregateAgentResults call complianceInput
// already needs.
func (h *Handler) basReadinessInput(asOf time.Time, allResults []models.SimulationResult) endpointrisk.BASReadinessInput {
	results := filterByAsOf(allResults, asOf)
	var passed, failed int
	var lastAt *time.Time
	techSeen := map[string]bool{}
	for _, r := range results {
		if r.Result == models.ResultSkipped || r.Result == models.ResultError {
			continue
		}
		techSeen[r.Technique.ID] = true
		if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
			passed++
		} else if r.Result == models.ResultFail {
			failed++
		}
		if lastAt == nil || r.ExecutedAt.After(*lastAt) {
			t := r.ExecutedAt
			lastAt = &t
		}
	}
	tested := passed + failed
	if tested == 0 {
		return endpointrisk.BASReadinessInput{}
	}
	return endpointrisk.BASReadinessInput{
		TechniquesTested: len(techSeen),
		PassRate:         float64(passed) / float64(tested) * 100,
		LastExecutedAt:   lastAt,
		Collected:        true,
	}
}
```

- [ ] **Step 2: Write `endpointrisk_aggregations_test.go`**

```go
package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestBasReadinessInput_ComputesPassRateAndTechCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-a1', 'ER-HOST-1')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-run-1', 'er-scn-1', 'ER Test Run', 'er-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"technique":{"id":"T1059","name":"PowerShell","tactic":"execution"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"},
				{"technique":{"id":"T1003","name":"OS Credential Dumping","tactic":"credential-access"},"result":"fail","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"},
				{"technique":{"id":"T1078","name":"Valid Accounts","tactic":"defense-evasion"},"result":"skipped","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(ctx, "er-a1")
		got := h.basReadinessInput(time.Now().UTC().Add(time.Hour), all)
		if !got.Collected {
			t.Fatal("expected Collected=true")
		}
		if got.PassRate != 50 {
			t.Errorf("PassRate = %.1f, want 50 (1 pass, 1 fail, skipped excluded)", got.PassRate)
		}
		if got.TechniquesTested != 2 {
			t.Errorf("TechniquesTested = %d, want 2", got.TechniquesTested)
		}
	})
}

func TestBasReadinessInput_NoResults_NotCollected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		all := h.aggregateAgentResults(context.Background(), "no-such-agent-ever")
		got := h.basReadinessInput(time.Now().UTC(), all)
		if got.Collected {
			t.Error("expected Collected=false for an agent with no results")
		}
	})
}

func TestFilterByAsOf_ExcludesFutureResults(t *testing.T) {
	now := time.Now().UTC()
	all := h_testAggregateAgentResultsFixture(now)
	got := filterByAsOf(all, now.Add(-24*time.Hour))
	if len(got) != 0 {
		t.Errorf("got %d results, want 0 (all fixture results are at 'now', cutoff is 24h before)", len(got))
	}
}
```

`h_testAggregateAgentResultsFixture` above is a placeholder — replace it with an inline slice literal instead of a fixture helper. Change `TestFilterByAsOf_ExcludesFutureResults` to:

```go
func TestFilterByAsOf_ExcludesFutureResults(t *testing.T) {
	now := time.Now().UTC()
	all := []models.SimulationResult{{ExecutedAt: now}}
	got := filterByAsOf(all, now.Add(-24*time.Hour))
	if len(got) != 0 {
		t.Errorf("got %d results, want 0 (fixture result is at 'now', cutoff is 24h before)", len(got))
	}
}
```

with `"github.com/audspect/bas/internal/models"` added to the import block.

- [ ] **Step 3: Run tests**

Run: `go test ./internal/api/... -run "BasReadinessInput|FilterByAsOf" -v` (from `orchestrator/`)
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_aggregations.go orchestrator/internal/api/endpointrisk_aggregations_test.go
git commit -m "feat(endpointrisk): add compliance and BAS readiness per-agent aggregations"
```

---

### Task 3: `GET /api/agents/{agentId}/risk` — per-agent detail endpoint

**Files:**
- Create: `orchestrator/internal/api/endpointrisk_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/endpointrisk_handlers_test.go`

**Interfaces:**
- Consumes: `h.buildAssetGraph(r) (*exposure.AssetGraph, error)` (existing, `exposure_handlers.go:19`), `ag.Summaries() []exposure.AssetSummary`, `ag.Profile(hostKey) (exposure.AssetExposureProfile, bool)` (existing — note: lookup here is by `AgentID`, matched via `Summaries()`'s `Asset.AgentID`/`Asset.HostKey` fields, not by calling `attackpath.NormalizeHostKey` directly), `h.aggregateAgentResults`, `h.complianceInput`, `h.basReadinessInput` (Task 2), `endpointrisk.ComputeHealth` (Task 1).
- Produces: `GET /api/agents/{agentId}/risk` → `endpointrisk.EndpointHealth` JSON.

- [ ] **Step 1: Write `endpointrisk_handlers.go`**

```go
package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/exposure"
)

// profileForAgent finds the AssetExposureProfile for agentId within an
// already-built AssetGraph by matching AssetIdentity.AgentID -- exposure's
// own exported surface is hostKey-keyed (Profile(hostKey)), but
// AssetIdentity.HostKey is present on every Summaries() row, so this needs
// no change to internal/exposure itself.
func profileForAgent(ag *exposure.AssetGraph, agentID string) (exposure.AssetExposureProfile, bool) {
	for _, s := range ag.Summaries() {
		if s.Asset.AgentID == agentID {
			return ag.Profile(s.Asset.HostKey)
		}
	}
	return exposure.AssetExposureProfile{}, false
}

// GetAgentRisk returns one agent's computed Health Score, categorized
// findings, attack-path chain, and action plan. Read-only (Viewer+).
// GET /api/agents/{agentId}/risk
func (h *Handler) GetAgentRisk(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile, ok := profileForAgent(ag, agentID)
	if !ok {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	allResults := h.aggregateAgentResults(r.Context(), agentID)
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)

	compliance := h.complianceInput(r.Context(), agentID, now, allResults)
	bas := h.basReadinessInput(now, allResults)
	pastCompliance := h.complianceInput(r.Context(), agentID, weekAgo, allResults)
	pastBAS := h.basReadinessInput(weekAgo, allResults)

	health := endpointrisk.ComputeHealth(agentID, profile, compliance, bas, pastCompliance, pastBAS)
	respond(w, health)
}
```

- [ ] **Step 2: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/controlhealth/summary", h.GetControlHealthSummary)
```

Add immediately after it:

```go
		r.Get("/api/controlhealth/summary", h.GetControlHealthSummary)
		r.Get("/api/agents/{agentId}/risk", h.GetAgentRisk)
```

- [ ] **Step 3: Register the RBAC drift matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/controlhealth/summary", tierAny, ""},
```

Add immediately after it:

```go
	{http.MethodGet, "/api/controlhealth/summary", tierAny, ""},
	{http.MethodGet, "/api/agents/{agentId}/risk", tierAny, ""},
```

- [ ] **Step 4: Write `endpointrisk_handlers_test.go`**

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetAgentRisk_UnknownAgent404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "no-such-agent-er")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetAgentRisk_KnownAgent_ReturnsAllCategories(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h2-a1', 'ER-H2-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-h2-run', 'er-h2-scn', 'ER H2 Run', 'er-h2-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-h2-a1")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got endpointrisk.EndpointHealth
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got.Categories) != 9 {
			t.Errorf("got %d categories, want 9 (5 collected + 4 not-yet-collected)", len(got.Categories))
		}
	})
}
```

Check that `withURLParam` (used above) already exists in this package (it's referenced in `report_nil_engine_test.go`) before writing this step — reuse it as-is; do not redefine it.

- [ ] **Step 5: Run tests**

Run: `go build ./...` (from `orchestrator/`)
Expected: clean build.

Run: `go test ./internal/api/... -run "GetAgentRisk|TestRBACMatrix_NoDrift" -v` (from `orchestrator/`)
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_handlers.go orchestrator/internal/api/endpointrisk_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(endpointrisk): add GET /api/agents/{agentId}/risk"
```

---

### Task 4: `GET /api/agents/risk-summary` — fleet list endpoint

**Files:**
- Modify: `orchestrator/internal/api/endpointrisk_handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Modify: `orchestrator/internal/api/endpointrisk_handlers_test.go`

**Interfaces:**
- Consumes: everything Task 3 produces, plus `ag.Summaries()` (existing).
- Produces: `GET /api/agents/risk-summary` → `{"agents": []AgentRiskRow}` where `AgentRiskRow{AgentID, Hostname, HealthScore, CriticalityRisk, Trend, TopDeficitCategory string, OpenFindingsCount int}`.

- [ ] **Step 1: Add the fleet-list handler to `endpointrisk_handlers.go`**

Find (search for the end of `GetAgentRisk`'s closing brace, i.e. the last line of that function):

```go
	health := endpointrisk.ComputeHealth(agentID, profile, compliance, bas, pastCompliance, pastBAS)
	respond(w, health)
}
```

Add immediately after it:

```go

// AgentRiskRow is the fleet-list projection -- one row per managed agent,
// enough to sort/filter by before drilling into GetAgentRisk's full detail.
type AgentRiskRow struct {
	AgentID            string `json:"agentId"`
	Hostname           string `json:"hostname"`
	HealthScore        int    `json:"healthScore"`
	CriticalityRisk    int    `json:"criticalityRisk"`
	Trend              string `json:"trend"`
	TopDeficitCategory string `json:"topDeficitCategory,omitempty"`
	OpenFindingsCount  int    `json:"openFindingsCount"`
}

// GetAgentRiskSummary returns every managed agent's Health Score for the
// fleet-wide "Risk & Remediation" tab. Read-only (Viewer+).
// GET /api/agents/risk-summary
func (h *Handler) GetAgentRiskSummary(w http.ResponseWriter, r *http.Request) {
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)

	var out []AgentRiskRow
	for _, s := range ag.Summaries() {
		if s.Asset.AgentID == "" {
			continue // exposure includes non-agent graph nodes too -- this tab is agent-scoped
		}
		profile, ok := ag.Profile(s.Asset.HostKey)
		if !ok {
			continue
		}
		allResults := h.aggregateAgentResults(r.Context(), s.Asset.AgentID)
		compliance := h.complianceInput(r.Context(), s.Asset.AgentID, now, allResults)
		bas := h.basReadinessInput(now, allResults)
		pastCompliance := h.complianceInput(r.Context(), s.Asset.AgentID, weekAgo, allResults)
		pastBAS := h.basReadinessInput(weekAgo, allResults)
		health := endpointrisk.ComputeHealth(s.Asset.AgentID, profile, compliance, bas, pastCompliance, pastBAS)

		row := AgentRiskRow{
			AgentID: s.Asset.AgentID, Hostname: s.Asset.Label,
			HealthScore: health.HealthScore, CriticalityRisk: health.CriticalityRisk, Trend: health.Trend,
		}
		if len(health.ActionPlan) > 0 {
			row.TopDeficitCategory = health.ActionPlan[0].CategoryName
		}
		for _, c := range health.Categories {
			row.OpenFindingsCount += len(c.Findings)
		}
		out = append(out, row)
	}
	respond(w, map[string]any{"agents": out})
}
```

- [ ] **Step 2: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/agents/{agentId}/risk", h.GetAgentRisk)
```

Add immediately after it:

```go
		r.Get("/api/agents/{agentId}/risk", h.GetAgentRisk)
		r.Get("/api/agents/risk-summary", h.GetAgentRiskSummary)
```

- [ ] **Step 3: Register the RBAC drift matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/agents/{agentId}/risk", tierAny, ""},
```

Add immediately after it:

```go
	{http.MethodGet, "/api/agents/{agentId}/risk", tierAny, ""},
	{http.MethodGet, "/api/agents/risk-summary", tierAny, ""},
```

- [ ] **Step 4: Add a fleet-list test to `endpointrisk_handlers_test.go`**

Find the end of `TestGetAgentRisk_KnownAgent_ReturnsAllCategories` (its closing `}`) and add after it:

```go

func TestGetAgentRiskSummary_IncludesKnownAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h4-a1', 'ER-H4-HOST')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/agents/risk-summary", nil)
		w := httptest.NewRecorder()
		h.GetAgentRiskSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			Agents []AgentRiskRow `json:"agents"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		found := false
		for _, a := range body.Agents {
			if a.AgentID == "er-h4-a1" {
				found = true
			}
		}
		if !found {
			t.Error("expected er-h4-a1 in the fleet risk summary")
		}
	})
}
```

- [ ] **Step 5: Run tests**

Run: `go build ./...` (from `orchestrator/`)
Expected: clean build.

Run: `go test ./internal/api/... -run "GetAgentRisk|TestRBACMatrix_NoDrift" -v` (from `orchestrator/`)
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/endpointrisk_handlers.go orchestrator/internal/api/endpointrisk_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(endpointrisk): add GET /api/agents/risk-summary fleet list"
```

---

### Task 5: Frontend — Agents section sub-tab switcher + fleet list

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET /api/agents/risk-summary` (Task 4), existing `apicall`, `x()`, `showToast` helpers.
- Produces: `setAgentsView(view)` (global, mirrors `setDashView`), `loadAgentRiskSummary()`, `renderAgentRiskSummary(rows)` — the fleet table renderer.

- [ ] **Step 1: Add the sub-tab buttons and a second view container inside `#tab-agents`**

Find (search for `<div id="tab-agents" style="display:none">` through the header block ending at the KPI row):

```html
      <div id="tab-agents" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Simulation agents <span id="agent-cnt" class="cnt">0</span></h1>
            <div style="font-size:0.8rem;color:var(--muted)">Lightweight collectors across your environment — they execute safe emulations locally and stream telemetry back.</div>
          </div>
          <div style="display:flex;gap:0.5rem;flex-shrink:0">
            <button class="btn btn-outline btn-sm" onclick="loadAgents()">Refresh</button>
            <button class="btn btn-primary btn-sm" onclick="showAgentDownload()">&#8595; Deploy agent</button>
          </div>
        </div>
        <div class="kpi-row" id="agent-tiles"></div>
```

Replace with:

```html
      <div id="tab-agents" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Simulation agents <span id="agent-cnt" class="cnt">0</span></h1>
            <div style="font-size:0.8rem;color:var(--muted)">Lightweight collectors across your environment — they execute safe emulations locally and stream telemetry back.</div>
          </div>
          <div style="display:flex;gap:0.5rem;flex-shrink:0">
            <button class="btn btn-outline btn-sm" onclick="loadAgents()">Refresh</button>
            <button class="btn btn-primary btn-sm" onclick="showAgentDownload()">&#8595; Deploy agent</button>
          </div>
        </div>
        <div style="display:flex;gap:0.5rem;margin-bottom:1rem">
          <button type="button" class="dash-view-btn active" data-agents-view="operational" onclick="setAgentsView('operational')">Operational</button>
          <button type="button" class="dash-view-btn" data-agents-view="risk" onclick="setAgentsView('risk')">Risk &amp; Remediation</button>
        </div>
        <div id="agents-view-operational">
        <div class="kpi-row" id="agent-tiles"></div>
```

- [ ] **Step 2: Close the new `#agents-view-operational` wrapper and add the `#agents-view-risk` container**

Find (search for the end of the Agent Download section — the closing of `#tab-agents`; locate the literal text `<!-- Connection Config (admin only) -->` as the anchor immediately after the agents table, since that section stays inside the Operational view):

```html
        </div>

        <!-- Connection Config (admin only) -->
        <div id="conn-cfg-wrap" style="display:none; margin-top:2rem">
```

Replace with:

```html
        </div>
        </div>
        <div id="agents-view-risk" style="display:none">
          <div class="kpi-row" id="agent-risk-tiles" style="margin-bottom:1rem"></div>
          <div class="tbl-wrap" style="overflow-x:auto">
            <table style="min-width:700px">
              <thead><tr>
                <th style="min-width:160px">Host</th><th>Health Score</th><th>Criticality</th><th>Trend</th><th>Top Issue</th><th>Open Findings</th><th style="min-width:110px">Actions</th>
              </tr></thead>
              <tbody id="agent-risk-body">
                <tr><td colspan="7" class="empty">Loading…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Connection Config (admin only) -->
        <div id="conn-cfg-wrap" style="display:none; margin-top:2rem">
```

- [ ] **Step 3: Add `setAgentsView`, `loadAgentRiskSummary`, and `renderAgentRiskSummary`**

Find (search for `function setDashView(view) {` through its closing brace):

```javascript
function setDashView(view) {
  DASH_VIEW = view;
  document.getElementById('dash-view-operational').style.display = view === 'operational' ? '' : 'none';
  document.getElementById('dash-view-executive').style.display = view === 'executive' ? '' : 'none';
  document.querySelectorAll('.dash-view-btn').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-view') === view);
  });
  try { localStorage.setItem('bas_last_dash_view', view); } catch (e) {}
  if (view === 'operational') { loadDashboard(); startDashCampPoll(); }
  else { stopDashCampPoll(); loadExecDashboard(); }
}
```

Add immediately after it:

```javascript
function setAgentsView(view) {
  document.getElementById('agents-view-operational').style.display = view === 'operational' ? '' : 'none';
  document.getElementById('agents-view-risk').style.display = view === 'risk' ? '' : 'none';
  document.querySelectorAll('[data-agents-view]').forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-agents-view') === view);
  });
  if (view === 'risk') loadAgentRiskSummary();
}
function loadAgentRiskSummary() {
  var tb = document.getElementById('agent-risk-body');
  if (tb) tb.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
  apicall('/api/agents/risk-summary').then(function(d) {
    renderAgentRiskSummary((d && d.agents) || []);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function _riskScoreColor(score) {
  return score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';
}
function _riskTrendBadge(trend) {
  if (trend === 'Improving') return '<span style="color:var(--success)">&#8593; Improving</span>';
  if (trend === 'Declining') return '<span style="color:var(--danger)">&#8595; Declining</span>';
  if (trend === 'Stable') return '<span style="color:var(--muted)">&#8594; Stable</span>';
  return '<span style="color:var(--muted)">—</span>';
}
function renderAgentRiskSummary(rows) {
  var tb = document.getElementById('agent-risk-body');
  if (!tb) return;
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">No agents to show.</td></tr>';
    return;
  }
  rows.sort(function(a, b) { return a.healthScore - b.healthScore; });
  tb.innerHTML = rows.map(function(a) {
    return '<tr>' +
      '<td>' + x(a.hostname || a.agentId) + '</td>' +
      '<td style="color:' + _riskScoreColor(a.healthScore) + ';font-weight:700">' + a.healthScore + '</td>' +
      '<td>' + (a.criticalityRisk || 0) + '</td>' +
      '<td>' + _riskTrendBadge(a.trend) + '</td>' +
      '<td>' + x(a.topDeficitCategory || '—') + '</td>' +
      '<td>' + (a.openFindingsCount || 0) + '</td>' +
      '<td><button class="btn btn-outline btn-sm" onclick="openAgentDetail(\'' + x(a.agentId) + '\');setTimeout(function(){showAgentTab(\'risk\')},50)">View</button></td>' +
      '</tr>';
  }).join('');
}
```

- [ ] **Step 4: Verify syntax**

```bash
START=$(grep -n '^<script>$' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "$((START+1)),$((END-1))p" orchestrator/wwwroot/index.html > /tmp/er_check.js
node --check /tmp/er_check.js
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(endpointrisk-ui): add Risk & Remediation fleet tab to Agents section"
```

---

### Task 6: Frontend — per-agent drawer "risk" tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `GET /api/agents/{agentId}/risk` (Task 3), `apNodePill(name, isTarget)`, `apArrow(kind)` (existing, from Attack Path Validation — `wwwroot/index.html`), `_riskScoreColor`, `_riskTrendBadge` (Task 5).
- Produces: `showAgentTab('risk')` support (extends the existing `showAgentTab` dispatcher, confirmed at `wwwroot/index.html:3534` — panels are `#agt-tab-<name>`, not `#agt-panel-<name>`; the tab bar is a plain list of `<button>`s at `#agt-tab-bar`, index-matched against two hardcoded array literals inside `showAgentTab`, both of which must be updated), `loadAgtRisk(agentId)`, `renderAgtRisk(health)`.

- [ ] **Step 1: Add `'risk'` to `showAgentTab`'s two array literals and its dispatch branch**

Find (search for `function showAgentTab(tab) {` through its closing brace — confirmed exact text below):

```javascript
function showAgentTab(tab) {
  ['overview','scenarios','logs','health','attackpath'].forEach(function(t) {
    document.getElementById('agt-tab-' + t).style.display = (t === tab ? '' : 'none');
  });
  document.querySelectorAll('#agt-tab-bar .tab-btn').forEach(function(btn, i) {
    var tabs = ['overview','scenarios','logs','health','attackpath'];
    btn.classList.toggle('active', tabs[i] === tab);
  });
  if (_agtLogRefresh) { clearInterval(_agtLogRefresh); _agtLogRefresh = null; }
  var id = _agtDetailId;
  if (!id) return;
  if (tab === 'overview')   loadAgtOverview(id);
  if (tab === 'scenarios')  loadAgtScenarios(id);
  if (tab === 'logs')       { _agtLogTier = 'operational'; loadAgtLogs(id, _agtLogTier); _agtLogRefresh = setInterval(function(){ loadAgtLogs(_agtDetailId, _agtLogTier); }, 15000); }
  if (tab === 'health')     loadAgtHealth(id);
  if (tab === 'attackpath') loadAgtAttackPath(id);
}
```

Replace with:

```javascript
function showAgentTab(tab) {
  ['overview','scenarios','logs','health','attackpath','risk'].forEach(function(t) {
    document.getElementById('agt-tab-' + t).style.display = (t === tab ? '' : 'none');
  });
  document.querySelectorAll('#agt-tab-bar .tab-btn').forEach(function(btn, i) {
    var tabs = ['overview','scenarios','logs','health','attackpath','risk'];
    btn.classList.toggle('active', tabs[i] === tab);
  });
  if (_agtLogRefresh) { clearInterval(_agtLogRefresh); _agtLogRefresh = null; }
  var id = _agtDetailId;
  if (!id) return;
  if (tab === 'overview')   loadAgtOverview(id);
  if (tab === 'scenarios')  loadAgtScenarios(id);
  if (tab === 'logs')       { _agtLogTier = 'operational'; loadAgtLogs(id, _agtLogTier); _agtLogRefresh = setInterval(function(){ loadAgtLogs(_agtDetailId, _agtLogTier); }, 15000); }
  if (tab === 'health')     loadAgtHealth(id);
  if (tab === 'attackpath') loadAgtAttackPath(id);
  if (tab === 'risk')       loadAgtRisk(id);
}
```

The `tabs[i]` index-matching means the new "Risk" button (Step 2) must be the 6th button in `#agt-tab-bar`, matching `'risk'` being the 6th array element here — both appended at the end, so this holds.

- [ ] **Step 2: Add the "Risk" tab button and its panel `<div>`**

Find (search for `<div class="tab-bar" id="agt-tab-bar">` through the matching `</div>` of `.drawer-body` — confirmed exact text below):

```html
    <div class="tab-bar" id="agt-tab-bar">
      <button class="tab-btn active" onclick="showAgentTab('overview')">Overview</button>
      <button class="tab-btn" onclick="showAgentTab('scenarios')">Scenarios</button>
      <button class="tab-btn" onclick="showAgentTab('logs')">Logs</button>
      <button class="tab-btn" onclick="showAgentTab('health')">Health</button>
      <button class="tab-btn" onclick="showAgentTab('attackpath')">Attack Path</button>
    </div>
    <div class="drawer-body" style="overflow-y:auto">
      <div id="agt-tab-overview" class="tab-pane"></div>
      <div id="agt-tab-scenarios" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-logs" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-health" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-attackpath" class="tab-pane" style="display:none"></div>
    </div>
```

Replace with:

```html
    <div class="tab-bar" id="agt-tab-bar">
      <button class="tab-btn active" onclick="showAgentTab('overview')">Overview</button>
      <button class="tab-btn" onclick="showAgentTab('scenarios')">Scenarios</button>
      <button class="tab-btn" onclick="showAgentTab('logs')">Logs</button>
      <button class="tab-btn" onclick="showAgentTab('health')">Health</button>
      <button class="tab-btn" onclick="showAgentTab('attackpath')">Attack Path</button>
      <button class="tab-btn" onclick="showAgentTab('risk')">Risk</button>
    </div>
    <div class="drawer-body" style="overflow-y:auto">
      <div id="agt-tab-overview" class="tab-pane"></div>
      <div id="agt-tab-scenarios" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-logs" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-health" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-attackpath" class="tab-pane" style="display:none"></div>
      <div id="agt-tab-risk" class="tab-pane" style="display:none"></div>
    </div>
```

- [ ] **Step 3: Write `loadAgtRisk` and `renderAgtRisk`**

Find (search for `function loadAgtHealth(agentId) {` through its closing brace) and add the following new functions immediately after it:

```javascript
function loadAgtRisk(agentId) {
  var panel = document.getElementById('agt-tab-risk');
  if (panel) panel.innerHTML = '<div class="empty" style="padding:2rem">Loading…</div>';
  apicall('/api/agents/' + encodeURIComponent(agentId) + '/risk').then(function(d) {
    renderAgtRisk(d);
  }).catch(function(e) { if (panel) panel.innerHTML = '<div class="empty">' + x(e.message) + '</div>'; });
}
function _riskCategoryCard(c) {
  if (!c.collected) {
    return '<div class="dash-panel" style="margin-bottom:0.75rem;opacity:0.6"><div class="dash-panel-body" style="padding:0.85rem">' +
      '<div style="font-weight:700;color:var(--text)">' + x(c.name) + '</div>' +
      '<div class="tiny muted">Not yet collected</div></div></div>';
  }
  var findingsHtml = (c.findings || []).map(function(f) {
    return '<li><strong>' + x(f.title) + '</strong> (' + x(f.severity) + ') — ' + x(f.risk) +
      (f.affectedStandard ? '<div class="tiny muted">Affected standard: ' + x(f.affectedStandard) + '</div>' : '') +
      '<div class="tiny" style="color:var(--accent)">Remediation: ' + x(f.remediation) + '</div></li>';
  }).join('');
  return '<div class="dash-panel" style="margin-bottom:0.75rem"><div class="dash-panel-body" style="padding:0.85rem">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem">' +
    '<div style="font-weight:700;color:var(--text)">' + x(c.name) + '</div>' +
    '<div style="color:' + _riskScoreColor(c.score) + ';font-weight:700">' + c.score + '</div></div>' +
    (findingsHtml ? '<ul style="margin:0;padding-left:1.1rem;color:var(--muted);display:flex;flex-direction:column;gap:0.3rem">' + findingsHtml + '</ul>' : '<div class="tiny muted">No open findings.</div>') +
    '</div></div>';
}
function renderAgtRisk(health) {
  var panel = document.getElementById('agt-tab-risk');
  if (!panel) return;
  var h = '<div class="kpi-row" style="margin-bottom:1rem">' +
    '<div class="kpi-card"><div class="kpi-label">Health Score</div><div class="kpi-value" style="color:' + _riskScoreColor(health.healthScore) + '">' + health.healthScore + '</div><div class="tiny muted">' + _riskTrendBadge(health.trend) + '</div></div>' +
    '<div class="kpi-card"><div class="kpi-label">Criticality</div><div class="kpi-value">' + health.criticalityRisk + '</div><div class="tiny muted">sort/priority signal, not part of Health Score</div></div>' +
    '</div>';

  if ((health.actionPlan || []).length) {
    h += '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:0.85rem">' +
      '<div style="font-weight:700;color:var(--text);margin-bottom:0.5rem">Recommended Action Plan</div>' +
      '<ol style="margin:0;padding-left:1.1rem;display:flex;flex-direction:column;gap:0.4rem">' +
      health.actionPlan.map(function(a) {
        return '<li><strong>' + x(a.categoryName) + '</strong> (−' + a.deficit + ' pts) — ' + x(a.finding.title) + '<div class="tiny" style="color:var(--accent)">' + x(a.finding.remediation) + '</div></li>';
      }).join('') + '</ol></div></div>';
  }

  if ((health.attackPathChain || []).length) {
    h += '<div class="dash-panel" style="margin-bottom:1rem"><div class="dash-panel-body" style="padding:0.85rem">' +
      '<div style="font-weight:700;color:var(--text);margin-bottom:0.5rem">Attack Path Chain</div>' +
      '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:0.25rem">' + apNodePill(health.attackPathChain[0].from);
    for (var i = 0; i < health.attackPathChain.length; i++) {
      h += apArrow(health.attackPathChain[i].kind) + apNodePill(health.attackPathChain[i].to, i === health.attackPathChain.length - 1);
    }
    h += '</div></div></div>';
  }

  h += (health.categories || []).map(_riskCategoryCard).join('');
  panel.innerHTML = h;
}
```

- [ ] **Step 4: Verify syntax**

```bash
START=$(grep -n '^<script>$' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
END=$(grep -n '</script>' orchestrator/wwwroot/index.html | tail -1 | cut -d: -f1)
sed -n "$((START+1)),$((END-1))p" orchestrator/wwwroot/index.html > /tmp/er_check2.js
node --check /tmp/er_check2.js
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(endpointrisk-ui): add per-agent Risk drill-down tab to the detail drawer"
```

---

## Self-Review Notes

- **Spec coverage:** §1 architecture (Tasks 1-4) · §2 Health Score formula (Task 1) · §3 categories incl. "Not yet collected" placeholders (Task 1) · §4 attack-path chain (Task 1, Task 6) · §5 action plan ranked by deficit (Task 1, Task 6) · §6 partial trend, Compliance+BAS only (Task 1, Task 2) · §7 fleet tab + drill-down UI (Task 5, Task 6) · §8 testing conventions (every task). All spec sections have a task.
- **Placeholder scan:** Task 1 Step 4 and Task 2 Step 2 each contain one deliberately-flagged placeholder helper (`attackpathEdge`, `h_testAggregateAgentResultsFixture`) that Step 4/the following step explicitly instructs the implementer to delete and replace with real code shown immediately after — these are call-outs of a genuine two-draft need (the real type name wasn't confirmed until later in this same step), not unresolved TBDs; both replacements are fully written out inline, not described abstractly. Task 6 was rewritten after directly reading `wwwroot/index.html:3534` (`showAgentTab`) and `:3924` (`#agt-tab-bar`) — the initial draft guessed a `showAgtTab`/`agt-panel-<name>` naming convention that turned out to be wrong (real names are `showAgentTab`/`agt-tab-<name>`, and the tab bar is two hardcoded array literals index-matched against a plain button list, not a dynamic pattern); Task 6's steps now quote and edit that exact real markup.
- **Type consistency:** `ComplianceInput`/`BASReadinessInput` (Task 1) match the exact field names Task 2's aggregations populate and Task 3/4's handlers pass through. `EndpointHealth`/`CategoryScore`/`ActionItem`/`AttackPathStep` (Task 1) match the JSON field names Task 5/6's frontend reads (`healthScore`, `criticalityRisk`, `categories[].collected/score/findings`, `actionPlan[].categoryName/deficit/finding`, `attackPathChain[].from/to/kind`, `trend`). `AgentRiskRow` (Task 4) matches the fields Task 5's `renderAgentRiskSummary` reads (`hostname`, `healthScore`, `criticalityRisk`, `trend`, `topDeficitCategory`, `openFindingsCount`, `agentId`).
