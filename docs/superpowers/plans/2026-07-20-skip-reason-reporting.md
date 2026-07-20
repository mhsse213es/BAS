# SkipReason Reporting Breakdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every `Result=Skipped` step carries a `SkipReason` bucketed into Policy / Content / Platform, and reports show a dedicated Execution Summary breaking those out, with an executive-narrative sentence when policy skips are present.

**Architecture:** A small, fully-enumerable classifier (`classifySkipReason`) maps the free-text of self-authored `"SKIP:"` marker messages to one of two new `models.SkipReason*` constants, wired into `scenario.Interpret` at the one point that already extracts that text. The reporting layer aggregates `SkipReason` across a report's results into a new `SkipBreakdown` struct (mirroring the existing `PrivilegeSummary` pattern), wired into the single shared `deriveExecutive` helper that already runs for every report type. A new HTML section renders it; the executive-conclusion sentence gets one more line for policy skips only.

**Tech Stack:** Go, `internal/models`, `internal/scenario`, `internal/reporting`.

## Global Constraints

- **Three report-facing buckets:** Policy (`SkipReasonPolicyPrivilege`, already exists) / Content (`SkipReasonMissingContent`, new) / Platform (`SkipReasonPlatformUnavailable`, new — covers OS mismatch, Caldera not configured, Caldera ability not found, and malformed steps with no command). Do not name anything "Prerequisite" — that word is already `ErrMissingPrerequisite`, a distinct **ERROR** reason (a different outcome class), and reusing it here would collide with existing report vocabulary.
- **Classification happens at `Interpret` time**, not as a backfill. Historical `SimulationResult` rows already persisted before this change will show as Platform (the empty/unrecognized-reason fallback) in reports generated after this change — they are not retroactively reclassified.
- **No changes to `ComputeScore` / `models.Score`.** Skips are already correctly excluded from scoring; this plan only adds descriptive breakdown.
- **No changes to the existing "Simulation Reliability" table** (`html.go:1257-1265`). It answers a different question (data confidence) than the new Execution Summary (what happened and why).
- **The executive narrative gets a new sentence only for Policy skips.** Content/Platform skips appear in the Execution Summary table but get no narrative sentence — they're environment facts, not an operator decision worth narrating.
- **The policy-skip marker text (`"SKIP: requires %s privilege, execution policy caps at %s"`, `handlers.go:901`) is not one of the two classified shapes.** It's fine for it to classify as unrecognized inside `Interpret` — `synthesizePolicySkipResult` overwrites `SkipReason` explicitly on the very next line (`handlers.go:904`) regardless. Do not add special-case handling for it in `classifySkipReason`.
- Run all `go` commands from `orchestrator/`.

---

### Task 1: SkipReason classification

**Files:**
- Modify: `orchestrator/internal/models/schema.go` (new constants, comment fix)
- Modify: `orchestrator/internal/scenario/outcome.go` (new `classifySkipReason` function)
- Modify: `orchestrator/internal/scenario/interpreter.go` (wire into `Interpret`)
- Test: `orchestrator/internal/scenario/interpret_test.go` (existing file)

**Interfaces:**
- Produces: `models.SkipReasonMissingContent = "missing-content"`, `models.SkipReasonPlatformUnavailable = "platform-unavailable"` (alongside the existing `models.SkipReasonPolicyPrivilege`). `scenario.classifySkipReason(detail string) string`. `models.SimulationResult.SkipReason` (existing field) now populated for every skip, not just policy ones.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/scenario/interpret_test.go` (the file already imports `"github.com/audspect/bas/internal/models"`):

```go
func TestClassifySkipReason(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		want   string
	}{
		{"ART missing payload", "requires external payload(s) not available on server: gsecdump.exe — drop them in ART_PAYLOAD_DIR to enable this test", models.SkipReasonMissingContent},
		{"ART not in local store with OS", "ART technique T1003 not in local store for windows", models.SkipReasonPlatformUnavailable},
		{"ART not in local store no OS", "ART technique T1003 not in local store", models.SkipReasonPlatformUnavailable},
		{"malformed step no command", "No command defined for step 'my-step'", models.SkipReasonPlatformUnavailable},
		{"caldera not configured", "Caldera not configured — set CALDERA_URL to enable ability abc123", models.SkipReasonPlatformUnavailable},
		{"caldera ability not found", "Caldera ability abc123 not found", models.SkipReasonPlatformUnavailable},
		{"unrecognized text", "some future skip reason nobody has written yet", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifySkipReason(c.detail); got != c.want {
				t.Errorf("classifySkipReason(%q) = %q, want %q", c.detail, got, c.want)
			}
		})
	}
}

func TestInterpret_SetsSkipReason(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"ART missing payload", "SKIP: requires external payload(s) not available on server: gsecdump.exe", models.SkipReasonMissingContent},
		{"ART not in local store", "SKIP: ART technique T1003 not in local store for windows", models.SkipReasonPlatformUnavailable},
		{"unmatched skip text (e.g. policy marker) leaves SkipReason empty", "SKIP: requires admin privilege, execution policy caps at user", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			step := Step{TechniqueID: "T1003", Name: "test", Framework: "art"}
			res := Interpret(step, ExecResult{ExitCode: 0, Stdout: c.stdout})
			if res.Result != models.ResultSkipped {
				t.Fatalf("Result = %q, want skipped", res.Result)
			}
			if res.SkipReason != c.want {
				t.Errorf("SkipReason = %q, want %q", res.SkipReason, c.want)
			}
		})
	}
	// A non-skip result must never carry a SkipReason.
	passRes := Interpret(Step{TechniqueID: "T1059", Framework: "art"}, ExecResult{ExitCode: 0, Stdout: "the operation completed successfully"})
	if passRes.SkipReason != "" {
		t.Errorf("non-skip SkipReason = %q, want empty", passRes.SkipReason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/... -run 'TestClassifySkipReason|TestInterpret_SetsSkipReason' -v`
Expected: FAIL — `undefined: classifySkipReason` (compile error). `TestInterpret_SetsSkipReason` will also fail once it compiles, since `SkipReason` is never set yet.

- [ ] **Step 3: Add the new constants and fix the now-outdated comment**

In `orchestrator/internal/models/schema.go`, the current field:

```go
	// SkipReason distinguishes WHY a Result=ResultSkipped entry was skipped,
	// matching the lightweight plain-string classification style already used
	// by Framework/DetectionVerdict/CleanupVerdict/ExecutedAs on this struct.
	// Empty for all pre-existing skip causes (missing payload, technique not in
	// local store, etc.) — only set for skips this platform itself decided to
	// make, not ones discovered by parsing agent output.
	SkipReason string `json:"skipReason,omitempty"`
```

becomes:

```go
	// SkipReason distinguishes WHY a Result=ResultSkipped entry was skipped,
	// matching the lightweight plain-string classification style already used
	// by Framework/DetectionVerdict/CleanupVerdict/ExecutedAs on this struct.
	// Set for every skip: either synthesized directly (policy-privilege) or
	// classified from the "SKIP:" marker text at Interpret time (see
	// scenario.classifySkipReason) — a self-authored, fully-enumerable
	// vocabulary, not a heuristic guess at unpredictable agent output.
	SkipReason string `json:"skipReason,omitempty"`
```

The current constant block:

```go
// SkipReasonPolicyPrivilege marks a SimulationResult synthesized server-side
// because a step's RequiresPriv exceeded the run's MaxPrivilege execution
// policy — the step was never dispatched to the agent at all.
const SkipReasonPolicyPrivilege = "policy-privilege"
```

becomes:

```go
// SkipReasonPolicyPrivilege marks a SimulationResult synthesized server-side
// because a step's RequiresPriv exceeded the run's MaxPrivilege execution
// policy — the step was never dispatched to the agent at all.
const SkipReasonPolicyPrivilege = "policy-privilege"

// SkipReasonMissingContent marks a skip caused by content unavailable on the
// server — e.g. an ART atomic test's required external payload was never
// staged in ART_PAYLOAD_DIR.
const SkipReasonMissingContent = "missing-content"

// SkipReasonPlatformUnavailable marks a skip caused by an environment/tooling
// gap: the technique isn't available for the target OS, Caldera isn't
// configured, a referenced Caldera ability doesn't exist, or a step has no
// executable command at all.
const SkipReasonPlatformUnavailable = "platform-unavailable"
```

- [ ] **Step 4: Add `classifySkipReason` to `outcome.go`**

In `orchestrator/internal/scenario/outcome.go`, the current import block:

```go
package scenario

import (
	"fmt"
	"strings"
)
```

becomes:

```go
package scenario

import (
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/models"
)
```

Add this function immediately after the closing `}` of `classifyExecutionError` (before `ranToCompletion`):

```go

// classifySkipReason maps the free-text detail of a "SKIP:" marker (already
// stripped of its prefix) to a models.SkipReason* bucket. Every message this
// matches against is authored by our own server code (art.go/builder.go),
// never third-party program output, so this is a small, fully-enumerable
// vocabulary — not a fragile heuristic. Returns "" for unrecognized text
// (the reporting layer's bucket aggregation falls that back to Platform).
func classifySkipReason(detail string) string {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, "not available on server"):
		return models.SkipReasonMissingContent
	case strings.Contains(lower, "not in local store"),
		strings.Contains(lower, "no command defined"),
		strings.Contains(lower, "caldera not configured"),
		strings.Contains(lower, "caldera ability") && strings.Contains(lower, "not found"):
		return models.SkipReasonPlatformUnavailable
	}
	return ""
}
```

- [ ] **Step 5: Wire it into `Interpret`**

In `orchestrator/internal/scenario/interpreter.go`, the current block:

```go
	var checkResult models.CheckResult
	var details string

	switch framework {
	case "art":
		checkResult, details = interpretART(result, combined)
	case "caldera":
		checkResult, details = interpretCaldera(result, combined)
	default:
		checkResult, details = interpretCustom(result, combined)
	}

	return models.SimulationResult{
		ID: TaskID(step.TechniqueID, step.Name),
		Technique: models.AttackTechnique{
			ID:     techniqueID,
			Name:   techniqueName,
			Tactic: tactic,
		},
		Result:         checkResult,
		Severity:       sev,
		ThreatImpact:   models.ThreatImpact(tactic, techniqueID, techniqueName),
		Details:        details,
		Remediation:    models.Remediation(checkResult, tactic, techniqueID, techniqueName),
```

becomes:

```go
	var checkResult models.CheckResult
	var details string

	switch framework {
	case "art":
		checkResult, details = interpretART(result, combined)
	case "caldera":
		checkResult, details = interpretCaldera(result, combined)
	default:
		checkResult, details = interpretCustom(result, combined)
	}

	var skipReason string
	if checkResult == models.ResultSkipped {
		skipReason = classifySkipReason(details)
	}

	return models.SimulationResult{
		ID: TaskID(step.TechniqueID, step.Name),
		Technique: models.AttackTechnique{
			ID:     techniqueID,
			Name:   techniqueName,
			Tactic: tactic,
		},
		Result:         checkResult,
		Severity:       sev,
		ThreatImpact:   models.ThreatImpact(tactic, techniqueID, techniqueName),
		Details:        details,
		SkipReason:     skipReason,
		Remediation:    models.Remediation(checkResult, tactic, techniqueID, techniqueName),
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/... -run 'TestClassifySkipReason|TestInterpret_SetsSkipReason' -v`
Expected: all PASS.

- [ ] **Step 7: Run the full `internal/scenario` suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/scenario/... -v 2>&1 | tail -40`
Expected: all PASS, including every pre-existing `TestInterpretART*`/`TestInterpretCustom*` test (they call `interpretART`/`interpretCustom` directly, whose signatures are unchanged — only `Interpret` itself, which none of them call, gained the new field).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/models/schema.go orchestrator/internal/scenario/outcome.go orchestrator/internal/scenario/interpreter.go orchestrator/internal/scenario/interpret_test.go
git commit -m "feat(reporting): classify skip causes into Policy/Content/Platform SkipReason buckets"
git push
```

---

### Task 2: Reporting `SkipBreakdown` + executive narrative

**Files:**
- Modify: `orchestrator/internal/reporting/engine.go` (`SkipBreakdown` struct, `FullReport.SkipBreakdown` field, `buildSkipBreakdown`)
- Modify: `orchestrator/internal/reporting/insights.go` (`deriveExecutive`, `buildExecutiveConclusion`)
- Test: `orchestrator/internal/reporting/engine_test.go` (existing file)
- Test: `orchestrator/internal/reporting/insights_test.go` (existing file)

**Interfaces:**
- Consumes: `models.SimulationResult.SkipReason`, `models.SkipReasonPolicyPrivilege`/`SkipReasonMissingContent`/`SkipReasonPlatformUnavailable` (Task 1).
- Produces: `reporting.SkipBreakdown{Policy, Content, Platform int}`. `reporting.buildSkipBreakdown(results []models.SimulationResult) SkipBreakdown`. `FullReport.SkipBreakdown SkipBreakdown`. `buildExecutiveConclusion` gains a 5th parameter `skip SkipBreakdown`.

**Why one shared wiring point, not three:** `PrivilegeSummary` (the established precedent for this kind of "derived from results, shown in the summary" field) is wired at three separate call sites, one per report-building function (`Build`, `BuildFromRun`, `BuildFromCampaign` — `engine.go` lines ~1291, ~1566, ~1753). But all three of those functions already call a single shared helper, `deriveExecutive(report *FullReport, results []models.SimulationResult, dets []DetectionTechnique)` (`insights.go:426`), right after setting `PrivilegeSummary`. `deriveExecutive` already receives `results` as a parameter and is the one place `buildExecutiveConclusion` is called from — so wiring `SkipBreakdown` there covers all three report types with one change, and keeps the breakdown available at the exact point the narrative sentence needs it.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/reporting/engine_test.go`:

```go
func TestBuildSkipBreakdown(t *testing.T) {
	results := []models.SimulationResult{
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonMissingContent},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonPlatformUnavailable},
		{Result: models.ResultSkipped, SkipReason: ""}, // unrecognized/legacy skip
		{Result: models.ResultPass},                    // not a skip — must not be counted
	}
	got := buildSkipBreakdown(results)
	want := SkipBreakdown{Policy: 2, Content: 1, Platform: 2}
	if got != want {
		t.Errorf("buildSkipBreakdown = %+v, want %+v", got, want)
	}
}
```

Add to `orchestrator/internal/reporting/insights_test.go` (the file already imports `"strings"`):

```go
func TestBuildExecutiveConclusion_PolicySkipSentence(t *testing.T) {
	s := ExecutiveSummary{PassedTechniques: 20, FailedTechniques: 6, PreventionScore: 76.9}
	withPolicy := buildExecutiveConclusion(s, Insights{}, DetectionSummary{}, nil, SkipBreakdown{Policy: 14})
	if !strings.Contains(withPolicy, "14 techniques requiring administrative privileges were intentionally excluded") {
		t.Errorf("conclusion = %q, want a policy-skip sentence naming 14", withPolicy)
	}

	withoutPolicy := buildExecutiveConclusion(s, Insights{}, DetectionSummary{}, nil, SkipBreakdown{Content: 3, Platform: 2})
	if strings.Contains(withoutPolicy, "intentionally excluded") {
		t.Errorf("conclusion = %q, want no policy sentence when Policy=0 (Content/Platform skips get no narrative)", withoutPolicy)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run 'TestBuildSkipBreakdown|TestBuildExecutiveConclusion_PolicySkipSentence' -v`
Expected: FAIL — compile errors (`undefined: SkipBreakdown`, `undefined: buildSkipBreakdown`, and `buildExecutiveConclusion` called with 5 args but declared with 4).

- [ ] **Step 3: Add `SkipBreakdown` struct, `FullReport` field, and `buildSkipBreakdown`**

In `orchestrator/internal/reporting/engine.go`, the current `FullReport` field:

```go
	// PrivilegeSummary counts steps by execution context across the TechniqueMatrix.
	// Populated alongside TechniqueMatrix so the summary page can show privilege coverage.
	PrivilegeSummary PrivilegeSummary `json:"privilegeSummary"`
}
```

becomes:

```go
	// PrivilegeSummary counts steps by execution context across the TechniqueMatrix.
	// Populated alongside TechniqueMatrix so the summary page can show privilege coverage.
	PrivilegeSummary PrivilegeSummary `json:"privilegeSummary"`
	// SkipBreakdown counts Result=Skipped entries by SkipReason. Populated by
	// deriveExecutive so a policy-constrained run reads as "compliant," not
	// "incomplete."
	SkipBreakdown SkipBreakdown `json:"skipBreakdown"`
}
```

The current end of `buildPrivilegeSummary`:

```go
	if ps.Legacy > 0 {
		ps.LegacyRate = ps.LegacyPrevented * 100 / ps.Legacy
	}
	return ps
}

// killChainAction renders a concise adversary-action label for a kill-chain node.
```

becomes:

```go
	if ps.Legacy > 0 {
		ps.LegacyRate = ps.LegacyPrevented * 100 / ps.Legacy
	}
	return ps
}

// SkipBreakdown counts Result=Skipped entries by SkipReason.
type SkipBreakdown struct {
	Policy   int `json:"policy"`
	Content  int `json:"content"`
	Platform int `json:"platform"`
}

// buildSkipBreakdown counts skipped results by SkipReason. An empty or
// unrecognized reason falls into Platform — an unclassified skip is still an
// environment gap, not a policy decision.
func buildSkipBreakdown(results []models.SimulationResult) SkipBreakdown {
	var sb SkipBreakdown
	for _, r := range results {
		if r.Result != models.ResultSkipped {
			continue
		}
		switch r.SkipReason {
		case models.SkipReasonPolicyPrivilege:
			sb.Policy++
		case models.SkipReasonMissingContent:
			sb.Content++
		default:
			sb.Platform++
		}
	}
	return sb
}

// killChainAction renders a concise adversary-action label for a kill-chain node.
```

- [ ] **Step 4: Wire `SkipBreakdown` and extend `buildExecutiveConclusion` in `insights.go`**

The current `deriveExecutive`:

```go
func deriveExecutive(report *FullReport, results []models.SimulationResult, dets []DetectionTechnique) {
	if report.Summary.PassedTechniques+report.Summary.FailedTechniques == 0 {
		report.Summary.ExposureLevel = "No Data"
	} else {
		report.Summary.ExposureLevel = exposureLevel(report.Summary.PreventionScore)
	}
	ds, measured := detectionScore(report.Detection)
	report.Summary.DetectionScore = round1(ds)
	report.Summary.DetectionMeasured = measured
	report.Summary.PenetrationTested, report.Summary.PenetrationFailed, report.Summary.PenetrationPct = penetration(report.Summary)

	enrichTacticDetection(report.TacticHeatmap, results, dets)
	report.TopRiskDrivers = buildTopRiskDrivers(results, 8)
	report.Insights = buildInsights(report.TacticHeatmap, report.Detection)
	report.ActionPlan = buildActionPlan(results)
	report.Reliability = buildReliability(report.Summary)
	report.Glossary = buildGlossary(results)
	report.ExecutiveConclusion = buildExecutiveConclusion(report.Summary, report.Insights, report.Detection, report.ActionPlan)
	report.DetectionSources = buildDetectionSources(results)
}
```

becomes:

```go
func deriveExecutive(report *FullReport, results []models.SimulationResult, dets []DetectionTechnique) {
	if report.Summary.PassedTechniques+report.Summary.FailedTechniques == 0 {
		report.Summary.ExposureLevel = "No Data"
	} else {
		report.Summary.ExposureLevel = exposureLevel(report.Summary.PreventionScore)
	}
	ds, measured := detectionScore(report.Detection)
	report.Summary.DetectionScore = round1(ds)
	report.Summary.DetectionMeasured = measured
	report.Summary.PenetrationTested, report.Summary.PenetrationFailed, report.Summary.PenetrationPct = penetration(report.Summary)

	enrichTacticDetection(report.TacticHeatmap, results, dets)
	report.TopRiskDrivers = buildTopRiskDrivers(results, 8)
	report.Insights = buildInsights(report.TacticHeatmap, report.Detection)
	report.ActionPlan = buildActionPlan(results)
	report.Reliability = buildReliability(report.Summary)
	report.SkipBreakdown = buildSkipBreakdown(results)
	report.Glossary = buildGlossary(results)
	report.ExecutiveConclusion = buildExecutiveConclusion(report.Summary, report.Insights, report.Detection, report.ActionPlan, report.SkipBreakdown)
	report.DetectionSources = buildDetectionSources(results)
}
```

The current `buildExecutiveConclusion`:

```go
func buildExecutiveConclusion(s ExecutiveSummary, ins Insights, det DetectionSummary, plan []ActionItem) string {
	if s.PassedTechniques+s.FailedTechniques == 0 {
		return "No techniques were executed against this endpoint, so no security conclusion can be drawn. Run a scenario to generate assessment evidence."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "This assessment executed %d techniques against %s, of which %d were not prevented (prevention score %.0f%%, %s exposure). ",
		s.PassedTechniques+s.FailedTechniques, "the endpoint", s.FailedTechniques, s.PreventionScore, strings.ToLower(exposureLevel(s.PreventionScore)))
	if ins.Least != nil && ins.Least.PassPct < 100 {
```

becomes:

```go
func buildExecutiveConclusion(s ExecutiveSummary, ins Insights, det DetectionSummary, plan []ActionItem, skip SkipBreakdown) string {
	if s.PassedTechniques+s.FailedTechniques == 0 {
		return "No techniques were executed against this endpoint, so no security conclusion can be drawn. Run a scenario to generate assessment evidence."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "This assessment executed %d techniques against %s, of which %d were not prevented (prevention score %.0f%%, %s exposure). ",
		s.PassedTechniques+s.FailedTechniques, "the endpoint", s.FailedTechniques, s.PreventionScore, strings.ToLower(exposureLevel(s.PreventionScore)))
	if skip.Policy > 0 {
		fmt.Fprintf(&b, "%d techniques requiring administrative privileges were intentionally excluded by the execution policy. ", skip.Policy)
	}
	if ins.Least != nil && ins.Least.PassPct < 100 {
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run 'TestBuildSkipBreakdown|TestBuildExecutiveConclusion_PolicySkipSentence' -v`
Expected: both PASS.

- [ ] **Step 6: Run the full `internal/reporting` suite to confirm no regression**

Run: `cd orchestrator && go test ./internal/reporting/... 2>&1 | tail -40`
Expected: `ok`. This exercises `Build`/`BuildFromRun`/`BuildFromCampaign`'s existing tests, which all now populate `SkipBreakdown` via `deriveExecutive` and call the 5-arg `buildExecutiveConclusion` — confirming nothing else broke.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/reporting/engine.go orchestrator/internal/reporting/insights.go orchestrator/internal/reporting/engine_test.go orchestrator/internal/reporting/insights_test.go
git commit -m "feat(reporting): SkipBreakdown aggregation and policy-skip executive narrative"
git push
```

---

### Task 3: "Execution Summary" HTML section

**Files:**
- Modify: `orchestrator/internal/reporting/html.go` (new `addInt` template func, new HTML section)
- Test: `orchestrator/internal/reporting/html_test.go` (existing file)

**Interfaces:**
- Consumes: `FullReport.SkipBreakdown` (Task 2), `ExecutiveSummary.PassedTechniques`/`.FailedTechniques` (already exist).
- Produces: nothing new for other tasks — this is the final, leaf rendering step.

- [ ] **Step 1: Extend the failing test**

In `orchestrator/internal/reporting/html_test.go`, `TestGenerateHTMLRendersAllSections`'s `rep` literal currently has:

```go
		Reliability: Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
```

Add a `SkipBreakdown` field right after it:

```go
		Reliability:   Reliability{Attempted: 12, Valid: 12, Confidence: "High"},
		SkipBreakdown: SkipBreakdown{Policy: 4, Content: 1, Platform: 2},
```

Then in the same test's `want` substring list, the current entries include:

```go
		"Assessment Summary",      // §2 heading
```

Add these entries right after it:

```go
		"Assessment Summary",      // §2 heading
		"Execution Summary",       // new §2 sub-table heading
		"Skipped (Policy)",        // execution-summary row label
		"Skipped (Content)",       // execution-summary row label
		"Skipped (Platform)",      // execution-summary row label
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestGenerateHTMLRendersAllSections -v`
Expected: FAIL — the rendered HTML doesn't contain "Execution Summary" or the skip-row labels yet.

- [ ] **Step 3: Add the `addInt` template function**

In `orchestrator/internal/reporting/html.go`, the current `barWidth` entry in the `template.FuncMap`:

```go
	"barWidth": func(f float64) int {
		v := int(math.Round(f))
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	},
```

becomes:

```go
	"barWidth": func(f float64) int {
		v := int(math.Round(f))
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	},
	"addInt": func(a, b float64) int { return int(a) + int(b) },
```

(Template values from `GenerateHTML`'s JSON round-trip always arrive as `float64` — see the comment on `TestGenerateHTMLRendersAllSections` — so `addInt` takes two `float64`s, matching every other numeric template func in this file.)

- [ ] **Step 4: Add the Execution Summary section**

In the `reportHTML` template constant, the current block:

```html
<h3>Secondary Metrics</h3>
<table>
  <tr>
    <td>Tactic Coverage (breadth)</td><td><strong>{{fmtScore .summary.killChainCoverage}}%</strong> of 14 ATT&amp;CK tactics</td>
    <td>Defense Rate</td><td><strong>{{fmtScore .summary.coverageScore}}%</strong> tactics fully blocked</td>
  </tr>
  <tr>
    <td>Kill-Chain Amplifier</td><td><strong>{{fmtScore .summary.killChainAmplifier}}×</strong></td>
    <td>Mean Time-to-Detect</td><td><strong>{{mttd .summary.mttdMs}}</strong></td>
  </tr>
</table>

<h3>Simulation Reliability</h3>
```

becomes:

```html
<h3>Secondary Metrics</h3>
<table>
  <tr>
    <td>Tactic Coverage (breadth)</td><td><strong>{{fmtScore .summary.killChainCoverage}}%</strong> of 14 ATT&amp;CK tactics</td>
    <td>Defense Rate</td><td><strong>{{fmtScore .summary.coverageScore}}%</strong> tactics fully blocked</td>
  </tr>
  <tr>
    <td>Kill-Chain Amplifier</td><td><strong>{{fmtScore .summary.killChainAmplifier}}×</strong></td>
    <td>Mean Time-to-Detect</td><td><strong>{{mttd .summary.mttdMs}}</strong></td>
  </tr>
</table>

<h3>Execution Summary</h3>
<table>
  <tr><td>Executed</td><td><strong>{{addInt .summary.passedTechniques .summary.failedTechniques}}</strong></td>
      <td>Succeeded</td><td style="color:#0d9488"><strong>{{.summary.passedTechniques}}</strong></td></tr>
  <tr><td>Failed</td><td style="color:#da3633"><strong>{{.summary.failedTechniques}}</strong></td>
      <td></td><td></td></tr>
  <tr><td>Skipped (Policy)</td><td><strong>{{.skipBreakdown.policy}}</strong></td>
      <td>Skipped (Content)</td><td><strong>{{.skipBreakdown.content}}</strong></td></tr>
  <tr><td>Skipped (Platform)</td><td><strong>{{.skipBreakdown.platform}}</strong></td>
      <td></td><td></td></tr>
</table>

<h3>Simulation Reliability</h3>
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/reporting/... -run TestGenerateHTMLRendersAllSections -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/reporting/html.go orchestrator/internal/reporting/html_test.go
git commit -m "feat(reporting): render Execution Summary section with skip-reason breakdown"
git push
```

---

### Task 4: Full verification

**Files:** none created — build/vet/gofmt only.

- [ ] **Step 1: Full build/vet/gofmt**

```bash
cd orchestrator
go build ./...
go vet ./...
gofmt -w internal/models/schema.go internal/scenario/outcome.go internal/scenario/interpreter.go internal/scenario/interpret_test.go internal/reporting/engine.go internal/reporting/insights.go internal/reporting/engine_test.go internal/reporting/insights_test.go internal/reporting/html.go internal/reporting/html_test.go
gofmt -l internal/models/schema.go internal/scenario/outcome.go internal/scenario/interpreter.go internal/scenario/interpret_test.go internal/reporting/engine.go internal/reporting/insights.go internal/reporting/engine_test.go internal/reporting/insights_test.go internal/reporting/html.go internal/reporting/html_test.go
```
Expected: build/vet clean; `gofmt -w` normalizes any rough struct-tag alignment from the edits above; the follow-up `gofmt -l` prints nothing (or only CRLF-line-ending noise on files this Windows checkout hasn't normalized — confirmed cosmetic-only in prior sessions, see `project_docker_windows` memory).

- [ ] **Step 2: Commit any gofmt reformatting**

If Step 1's `gofmt -w` changed anything (`git status --short orchestrator/internal`), commit it:

```bash
git add -u orchestrator/internal
git commit -m "chore(reporting): gofmt struct-tag alignment"
git push
```

If nothing changed, skip this step.

- [ ] **Step 3: Full `internal/models`, `internal/scenario`, and `internal/reporting` suites**

```bash
cd orchestrator
go test ./internal/models/... -v
go test ./internal/scenario/... -v
go test ./internal/reporting/... -v 2>&1 | tail -60
```
Expected: all three packages fully green. `internal/reporting` has no container dependency (unlike `internal/api`), so it should be fast — if anything unrelated fails, re-run it in isolation before treating it as a real regression.

- [ ] **Step 4: Report results to the user**

Summarize: test results, and confirm the three-bucket taxonomy (Policy/Content/Platform) now flows end-to-end from `Interpret` through every report type (single-agent, scoped, campaign) to both the new Execution Summary table and the executive narrative.
