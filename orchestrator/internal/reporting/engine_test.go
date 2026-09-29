package reporting

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ERROR results are BAS execution problems, not security outcomes. They must not
// taint a tactic as failed in the heatmap, must not become Top Findings, and
// must not roll a tactic up to a "fail" detection-coverage verdict.
func TestReportExcludesErrorFromOutcomes(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1112", Tactic: "defense-evasion"}, Result: models.ResultError, Severity: "High", Details: "ERROR: Invalid syntax."},
		{Technique: models.AttackTechnique{ID: "T1059", Tactic: "execution"}, Result: models.ResultPass, Severity: "High"},
	}

	heat := buildTacticHeatmap(results)
	for _, e := range heat {
		if e.Tactic == "defense-evasion" {
			t.Errorf("defense-evasion appeared in heatmap with %d failed — ERROR must not taint a tactic", e.Failed)
		}
	}

	if f := buildTopFindings(results, "scenario"); len(f) != 0 {
		t.Errorf("buildTopFindings = %d, want 0 (ERROR is not a finding)", len(f))
	}

	// An ERROR-only tactic has no executed checks, so it reads "unknown" (as a
	// skipped-only tactic does) — never "fail" or "pass".
	for _, c := range buildDetectionCategories(results) {
		if c.Name == "defense-evasion" && c.Result != "unknown" {
			t.Errorf("defense-evasion detection verdict = %q, want unknown (ERROR must not score as fail/pass)", c.Result)
		}
	}
}

// TestBuildTechniqueMatrix_PreservesStepName proves two atomics of the same
// technique produce two distinguishable TechniqueRows -- previously
// TechniqueName alone was identical for every atomic under one technique ID,
// so the report table, CSV, and results drawer showed indistinguishable
// duplicate rows for any technique with more than one atomic (routine in a
// Full Sweep).
func TestBuildTechniqueMatrix_PreservesStepName(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			StepName:  "T1003 - Test 1: Mimikatz",
			Result:    models.ResultFail,
		},
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			StepName:  "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump",
			Result:    models.ResultPass,
		},
	}
	rows := buildTechniqueMatrix(results, nil)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].TechniqueName != rows[1].TechniqueName {
		t.Fatalf("TechniqueName should be identical for both (same technique): %q vs %q", rows[0].TechniqueName, rows[1].TechniqueName)
	}
	if rows[0].StepName == rows[1].StepName {
		t.Error("StepName must distinguish the two atomics, got the same value for both")
	}
	if rows[0].StepName != "T1003 - Test 1: Mimikatz" {
		t.Errorf("rows[0].StepName = %q, want %q", rows[0].StepName, "T1003 - Test 1: Mimikatz")
	}
	if rows[1].StepName != "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump" {
		t.Errorf("rows[1].StepName = %q, want %q", rows[1].StepName, "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump")
	}
}

// TestBuildAttackFlow_PreservesStepName mirrors the TechniqueMatrix case for
// the Attack Flow visualization, which is also built one node per raw result.
func TestBuildAttackFlow_PreservesStepName(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			StepName:  "T1003 - Test 1: Mimikatz",
			Result:    models.ResultFail,
		},
		{
			Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"},
			StepName:  "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump",
			Result:    models.ResultFail,
		},
	}
	nodes := BuildAttackFlow(results)
	if len(nodes) != 2 {
		t.Fatalf("len(nodes) = %d, want 2", len(nodes))
	}
	if nodes[0].StepName == nodes[1].StepName {
		t.Error("StepName must distinguish the two atomics, got the same value for both")
	}
}

// The same ATT&CK technique run many times must collapse into ONE group with a
// per-verdict tally, in first-seen order — so the report stops repeating the same
// "Critical" finding dozens of times.
func TestGroupResultsByTechnique(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory"}, Result: models.ResultFail, Severity: "Critical"},
		{Technique: models.AttackTechnique{ID: "T1112", Name: "Modify Registry"}, Result: models.ResultPass},
		{Technique: models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory"}, Result: models.ResultError},
		{Technique: models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory"}, Result: models.ResultBlocked},
		{Technique: models.AttackTechnique{ID: "T1112", Name: "Modify Registry"}, Result: models.ResultSkipped},
	}

	groups := groupResultsByTechnique(results)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per technique)", len(groups))
	}
	if groups[0].TechniqueID != "T1003.001" || groups[1].TechniqueID != "T1112" {
		t.Errorf("group order = [%s, %s], want first-seen [T1003.001, T1112]", groups[0].TechniqueID, groups[1].TechniqueID)
	}
	g := groups[0]
	if g.Total != 3 || g.Executed != 1 || g.Blocked != 1 || g.Errored != 1 || g.Skipped != 0 {
		t.Errorf("T1003.001 tally = total %d exec %d blocked %d err %d skip %d; want 3/1/1/1/0",
			g.Total, g.Executed, g.Blocked, g.Errored, g.Skipped)
	}
	if groups[1].Blocked != 1 || groups[1].Skipped != 1 {
		t.Errorf("T1112 tally = blocked %d skip %d; want 1/1", groups[1].Blocked, groups[1].Skipped)
	}
}

// The same Critical technique failing across several atomics must surface as ONE
// top finding, not a repeated "Critical, Critical, Critical…" list.
func TestBuildTopFindingsDedupesByTechnique(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory", Tactic: "credential-access"}, Result: models.ResultFail, Severity: "Critical"},
		{Technique: models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory", Tactic: "credential-access"}, Result: models.ResultFail, Severity: "Critical"},
		{Technique: models.AttackTechnique{ID: "T1003.001", Name: "LSASS Memory", Tactic: "credential-access"}, Result: models.ResultFail, Severity: "Critical"},
		{Technique: models.AttackTechnique{ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "impact"}, Result: models.ResultFail, Severity: "High"},
	}
	f := buildTopFindings(results, "scenario")
	if len(f) != 2 {
		t.Fatalf("buildTopFindings = %d findings, want 2 (deduped by technique)", len(f))
	}
	if f[0].TechniqueID != "T1003.001" || f[1].TechniqueID != "T1486" {
		t.Errorf("findings = [%s, %s], want [T1003.001, T1486]", f[0].TechniqueID, f[1].TechniqueID)
	}
}

// Detection correlation: a Defender detection event => Detected; other telemetry
// => Logged (visibility, no alert); nothing => None. Honest by design — only
// Defender/Sysmon/Security are observable.
func TestClassifyDetection(t *testing.T) {
	cases := []struct {
		name       string
		events     []string
		wantStatus string
		wantDetect bool
	}{
		{"defender threat detected", []string{"4688:Security", "1116:Microsoft-Windows-Windows Defender/Operational"}, "Detected", true},
		{"defender action taken", []string{"1117:Microsoft-Windows-Windows Defender/Operational"}, "Detected", true},
		{"sysmon activity only", []string{"1:Microsoft-Windows-Sysmon/Operational"}, "Logged", false},
		{"security log only", []string{"4688:Security"}, "Logged", false},
		{"benign defender event is not a detection", []string{"1000:Microsoft-Windows-Windows Defender/Operational"}, "Logged", false},
		{"no telemetry", nil, "None", false},
		{"malformed tokens ignored", []string{"", "garbage", ":bad", "bad:"}, "None", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := classifyDetection(c.events)
			if d.Status != c.wantStatus || d.Detected != c.wantDetect {
				t.Errorf("classifyDetection(%v) = {Status:%q Detected:%v}, want {%q %v}",
					c.events, d.Status, d.Detected, c.wantStatus, c.wantDetect)
			}
		})
	}
}

// The prevention/detection summary counts only FAILs (executed-unprevented) and
// splits them by detection outcome. PASS/ERROR/SKIPPED never count.
func TestBuildDetectionSummary(t *testing.T) {
	results := []models.SimulationResult{
		{Result: models.ResultFail, Events: []string{"1116:Microsoft-Windows-Windows Defender/Operational"}}, // Detected
		{Result: models.ResultFail, Events: []string{"1:Microsoft-Windows-Sysmon/Operational"}},              // Logged
		{Result: models.ResultFail, Events: nil},                                                             // Undetected
		{Result: models.ResultFail, Events: []string{"4688:Security"}},                                       // Logged
		{Result: models.ResultPass, Events: []string{"1116:Microsoft-Windows-Windows Defender/Operational"}}, // ignored (prevented)
		{Result: models.ResultError, Events: nil},                                                            // ignored
	}
	s := buildDetectionSummary(results)
	if s.ExecutedUnprevented != 4 || s.Detected != 1 || s.LoggedOnly != 2 || s.Undetected != 1 {
		t.Errorf("summary = %+v; want {Exec:4 Detected:1 Logged:2 Undetected:1}", s)
	}
	if !s.TelemetryObserved {
		t.Errorf("TelemetryObserved = false; want true (some results carried events)")
	}
}

// When NO result in the run carried any telemetry, the summary must flag that
// detection was not measurable — so the report does not claim the FAILs "evaded"
// the SOC when in truth nothing was collected (old agent build / Defender off).
func TestBuildDetectionSummaryNoTelemetry(t *testing.T) {
	results := []models.SimulationResult{
		{Result: models.ResultFail, Events: nil},
		{Result: models.ResultFail, Events: nil},
		{Result: models.ResultPass, Events: nil},
	}
	s := buildDetectionSummary(results)
	if s.TelemetryObserved {
		t.Errorf("TelemetryObserved = true; want false (no result carried events)")
	}
	if s.ExecutedUnprevented != 2 || s.Undetected != 2 {
		t.Errorf("summary = %+v; want {Exec:2 Undetected:2}", s)
	}
}

// Attack path: only FAILs form the chain, ordered by kill-chain phase, deduped
// per phase; PASS/ERROR/SKIPPED never appear.
func TestBuildAttackPath(t *testing.T) {
	results := []models.SimulationResult{
		// out of kill-chain order on purpose
		{Technique: models.AttackTechnique{ID: "T1003", Name: "OS Credential Dumping", Tactic: "credential-access"}, Result: models.ResultFail},
		{Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail},
		{Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail}, // dup
		{Technique: models.AttackTechnique{ID: "T1547", Name: "Boot Autostart", Tactic: "persistence"}, Result: models.ResultFail},
		{Technique: models.AttackTechnique{ID: "T1112", Name: "Modify Registry", Tactic: "defense-evasion"}, Result: models.ResultPass},           // excluded
		{Technique: models.AttackTechnique{ID: "T1486", Name: "Impact", Tactic: "impact"}, Result: models.ResultError},                            // excluded
		{Technique: models.AttackTechnique{ID: "T1071", Name: "App Layer Protocol", Tactic: "command-and-control"}, Result: models.ResultSkipped}, // excluded
	}
	ap := buildAttackPath(results)
	// kill-chain order: execution, persistence, credential-access
	wantTactics := []string{"execution", "persistence", "credential-access"}
	if len(ap.Steps) != len(wantTactics) {
		t.Fatalf("got %d steps, want %d (%+v)", len(ap.Steps), len(wantTactics), ap.Steps)
	}
	for i, w := range wantTactics {
		if ap.Steps[i].Tactic != w {
			t.Errorf("step %d tactic = %q, want %q", i, ap.Steps[i].Tactic, w)
		}
	}
	if len(ap.Steps[0].Techniques) != 1 {
		t.Errorf("execution techniques = %v, want 1 (deduped)", ap.Steps[0].Techniques)
	}
}

// Control attribution: a Defender ASR block event => Defender ASR; a Defender
// threat-action event => Defender; output signatures => the matching control;
// nothing evidenced => "" (caller states a control blocked it without guessing).
func TestAttributeControl(t *testing.T) {
	cases := []struct {
		name   string
		result models.SimulationResult
		want   string
	}{
		{"asr block event", models.SimulationResult{Events: []string{"1121:Microsoft-Windows-Windows Defender/Operational"}}, "Microsoft Defender (ASR rule)"},
		{"defender threat action", models.SimulationResult{Events: []string{"1117:Microsoft-Windows-Windows Defender/Operational"}}, "Microsoft Defender"},
		{"output names defender", models.SimulationResult{RawOutput: "Operation did not complete successfully because the file contains a virus"}, "Microsoft Defender (from output)"},
		{"group policy block", models.SimulationResult{RawOutput: "This program is blocked by group policy."}, "Application Control / Group Policy"},
		{"constrained language", models.SimulationResult{RawOutput: "Cannot invoke method. Constrained Language mode."}, "PowerShell Constrained Language Mode"},
		{"no evidence", models.SimulationResult{RawOutput: "Access is denied."}, ""},
		{"benign defender event is not a block", models.SimulationResult{Events: []string{"1000:Microsoft-Windows-Windows Defender/Operational"}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := attributeControl(c.result); got != c.want {
				t.Errorf("attributeControl = %q, want %q", got, c.want)
			}
		})
	}
}

// Trend: newest scored run is "current", the next is "previous"; the delta is
// current − previous; running/failed runs are excluded; history is oldest-first.
func TestBuildTrendSummary(t *testing.T) {
	runs := []RunSummary{ // newest first, as the DB query returns
		{ID: "r3", Status: "completed", PreventionScore: 41, RiskScore: 60, StartedAt: time.Unix(300, 0)},
		{ID: "r-running", Status: "running", PreventionScore: 0, StartedAt: time.Unix(250, 0)},
		{ID: "r2", Status: "partial", PreventionScore: 28, RiskScore: 72, StartedAt: time.Unix(200, 0)},
		{ID: "r1", Status: "completed", PreventionScore: 20, RiskScore: 80, StartedAt: time.Unix(100, 0)},
	}
	tr := buildTrendSummary(runs)
	if !tr.HasPrevious {
		t.Fatal("HasPrevious = false; want true")
	}
	if tr.CurrentPrevention != 41 || tr.PreviousPrevention != 28 || tr.DeltaPrevention != 13 {
		t.Errorf("cur/prev/delta = %.0f/%.0f/%.0f; want 41/28/13", tr.CurrentPrevention, tr.PreviousPrevention, tr.DeltaPrevention)
	}
	if len(tr.History) != 3 {
		t.Fatalf("history len = %d; want 3 (running run excluded)", len(tr.History))
	}
	if tr.History[0].RunID != "r1" || tr.History[2].RunID != "r3" {
		t.Errorf("history order = [%s..%s]; want oldest-first r1..r3", tr.History[0].RunID, tr.History[2].RunID)
	}
}

// With fewer than two scored runs, no trend is asserted (no invented baseline).
func TestBuildTrendSummaryFirstRun(t *testing.T) {
	tr := buildTrendSummary([]RunSummary{{ID: "r1", Status: "completed", PreventionScore: 50}})
	if tr.HasPrevious {
		t.Errorf("HasPrevious = true; want false (only one scored run)")
	}
}

// Business-objective risk bands: High when most tested techniques in a tactic
// went unprevented, Low when all were blocked. Untested objectives and
// ERROR/SKIPPED results are excluded.
func TestBuildObjectiveRisks(t *testing.T) {
	results := []models.SimulationResult{
		// credential-access: 2 of 2 failed -> High
		{Technique: models.AttackTechnique{Tactic: "credential-access"}, Result: models.ResultFail},
		{Technique: models.AttackTechnique{Tactic: "credential-access"}, Result: models.ResultFail},
		// persistence: 0 of 2 failed -> Low
		{Technique: models.AttackTechnique{Tactic: "persistence"}, Result: models.ResultPass},
		{Technique: models.AttackTechnique{Tactic: "persistence"}, Result: models.ResultBlocked},
		// execution: 1 of 3 failed -> Medium
		{Technique: models.AttackTechnique{Tactic: "execution"}, Result: models.ResultFail},
		{Technique: models.AttackTechnique{Tactic: "execution"}, Result: models.ResultPass},
		{Technique: models.AttackTechnique{Tactic: "execution"}, Result: models.ResultPass},
		// discovery: only ERROR/SKIPPED -> excluded entirely
		{Technique: models.AttackTechnique{Tactic: "discovery"}, Result: models.ResultError},
		{Technique: models.AttackTechnique{Tactic: "discovery"}, Result: models.ResultSkipped},
		// defense-evasion: ONLY a vetoed result -> excluded entirely, not
		// "Low" (which would fabricate "all were blocked" for a technique
		// Audspect never attempted -- final whole-branch review, C4).
		{Technique: models.AttackTechnique{Tactic: "defense-evasion"}, Result: models.ResultVetoed},
	}
	got := buildObjectiveRisks(results)
	want := map[string]string{"Credential Theft": "High", "Persistence": "Low", "Code Execution": "Medium"}
	for _, o := range got {
		if o.Objective == "Defense Evasion" {
			t.Fatalf("Defense Evasion objective present with a vetoed-only technique: %+v -- must be excluded entirely, not scored", o)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %d objectives, want %d (%v)", len(got), len(want), got)
	}
	for _, o := range got {
		if want[o.Objective] != o.Risk {
			t.Errorf("%s risk = %q, want %q (failed %d/%d)", o.Objective, o.Risk, want[o.Objective], o.Failed, o.Tested)
		}
	}
}

func TestBuildSkipBreakdown(t *testing.T) {
	results := []models.SimulationResult{
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonMissingContent},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonPlatformUnavailable},
		{Result: models.ResultSkipped, SkipReason: models.SkipReasonCircuitOpen},
		{Result: models.ResultSkipped, SkipReason: ""}, // unrecognized/legacy skip
		{Result: models.ResultPass}, // not a skip — must not be counted
	}
	got := buildSkipBreakdown(results)
	want := SkipBreakdown{Policy: 2, Content: 1, Platform: 2, Scheduler: 1}
	if got != want {
		t.Errorf("buildSkipBreakdown = %+v, want %+v", got, want)
	}
}

func TestBuildCoverageSummary(t *testing.T) {
	cases := []struct {
		name            string
		results         []models.SimulationResult
		totalBase       int
		eligibleBase    int
		wantExecuted    int
		wantScenarioPct int
		wantEligiblePct int
	}{
		{
			name: "no filtering — every step executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass},
				{Technique: models.AttackTechnique{ID: "T1548"}, Result: models.ResultFail},
			},
			totalBase: 2, eligibleBase: 2,
			wantExecuted: 2, wantScenarioPct: 100, wantEligiblePct: 100,
		},
		{
			name: "policy skip excluded from Executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass},
				{Technique: models.AttackTechnique{ID: "T1548"}, Result: models.ResultSkipped, SkipReason: models.SkipReasonPolicyPrivilege},
			},
			totalBase: 2, eligibleBase: 1,
			wantExecuted: 1, wantScenarioPct: 50, wantEligiblePct: 100,
		},
		{
			// Regression for a real reporting bug: a content-skipped technique
			// was never dispatched real test content and produced no PASS/FAIL
			// verdict, so counting it as "executed" inflated Scenario/Eligible
			// Coverage to 100% on runs where 2 of 6 techniques never actually
			// ran -- misreading "we attempted to dispatch it" as "we validated
			// it." Executed must match the Execution Summary table's own
			// Executed count (passedTechniques+failedTechniques) exactly.
			name: "non-policy skip does NOT count as executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultSkipped, SkipReason: models.SkipReasonMissingContent},
			},
			totalBase: 1, eligibleBase: 1,
			wantExecuted: 0, wantScenarioPct: 0, wantEligiblePct: 0,
		},
		{
			name: "environmental error does NOT count as executed",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultError},
			},
			totalBase: 1, eligibleBase: 1,
			wantExecuted: 0, wantScenarioPct: 0, wantEligiblePct: 0,
		},
		{
			name: "dispatched but never returned — Executed < Eligible",
			results: []models.SimulationResult{
				{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass},
			},
			totalBase: 2, eligibleBase: 2,
			wantExecuted: 1, wantScenarioPct: 50, wantEligiblePct: 50,
		},
		{
			name:      "zero denominators — no coverage data available",
			results:   nil,
			totalBase: 0, eligibleBase: 0,
			wantExecuted: 0, wantScenarioPct: 0, wantEligiblePct: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildCoverageSummary(c.results, c.totalBase, c.eligibleBase)
			if got.Executed != c.wantExecuted || got.ScenarioCoveragePct != c.wantScenarioPct || got.EligibleCoveragePct != c.wantEligiblePct {
				t.Errorf("buildCoverageSummary() = %+v, want Executed=%d ScenarioCoveragePct=%d EligibleCoveragePct=%d",
					got, c.wantExecuted, c.wantScenarioPct, c.wantEligiblePct)
			}
		})
	}
}

func TestBuildEnvRestoration_RescuedWhenResidualMatchesReverted(t *testing.T) {
	matrix := []TechniqueRow{
		{TechniqueID: "T1053.005", CleanupVerdict: "leaked", CleanupResidual: []string{"schtask:\\Evil\\Task"}},
	}
	reverted := []string{"schtask deleted: \\Evil\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if e.StepsRescued != 1 {
		t.Errorf("StepsRescued = %d, want 1", e.StepsRescued)
	}
	if e.StepsCleaned != 1 {
		t.Errorf("StepsCleaned = %d, want 1 (rescued counts toward cleaned)", e.StepsCleaned)
	}
	if e.StepsLeaked != 0 {
		t.Errorf("StepsLeaked = %d, want 0", e.StepsLeaked)
	}
	if matrix[0].CleanupVerdict != "rescued" {
		t.Errorf("matrix[0].CleanupVerdict = %q, want %q (mutated in place)", matrix[0].CleanupVerdict, "rescued")
	}
}

func TestBuildEnvRestoration_LeakedWhenResidualHasNoMatch(t *testing.T) {
	matrix := []TechniqueRow{
		{TechniqueID: "T1070.001", TechniqueName: "Indicator Removal", StepName: "Clear logs",
			CleanupVerdict: "partial", CleanupResidual: []string{"tmp:/tmp/evil"}, CleanupError: "exit 1: Access is denied."},
	}
	reverted := []string{"schtask deleted: \\Unrelated\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if e.StepsRescued != 0 {
		t.Errorf("StepsRescued = %d, want 0", e.StepsRescued)
	}
	if e.StepsLeaked != 1 {
		t.Errorf("StepsLeaked = %d, want 1", e.StepsLeaked)
	}
	if matrix[0].CleanupVerdict != "partial" {
		t.Errorf("matrix[0].CleanupVerdict = %q, want unchanged %q", matrix[0].CleanupVerdict, "partial")
	}
	// TestBuildEnvRestoration_LeakedWhenResidualHasNoMatch doubles as the
	// regression test for LeakedItems: the aggregate StepsLeaked count alone
	// can't say WHICH step leaked, WHAT's still on the endpoint, or WHY the
	// cleanup script didn't remove it -- this is the per-step detail an
	// operator actually needs.
	if len(e.LeakedItems) != 1 {
		t.Fatalf("LeakedItems = %d entries, want 1", len(e.LeakedItems))
	}
	item := e.LeakedItems[0]
	if item.TechniqueID != "T1070.001" || item.StepName != "Clear logs" {
		t.Errorf("LeakedItems[0] = %+v, want TechniqueID=T1070.001 StepName=%q", item, "Clear logs")
	}
	if len(item.Residual) != 1 || item.Residual[0] != "tmp:/tmp/evil" {
		t.Errorf("LeakedItems[0].Residual = %v, want [tmp:/tmp/evil]", item.Residual)
	}
	if item.Error != "exit 1: Access is denied." {
		t.Errorf("LeakedItems[0].Error = %q, want the cleanup command's own captured detail", item.Error)
	}
}

// TestBuildEnvRestoration_RescuedItemExcludedFromLeakedItems confirms a step
// the whole-run safety net later confirmed removed never appears in the
// per-step leaked-detail list -- it was reclassified "rescued" before the
// LeakedItems population loop runs, so it must not double-report as a leak.
func TestBuildEnvRestoration_RescuedItemExcludedFromLeakedItems(t *testing.T) {
	matrix := []TechniqueRow{
		{TechniqueID: "T1053.005", CleanupVerdict: "leaked", CleanupResidual: []string{"schtask:\\Evil\\Task"}},
	}
	reverted := []string{"schtask deleted: \\Evil\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if len(e.LeakedItems) != 0 {
		t.Errorf("LeakedItems = %+v, want empty -- a rescued step is not a leak", e.LeakedItems)
	}
}

func TestBuildEnvRestoration_NilResidualFallsBackToLegacyMath(t *testing.T) {
	// Historical row recorded before this change: CleanupVerdict set, CleanupResidual nil.
	matrix := []TechniqueRow{
		{TechniqueID: "T1053.005", CleanupVerdict: "leaked", CleanupResidual: nil},
	}
	reverted := []string{"schtask deleted: \\Evil\\Task"}

	e := buildEnvRestoration(matrix, reverted)

	if e.StepsRescued != 0 {
		t.Errorf("StepsRescued = %d, want 0 (nil residual must never match)", e.StepsRescued)
	}
	if e.StepsLeaked != 1 {
		t.Errorf("StepsLeaked = %d, want 1 (unchanged legacy classification)", e.StepsLeaked)
	}
}

func TestNormalizeReverted(t *testing.T) {
	cases := []struct {
		entry   string
		wantKey string
		wantOK  bool
	}{
		{"tmp removed: /tmp/evil", "tmp:/tmp/evil", true},
		{"registry removed: HKCU\\Run\\Evil", "registry:HKCU\\Run\\Evil", true},
		{"schtask deleted: \\Evil\\Task", "schtask:\\Evil\\Task", true},
		{"service stopped: EvilSvc", "service:EvilSvc", true},
		{"startup removed: C:\\Startup\\evil.lnk", "startup:C:\\Startup\\evil.lnk", true},
		{"cron removed: /etc/cron.d/evil", "cron:/etc/cron.d/evil", true},
		{"file restored: /etc/hosts", "/etc/hosts", true},
		{"crontab: user crontab restored", "crontab:user", true},
		{"iptables: rules restored", "iptables", true},
		{"something unrecognized", "", false},
	}
	for _, c := range cases {
		key, ok := normalizeReverted(c.entry)
		if ok != c.wantOK || key != c.wantKey {
			t.Errorf("normalizeReverted(%q) = (%q, %v), want (%q, %v)", c.entry, key, ok, c.wantKey, c.wantOK)
		}
	}
}

func TestBuildTechniqueMatrix_PassesThroughCleanupResidual(t *testing.T) {
	results := []models.SimulationResult{
		{
			Technique:       models.AttackTechnique{ID: "T1053.005", Tactic: "persistence"},
			Result:          models.ResultFail,
			Severity:        "High",
			CleanupVerdict:  "partial",
			CleanupResidual: []string{"schtask:\\Evil\\Task"},
		},
	}
	rows := buildTechniqueMatrix(results, nil)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	want := []string{"schtask:\\Evil\\Task"}
	if !reflect.DeepEqual(rows[0].CleanupResidual, want) {
		t.Errorf("CleanupResidual = %v, want %v", rows[0].CleanupResidual, want)
	}
}

func TestBuildSweepTechniqueBreakdown_MixedOutcomes(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultBlocked},
		{ID: "r2", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultFail},
		{ID: "r3", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultFail},
		{ID: "r4", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultError},
	}
	dets := []DetectionTechnique{{TechniqueID: "T1055", Verdict: "detected", Confidence: "high"}}

	rows := buildSweepTechniqueBreakdown(results, dets)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.TechniqueID != "T1055" || r.TechniqueName != "Process Injection" || r.Tactic != "defense-evasion" {
		t.Errorf("row identity = %+v", r)
	}
	if r.Variants != 4 {
		t.Errorf("Variants = %d, want 4", r.Variants)
	}
	if r.Blocked != 1 {
		t.Errorf("Blocked = %d, want 1", r.Blocked)
	}
	if r.Detected != 2 {
		t.Errorf("Detected = %d, want 2", r.Detected)
	}
	if r.Missed != 0 {
		t.Errorf("Missed = %d, want 0", r.Missed)
	}
	if r.ErrorSkipped != 1 {
		t.Errorf("ErrorSkipped = %d, want 1", r.ErrorSkipped)
	}
	if !r.Measurable {
		t.Error("Measurable = false, want true")
	}
	wantPrevention := 1.0 / 3.0 * 100
	if math.Abs(r.PreventionPct-wantPrevention) > 0.01 {
		t.Errorf("PreventionPct = %v, want %v", r.PreventionPct, wantPrevention)
	}
	wantDetection := 2.0 / 3.0 * 100
	if math.Abs(r.DetectionPct-wantDetection) > 0.01 {
		t.Errorf("DetectionPct = %v, want %v", r.DetectionPct, wantDetection)
	}
}

func TestBuildSweepTechniqueBreakdown_AllErrorNotMeasurable(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "r1", Technique: models.AttackTechnique{ID: "T1059", Name: "PowerShell"}, Result: models.ResultError},
		{ID: "r2", Technique: models.AttackTechnique{ID: "T1059", Name: "PowerShell"}, Result: models.ResultSkipped},
	}
	rows := buildSweepTechniqueBreakdown(results, nil)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Measurable {
		t.Error("Measurable = true, want false (all results are error/skipped)")
	}
	if r.PreventionPct != 0 || r.DetectionPct != 0 {
		t.Errorf("PreventionPct/DetectionPct = %v/%v, want 0/0 when not measurable", r.PreventionPct, r.DetectionPct)
	}
	if r.ErrorSkipped != 2 {
		t.Errorf("ErrorSkipped = %d, want 2", r.ErrorSkipped)
	}
}

func TestBuildSweepTechniqueBreakdown_MultipleTechniquesAndEmptyInput(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection"}, Result: models.ResultBlocked},
		{ID: "r2", Technique: models.AttackTechnique{ID: "T1059", Name: "PowerShell"}, Result: models.ResultFail},
	}
	rows := buildSweepTechniqueBreakdown(results, nil)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2 (one per technique)", len(rows))
	}

	if rows := buildSweepTechniqueBreakdown(nil, nil); len(rows) != 0 {
		t.Errorf("empty input: len(rows) = %d, want 0", len(rows))
	}
}

func TestBuildSweepEncodingBreakdown_CaughtVsBypassed(t *testing.T) {
	samples := []sweepEncodingSample{
		{Encoding: "base64", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultBlocked}},
		{Encoding: "base64", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail}},
		{Encoding: "plain", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail}},
		{Encoding: "plain", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail}},
	}
	rows := buildSweepEncodingBreakdown(samples, nil)
	byEnc := map[string]SweepEncodingRow{}
	for _, r := range rows {
		byEnc[r.Encoding] = r
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if b := byEnc["base64"]; b.Total != 2 || b.Caught != 1 || b.Bypassed != 1 {
		t.Errorf("base64 = %+v, want Total=2 Caught=1 Bypassed=1", b)
	}
	if p := byEnc["plain"]; p.Total != 2 || p.Caught != 0 || p.Bypassed != 2 {
		t.Errorf("plain = %+v, want Total=2 Caught=0 Bypassed=2", p)
	}
	if !byEnc["base64"].Measurable || byEnc["base64"].CaughtPct != 50 {
		t.Errorf("base64 CaughtPct/Measurable = %v/%v, want 50/true", byEnc["base64"].CaughtPct, byEnc["base64"].Measurable)
	}
}

func TestBuildSweepEncodingBreakdown_AllErrorNotMeasurable(t *testing.T) {
	samples := []sweepEncodingSample{
		{Encoding: "gzip_b64", Result: models.SimulationResult{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultError}},
	}
	rows := buildSweepEncodingBreakdown(samples, nil)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].Measurable {
		t.Error("Measurable = true, want false")
	}
	if rows[0].CaughtPct != 0 {
		t.Errorf("CaughtPct = %v, want 0", rows[0].CaughtPct)
	}
}

func TestBuildSweepEncodingBreakdown_EmptyInput(t *testing.T) {
	if rows := buildSweepEncodingBreakdown(nil, nil); len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0", len(rows))
	}
}

func TestBuildFromSweep_AggregatesAcrossTechniquesAndEncodings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)

		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-report')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO vex_sweeps (id, agent_id, techniques, technique_variant_counts, status, completed_variants, total_variants, started_at)
			 VALUES ('sw-report-1', 'agent-sweep-report', ARRAY['T1055','T1059.001'], ARRAY[2,2], 'completed', 4, 4, NOW())`); err != nil {
			t.Fatalf("seed sweep: %v", err)
		}

		t1055Results := []models.SimulationResult{
			{ID: "t1055-r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultBlocked, Severity: "High"},
			{ID: "t1055-r2", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultFail, Severity: "High"},
		}
		t1055JSON, _ := json.Marshal(t1055Results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, sweep_id)
			 VALUES ('sr-t1055', '__variant__T1055', 'agent-sweep-report', 'T1055 variants', 'completed', $1, 'sw-report-1')`,
			t1055JSON); err != nil {
			t.Fatalf("seed sr-t1055: %v", err)
		}

		t1059Results := []models.SimulationResult{
			{ID: "t1059-r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
			{ID: "t1059-r2", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
		}
		t1059JSON, _ := json.Marshal(t1059Results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, sweep_id)
			 VALUES ('sr-t1059', '__variant__T1059.001', 'agent-sweep-report', 'T1059.001 variants', 'completed', $1, 'sw-report-1')`,
			t1059JSON); err != nil {
			t.Fatalf("seed sr-t1059: %v", err)
		}

		if _, err := pool.Exec(ctx,
			`INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, total_variants, status)
			 VALUES ('vr-t1055', 'agent-sweep-report', 'T1055', 'sr-t1055', 2, 'completed')`); err != nil {
			t.Fatalf("seed vr-t1055: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO variant_run_steps (variant_run_id, task_id, technique_id, encoding, exec_context, evasion, executor, risk_level, variant_hash)
			 VALUES ('vr-t1055', 't1055-r1', 'T1055', 'base64', 'powershell_direct', 'none', 'powershell', 'SAFE', 'hash1'),
			        ('vr-t1055', 't1055-r2', 'T1055', 'plain', 'powershell_direct', 'none', 'powershell', 'SAFE', 'hash2')`); err != nil {
			t.Fatalf("seed variant_run_steps: %v", err)
		}

		rep, err := e.BuildFromSweep(ctx, "sw-report-1", "")
		if err != nil {
			t.Fatalf("BuildFromSweep: %v", err)
		}

		if rep.Scope == nil || rep.Scope.Kind != "sweep" {
			t.Fatalf("Scope = %+v, want Kind=sweep", rep.Scope)
		}
		if len(rep.SweepTechniqueBreakdown) != 2 {
			t.Fatalf("len(SweepTechniqueBreakdown) = %d, want 2", len(rep.SweepTechniqueBreakdown))
		}
		byTech := map[string]SweepTechniqueRow{}
		for _, r := range rep.SweepTechniqueBreakdown {
			byTech[r.TechniqueID] = r
		}
		if t1055 := byTech["T1055"]; t1055.Blocked != 1 || t1055.ScenarioRunID != "sr-t1055" {
			t.Errorf("T1055 row = %+v, want Blocked=1 ScenarioRunID=sr-t1055", t1055)
		}
		if len(rep.SweepEncodingBreakdown) != 2 {
			t.Fatalf("len(SweepEncodingBreakdown) = %d, want 2 (base64, plain)", len(rep.SweepEncodingBreakdown))
		}
		if len(rep.TacticHeatmap) == 0 {
			t.Error("TacticHeatmap is empty — union of sweep results did not reach the reused report sections")
		}
	})
}

func TestBuildFromSweep_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := NewEngine(pool)
		if _, err := e.BuildFromSweep(context.Background(), "nope", ""); err == nil {
			t.Fatal("expected an error for an unknown sweep id")
		}
	})
}

func TestBuildFromEMSweep_AggregatesAcrossLayers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)

		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-emsweep-report')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO em_sweeps (id, agent_id, layers, completed_layers, total_layers, status, started_at)
			 VALUES ('em-report-1', 'agent-emsweep-report', ARRAY['em-01-control-validation','em-04-credential-theft'], 2, 2, 'completed', NOW())`); err != nil {
			t.Fatalf("seed em_sweep: %v", err)
		}

		layer1Results := []models.SimulationResult{
			{ID: "l1-r1", Technique: models.AttackTechnique{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion"}, Result: models.ResultBlocked, Severity: "High"},
			{ID: "l1-r2", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
		}
		l1JSON, _ := json.Marshal(layer1Results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, em_sweep_id)
			 VALUES ('sr-em-l1', 'em-01-control-validation', 'agent-emsweep-report', 'EM Layer 1', 'completed', $1, 'em-report-1')`,
			l1JSON); err != nil {
			t.Fatalf("seed sr-em-l1: %v", err)
		}

		layer2Results := []models.SimulationResult{
			{ID: "l2-r1", Technique: models.AttackTechnique{ID: "T1003", Name: "Credential Dumping", Tactic: "credential-access"}, Result: models.ResultFail, Severity: "Critical"},
		}
		l2JSON, _ := json.Marshal(layer2Results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, em_sweep_id)
			 VALUES ('sr-em-l2', 'em-04-credential-theft', 'agent-emsweep-report', 'EM Layer 4', 'completed', $1, 'em-report-1')`,
			l2JSON); err != nil {
			t.Fatalf("seed sr-em-l2: %v", err)
		}

		rep, err := e.BuildFromEMSweep(ctx, "em-report-1", "")
		if err != nil {
			t.Fatalf("BuildFromEMSweep: %v", err)
		}

		if rep.Scope == nil || rep.Scope.Kind != "em_sweep" {
			t.Fatalf("Scope = %+v, want Kind=em_sweep", rep.Scope)
		}
		if rep.Scope.RunCount != 2 {
			t.Errorf("Scope.RunCount = %d, want 2", rep.Scope.RunCount)
		}
		if len(rep.TacticHeatmap) == 0 {
			t.Error("TacticHeatmap is empty — union of EM sweep results did not reach the reused report sections")
		}
		if rep.Summary.TotalTechniques != 3 {
			t.Errorf("Summary.TotalTechniques = %d, want 3 (union of both layers' results)", rep.Summary.TotalTechniques)
		}
	})
}

func TestBuildFromEMSweep_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := NewEngine(pool)
		if _, err := e.BuildFromEMSweep(context.Background(), "nope", ""); err == nil {
			t.Fatal("expected an error for an unknown EM sweep id")
		}
	})
}
