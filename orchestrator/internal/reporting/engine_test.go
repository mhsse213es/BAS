package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
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
	}
	got := buildObjectiveRisks(results)
	want := map[string]string{"Credential Theft": "High", "Persistence": "Low", "Code Execution": "Medium"}
	if len(got) != len(want) {
		t.Fatalf("got %d objectives, want %d (%v)", len(got), len(want), got)
	}
	for _, o := range got {
		if want[o.Objective] != o.Risk {
			t.Errorf("%s risk = %q, want %q (failed %d/%d)", o.Objective, o.Risk, want[o.Objective], o.Failed, o.Tested)
		}
	}
}
