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
