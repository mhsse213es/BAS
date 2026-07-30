package compliance

import "testing"

func TestAllControls_FlattensEveryFrameworkSortedDeterministically(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	all := m.AllControls()

	wantTotal := 0
	for _, fw := range m.Frameworks() {
		wantTotal += fw.TotalControls
	}
	if len(all) != wantTotal {
		t.Fatalf("AllControls() returned %d controls, want %d (sum of every framework's TotalControls)", len(all), wantTotal)
	}

	for i, cwf := range all {
		if cwf.FrameworkID == "" || cwf.Control.ID == "" {
			t.Fatalf("all[%d] = %+v, want non-empty FrameworkID and Control.ID", i, cwf)
		}
		if i > 0 {
			prev := all[i-1]
			if cwf.FrameworkID < prev.FrameworkID {
				t.Fatalf("all[%d].FrameworkID = %q sorts before all[%d].FrameworkID = %q, want non-decreasing", i, cwf.FrameworkID, i-1, prev.FrameworkID)
			}
			if cwf.FrameworkID == prev.FrameworkID && cwf.Control.ID < prev.Control.ID {
				t.Fatalf("within framework %q, all[%d].Control.ID = %q sorts before all[%d].Control.ID = %q, want non-decreasing", cwf.FrameworkID, i, cwf.Control.ID, i-1, prev.Control.ID)
			}
		}
	}
}

func TestBuildNarrative_NoTestedControls(t *testing.T) {
	got := buildNarrative(ComplianceSummary{}, nil, nil)
	want := "No controls have been tested yet — run a scenario to generate compliance evidence."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_AllPassing(t *testing.T) {
	s := ComplianceSummary{TestedControls: 10, PassingControls: 10, CompliancePercent: 100}
	got := buildNarrative(s, nil, nil)
	want := "100% compliant — 10 of 10 tested controls are passing."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_MixedWithTopDomainAndTechnique(t *testing.T) {
	s := ComplianceSummary{
		TestedControls: 21, PassingControls: 13, FailingControls: 5,
		UntestedControls: 3, CompliancePercent: 62,
	}
	domains := []DomainResult{
		{Name: "Identity & Access", Failing: 3},
		{Name: "Logging & Monitoring", Failing: 2},
	}
	controls := []ControlResult{
		{Evidence: []TechniqueEvidence{
			{TechniqueID: "T1110", TechniqueName: "Brute Force", Result: "fail"},
			{TechniqueID: "T1110", TechniqueName: "Brute Force", Result: "fail"},
		}},
		{Evidence: []TechniqueEvidence{
			{TechniqueID: "T1078", TechniqueName: "Valid Accounts", Result: "fail"},
		}},
	}
	got := buildNarrative(s, domains, controls)
	want := "62% compliant — 13 of 21 tested controls are passing. 5 control(s) are failing, most concentrated in Identity & Access (3 of 5). The most common failing technique is Brute Force (T1110). 3 control(s) haven't been tested yet — run additional scenarios to close coverage gaps."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_DomainTieBreaksAlphabetically(t *testing.T) {
	s := ComplianceSummary{TestedControls: 4, PassingControls: 2, FailingControls: 2, CompliancePercent: 50}
	// domains is pre-sorted alphabetically by GenerateReport -- Alpha comes
	// before Bravo, both tied at 1 failing control each.
	domains := []DomainResult{
		{Name: "Alpha", Failing: 1},
		{Name: "Bravo", Failing: 1},
	}
	got := buildNarrative(s, domains, nil)
	want := "50% compliant — 2 of 4 tested controls are passing. 2 control(s) are failing, most concentrated in Alpha (1 of 2)."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildNarrative_TechniqueTieBreaksByID(t *testing.T) {
	s := ComplianceSummary{TestedControls: 4, PassingControls: 2, FailingControls: 2, CompliancePercent: 50}
	controls := []ControlResult{
		{Evidence: []TechniqueEvidence{
			{TechniqueID: "T2000", TechniqueName: "Zeta Technique", Result: "fail"},
			{TechniqueID: "T1000", TechniqueName: "Alpha Technique", Result: "fail"},
		}},
	}
	got := buildNarrative(s, nil, controls)
	want := "50% compliant — 2 of 4 tested controls are passing. 2 control(s) are failing. The most common failing technique is Alpha Technique (T1000)."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
