package compliance

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// The control status is derived from technique-level evidence. The raw execution results are never changed.
//
//	resisted     every mapped technique ran, none succeeded
//	failed       at least one executed technique succeeded (wins over everything else)
//	partial      some, not all, mapped techniques ran, none succeeded
//	inconclusive nothing ran cleanly but something errored or was vetoed
//	untested     nothing ran at all
//	manual       cannot be tested by running techniques

func synthMapper() *Mapper {
	no := false
	return &Mapper{frameworks: map[string]*FrameworkDef{
		"SYN": {
			FrameworkMeta: FrameworkMeta{ID: "SYN", Name: "Synthetic"},
			Controls: []ControlDef{
				{ID: "A", Domain: "D1", Techniques: []string{"T1001", "T1002", "T1003"}},
				{ID: "B", Domain: "D1", Techniques: []string{"T1110"}},
				{ID: "C", Domain: "D2", Techniques: []string{"T1003", "T1003.001"}},
				{ID: "M", Domain: "D2", Techniques: []string{"T1999"}, Testable: &no},
				{ID: "DUP", Domain: "D2", Techniques: []string{"T2001", "t2001", " T2001 "}},
			},
		},
	}}
}

func res(id string, kind models.CheckResult) models.SimulationResult {
	return models.SimulationResult{ID: id + "-" + string(kind), Technique: models.AttackTechnique{ID: id}, Result: kind}
}

func report(t *testing.T, results ...models.SimulationResult) *ComplianceReport {
	t.Helper()
	rep, err := synthMapper().GenerateReport(results, "SYN", "agent", "run", "scenario")
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func control(t *testing.T, rep *ComplianceReport, id string) ControlResult {
	t.Helper()
	for _, c := range rep.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s not in report", id)
	return ControlResult{}
}

func TestControlStatus_ResistedNeedsEveryMappedTechniqueToHaveRun(t *testing.T) {
	c := control(t, report(t, res("T1001", models.ResultPass), res("T1002", models.ResultBlocked), res("T1003", models.ResultPass)), "A")
	if c.Status != "resisted" || c.TechniquesMapped != 3 || c.TechniquesTested != 3 {
		t.Fatalf("got %s %d/%d, want resisted 3/3", c.Status, c.TechniquesTested, c.TechniquesMapped)
	}
}

func TestControlStatus_SomeTechniquesRunIsPartialNotCompliant(t *testing.T) {
	c := control(t, report(t, res("T1001", models.ResultPass), res("T1002", models.ResultBlocked)), "A")
	if c.Status != "partial" || c.TechniquesTested != 2 || c.TechniquesMapped != 3 {
		t.Fatalf("got %s %d/%d, want partial 2/3", c.Status, c.TechniquesTested, c.TechniquesMapped)
	}
}

func TestControlStatus_OneSurvivingTechniqueOutranksUntestedAndPassing(t *testing.T) {
	c := control(t, report(t, res("T1001", models.ResultFail)), "A")
	if c.Status != "failed" || c.TechniquesFailed != 1 || c.TechniquesTested != 1 {
		t.Fatalf("got %s failed=%d tested=%d, want failed 1/1", c.Status, c.TechniquesFailed, c.TechniquesTested)
	}
	c = control(t, report(t, res("T1001", models.ResultPass), res("T1002", models.ResultPass), res("T1003", models.ResultFail)), "A")
	if c.Status != "failed" {
		t.Fatalf("2 resisted + 1 failed = %s, want failed", c.Status)
	}
}

func TestControlStatus_ATechniqueThatBothSucceededAndWasBlockedHasFailed(t *testing.T) {
	c := control(t, report(t, res("T1110", models.ResultBlocked), res("T1110", models.ResultFail)), "B")
	if c.Status != "failed" {
		t.Fatalf("got %s, want failed: one run of the technique got through", c.Status)
	}
}

func TestControlStatus_ErrorsAndVetoesAreInconclusiveNotUntestedAndNotResisted(t *testing.T) {
	c := control(t, report(t, res("T1001", models.ResultError), res("T1002", models.ResultVetoed)), "A")
	if c.Status != "inconclusive" || c.TechniquesTested != 0 || c.TechniquesInconclusive != 2 {
		t.Fatalf("got %s tested=%d inconclusive=%d, want inconclusive 0/2", c.Status, c.TechniquesTested, c.TechniquesInconclusive)
	}
}

func TestControlStatus_AnErroredTechniqueDoesNotHideWhatDidRun(t *testing.T) {
	c := control(t, report(t, res("T1001", models.ResultPass), res("T1002", models.ResultError)), "A")
	if c.Status != "partial" || c.TechniquesTested != 1 || c.TechniquesInconclusive != 1 {
		t.Fatalf("got %s tested=%d inconclusive=%d, want partial 1 tested 1 inconclusive", c.Status, c.TechniquesTested, c.TechniquesInconclusive)
	}
}

func TestControlStatus_NothingRunIsUntestedAndSkippedCountsAsNothing(t *testing.T) {
	if c := control(t, report(t), "A"); c.Status != "untested" {
		t.Fatalf("no results: %s, want untested", c.Status)
	}
	if c := control(t, report(t, res("T1001", models.ResultSkipped)), "A"); c.Status != "untested" {
		t.Fatalf("skipped only: %s, want untested", c.Status)
	}
	if c := control(t, report(t, res("T7777", models.ResultPass)), "A"); c.Status != "untested" {
		t.Fatalf("an unrelated technique: %s, want untested", c.Status)
	}
}

func TestControlStatus_ManualIsNeverScored(t *testing.T) {
	c := control(t, report(t, res("T1999", models.ResultFail)), "M")
	if c.Status != "manual" || c.TechniquesMapped != 0 {
		t.Fatalf("got %s mapped=%d, want manual with nothing mapped for scoring", c.Status, c.TechniquesMapped)
	}
}

func TestControlStatus_BaseTechniqueCountsItsSubTechniquesButASubTechniqueNeedsItself(t *testing.T) {
	// C maps T1003 and T1003.001. A run of T1003.002 covers the base T1003 but not T1003.001.
	c := control(t, report(t, res("T1003.002", models.ResultPass)), "C")
	if c.Status != "partial" || c.TechniquesTested != 1 || c.TechniquesMapped != 2 {
		t.Fatalf("got %s %d/%d, want partial 1/2", c.Status, c.TechniquesTested, c.TechniquesMapped)
	}
	c = control(t, report(t, res("T1003.001", models.ResultPass)), "C")
	if c.Status != "resisted" || c.TechniquesTested != 2 {
		t.Fatalf("got %s tested=%d, want resisted 2/2: T1003.001 covers itself and the base", c.Status, c.TechniquesTested)
	}
}

func TestControlStatus_ATechniqueListedTwiceIsCountedOnce(t *testing.T) {
	c := control(t, report(t, res("T2001", models.ResultPass)), "DUP")
	if c.TechniquesMapped != 1 || c.Status != "resisted" {
		t.Fatalf("got %s mapped=%d, want resisted with 1 mapped technique", c.Status, c.TechniquesMapped)
	}
}

func TestControlCoverage_ListsEveryMappedTechniqueWithItsState(t *testing.T) {
	c := control(t, report(t, res("T1001", models.ResultPass), res("T1002", models.ResultFail), res("T1003", models.ResultError)), "A")
	got := map[string]string{}
	for _, tc := range c.TechniqueCoverage {
		got[tc.ID] = tc.State
	}
	want := map[string]string{"T1001": "resisted", "T1002": "failed", "T1003": "inconclusive"}
	if len(got) != 3 || got["T1001"] != want["T1001"] || got["T1002"] != want["T1002"] || got["T1003"] != want["T1003"] {
		t.Fatalf("technique coverage = %v, want %v", got, want)
	}
}

// One resisted control out of four testable is 25% coverage: the rate must never be shown without it.
func TestSummary_ResistanceRateAlwaysComesWithCoverage(t *testing.T) {
	rep := report(t, res("T1110", models.ResultPass)) // control B only
	s := rep.Summary
	if s.TestableControls != 4 || s.TestedControls != 1 || s.ResistedControls != 1 {
		t.Fatalf("testable=%d tested=%d resisted=%d, want 4/1/1", s.TestableControls, s.TestedControls, s.ResistedControls)
	}
	if s.CompliancePercent != 100 {
		t.Errorf("resistance rate = %v, want 100 (1 of 1 tested controls)", s.CompliancePercent)
	}
	if s.CoveragePercent != 25 {
		t.Errorf("control coverage = %v, want 25", s.CoveragePercent)
	}
	if s.SufficientCoverage {
		t.Error("25% coverage was called sufficient for framework-level conclusions")
	}
	if !strings.Contains(s.CoverageNote, "Insufficient coverage") {
		t.Errorf("coverage note = %q, want it to say coverage is insufficient", s.CoverageNote)
	}
}

func TestSummary_CountsEveryStatusAndTechniqueCoverage(t *testing.T) {
	rep := report(t,
		res("T1001", models.ResultPass), res("T1002", models.ResultPass), res("T1003", models.ResultPass), // A: resisted
		res("T1110", models.ResultFail),  // B: failed
		res("T2001", models.ResultError), // DUP: inconclusive
	) // C maps T1003 (covered by A's run) and T1003.001 (not run): partial. M is manual.
	s := rep.Summary
	if s.ResistedControls != 1 || s.FailingControls != 1 || s.PartialControls != 1 || s.InconclusiveControls != 1 {
		t.Fatalf("resisted=%d failed=%d partial=%d inconclusive=%d, want 1 each", s.ResistedControls, s.FailingControls, s.PartialControls, s.InconclusiveControls)
	}
	// Legacy counts keep their meaning: tested = ran and gave a result; passing = tested with nothing getting through.
	if s.TestedControls != 3 || s.PassingControls != 2 || s.UntestedControls != 1 || s.TestableControls != 4 {
		t.Fatalf("legacy tested=%d passing=%d untested=%d testable=%d, want 3/2/1/4", s.TestedControls, s.PassingControls, s.UntestedControls, s.TestableControls)
	}
	// Mapped techniques per control: A=3, B=1, C=2, DUP=1. Tested: A=3, B=1, C=1.
	if s.TechniquesMapped != 7 || s.TechniquesTested != 5 {
		t.Fatalf("techniques tested/mapped = %d/%d, want 5/7", s.TechniquesTested, s.TechniquesMapped)
	}
	if s.TechniqueCoveragePercent != round2(5.0/7.0*100) {
		t.Fatalf("technique coverage = %v, want %v", s.TechniqueCoveragePercent, round2(5.0/7.0*100))
	}
}

func TestSummary_PartialControlsCountAsTestedWithNoFailure(t *testing.T) {
	s := report(t, res("T1001", models.ResultPass)).Summary
	if s.PartialControls != 1 || s.TestedControls != 1 || s.PassingControls != 1 || s.ResistedControls != 0 {
		t.Fatalf("partial=%d tested=%d passing=%d resisted=%d, want 1/1/1/0", s.PartialControls, s.TestedControls, s.PassingControls, s.ResistedControls)
	}
}

func TestSummary_EnoughCoverageIsCalledSufficientOnlyAtTheThreshold(t *testing.T) {
	// 2 of 4 testable controls tested = 50% = the threshold.
	s := report(t, res("T1110", models.ResultPass), res("T2001", models.ResultPass)).Summary
	if s.CoveragePercent != 50 || !s.SufficientCoverage || s.CoverageNote != "" {
		t.Fatalf("coverage %v sufficient=%v note=%q, want 50 / true / empty", s.CoveragePercent, s.SufficientCoverage, s.CoverageNote)
	}
}

func TestNarrative_NeverSaysCompliantAndAlwaysStatesCoverage(t *testing.T) {
	rep := report(t, res("T1110", models.ResultPass))
	n := rep.Narrative
	if strings.Contains(strings.ToLower(n), "compliant") {
		t.Errorf("narrative calls the result compliant: %q", n)
	}
	for _, want := range []string{"Resistance rate 100%", "1 of 1 tested controls", "Control coverage 1 of 4", "25.0%", "Insufficient coverage for framework-level conclusions"} {
		if !strings.Contains(n, want) {
			t.Errorf("narrative %q lacks %q", n, want)
		}
	}
}

func TestNarrative_NothingTestedKeepsTheOldMessage(t *testing.T) {
	if got := report(t).Narrative; got != "No controls have been tested yet — run a scenario to generate compliance evidence." {
		t.Fatalf("got %q", got)
	}
}

// RBI's technique links are Audspect's own judgement, so the note must travel with the framework
// and must not appear on frameworks that have no such caveat.
func TestMappingWarning_RBICarriesItsCaveatAndOthersDoNot(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	for _, fw := range m.Frameworks() {
		if fw.ID == "RBI_CSF" {
			if !strings.Contains(fw.MappingWarning, "own judgement") {
				t.Errorf("RBI_CSF mapping warning = %q, want it to say the technique links are our own judgement", fw.MappingWarning)
			}
			continue
		}
		if fw.MappingWarning != "" {
			t.Errorf("%s carries a mapping warning it was not given: %q", fw.ID, fw.MappingWarning)
		}
	}
	rep, err := m.GenerateReport(nil, "RBI_CSF", "a", "r", "s")
	if err != nil || rep.Framework.MappingWarning == "" {
		t.Fatalf("a generated RBI report must carry the warning (err=%v)", err)
	}
}

// Every RBI control cites the paragraph of the 2026 directions it comes from, and the figures the directions do not
// state (patch windows, log retention, algorithms, products) are not asserted in a control name.
func TestRBIControlsCiteTheDirectionsAndAssertNoInventedFigures(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatal(err)
	}
	fw := m.frameworks["RBI_CSF"]
	if fw == nil {
		t.Fatal("RBI_CSF not loaded")
	}
	banned := []string{"30 days", "7 days", "180 days", "AES-256", "TLS 1.2", "SAST", "DAST", "immutable", "session recording"}
	for _, c := range fw.Controls {
		if !strings.Contains(c.Reference, "¶") {
			t.Errorf("%s has no paragraph reference (got %q)", c.ID, c.Reference)
		}
		for _, b := range banned {
			if strings.Contains(c.Name, b) {
				t.Errorf("%s asserts %q, which the directions do not state: %s", c.ID, b, c.Name)
			}
		}
	}
	rep, err := m.GenerateReport(nil, "RBI_CSF", "a", "r", "s")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Controls {
		if c.Reference == "" {
			t.Errorf("%s: the reference does not reach the report", c.ID)
		}
	}
}
