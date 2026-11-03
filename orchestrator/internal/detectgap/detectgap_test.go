package detectgap

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/verification"
)

func approved(result string) Attestation {
	return Attestation{Result: result, State: verification.StateApproved}
}

func tech(outcomes map[models.CheckResult]int, atts ...Attestation) Technique {
	return Technique{TechniqueID: "T1059.001", Outcomes: outcomes, Attestations: atts}
}

func TestClassify_OnlyReviewedEvidenceMakesADetectionGapOrADetection(t *testing.T) {
	ran := map[models.CheckResult]int{models.ResultFail: 1}
	cases := []struct {
		name string
		in   Technique
		want Status
	}{
		{"executed and a reviewed verification found an alert", tech(ran, approved(verification.ResultDetected)), Detected},
		{"executed and a reviewed verification found no alert", tech(ran, approved(verification.ResultNotDetected)), DetectionGap},
		{"executed, nobody verified", tech(ran), Unknown},
		{"executed, a not-detected verdict still awaiting review is not a gap yet",
			tech(ran, Attestation{Result: verification.ResultNotDetected, State: verification.StatePending}), Unknown},
		{"executed, a rejected not-detected verdict is not a gap",
			tech(ran, Attestation{Result: verification.ResultNotDetected, State: verification.StateRejected}), Unknown},
		{"executed, analyst marked it not applicable", tech(ran, approved(verification.ResultNotApplicable)), Unknown},
		{"any reviewed detection wins over a reviewed miss", tech(ran, approved(verification.ResultNotDetected), approved(verification.ResultDetected)), Detected},
		{"engine could not execute it", tech(map[models.CheckResult]int{models.ResultError: 1}, approved(verification.ResultNotDetected)), ExecutionError},
		{"skipped", tech(map[models.CheckResult]int{models.ResultSkipped: 2}), Skipped},
		{"blocked by a control: nothing alertable happened, so no gap even if no alert",
			tech(map[models.CheckResult]int{models.ResultBlocked: 1}, approved(verification.ResultNotDetected)), Unknown},
		{"one atomic failed to execute but another ran and was missed",
			tech(map[models.CheckResult]int{models.ResultError: 1, models.ResultFail: 1}, approved(verification.ResultNotDetected)), DetectionGap},
	}
	for _, c := range cases {
		if got := Classify(c.in); got.Status != c.want || got.Reason == "" {
			t.Errorf("%s: got %q (reason %q), want %q with a reason", c.name, got.Status, got.Reason, c.want)
		}
	}
}

func rule(id string, backends ...string) rulelib.Rule {
	r := rulelib.Rule{ID: id}
	for _, b := range backends {
		r.Translations = append(r.Translations, rulelib.Translation{Backend: b})
	}
	return r
}

func TestAvailability_SaysWhetherARuleAndATranslationExistNeverWhetherItWorks(t *testing.T) {
	if got := Availability(nil, ""); got != NoRuleAvailable {
		t.Errorf("no rules = %q", got)
	}
	rules := []rulelib.Rule{rule("A", "splunk"), rule("B", "elastic")}
	if got := Availability(rules, ""); got != RuleAvailable {
		t.Errorf("rules with translations, no backend asked = %q", got)
	}
	if got := Availability(rules, "splunk"); got != RuleAvailable {
		t.Errorf("a rule translates to splunk = %q", got)
	}
	if got := Availability(rules, "crowdstrike"); got != BackendTranslationUnavailable {
		t.Errorf("rules exist but none translates to crowdstrike = %q", got)
	}
	if got := Availability([]rulelib.Rule{rule("C")}, ""); got != BackendTranslationUnavailable {
		t.Errorf("a rule with no translation at all = %q", got)
	}
	if Effectiveness != "Not validated" {
		t.Errorf("effectiveness must say rules are not validated against telemetry, got %q", Effectiveness)
	}
}

func result(tech string, r models.CheckResult) models.SimulationResult {
	return models.SimulationResult{Technique: models.AttackTechnique{ID: tech, Name: "name " + tech}, Result: r}
}

// Assess is the single place a run's results and reviewed verifications become per-technique assessments, so the
// console, the export and the report cannot disagree.
func TestAssess_GroupsStepsByTechniqueAndClassifiesFromEvidence(t *testing.T) {
	results := []models.SimulationResult{
		result("T1059.001", models.ResultFail),
		result("", models.ResultFail), // a posture check, not a technique
		result("T1003", models.ResultError),
		result("T1059.001", models.ResultBlocked),
		result("T1070", models.ResultSkipped),
	}
	records := map[string]verification.Record{
		"exp1": {TechniqueID: "T1059.001", Result: verification.ResultNotDetected, WorkflowState: verification.StateApproved},
		"exp2": {TechniqueID: "T1059.001", Result: verification.ResultDetected, WorkflowState: verification.StatePending},
		"exp3": {TechniqueID: "T9999", Result: verification.ResultNotDetected, WorkflowState: verification.StateApproved}, // not in this run
	}
	got := Assess(results, records)
	if len(got) != 3 {
		t.Fatalf("got %d assessments, want 3 (one per technique, none for the posture check): %+v", len(got), got)
	}
	if got[0].TechniqueID != "T1059.001" || got[1].TechniqueID != "T1003" || got[2].TechniqueID != "T1070" {
		t.Errorf("order must follow first appearance in the run: %+v", got)
	}
	first := got[0]
	if first.Status != DetectionGap || first.Name != "name T1059.001" || first.Steps["fail"] != 1 || first.Steps["blocked"] != 1 {
		t.Errorf("T1059.001 = %+v, want a gap (the pending detection is unresolved) with both steps counted", first)
	}
	if got[1].Status != ExecutionError || got[2].Status != Skipped {
		t.Errorf("statuses = %q, %q", got[1].Status, got[2].Status)
	}
}

func TestAssess_NoResultsIsEmpty(t *testing.T) {
	if got := Assess(nil, nil); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

func ruleSev(id, sev string, backends ...string) rulelib.Rule {
	r := rule(id, backends...)
	r.Severity = sev
	return r
}

func TestPickRules_SeverityThenIDLimitedAndOnlyRulesThatTranslateToTheAskedSIEM(t *testing.T) {
	rules := []rulelib.Rule{
		ruleSev("AUDRULE-000005", "low", "splunk"),
		ruleSev("AUDRULE-000003", "high", "splunk", "elastic"),
		ruleSev("AUDRULE-000002", "critical", "elastic"),
		ruleSev("AUDRULE-000004", "high", "splunk"),
	}
	ids := func(rs []rulelib.Rule) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	got := ids(PickRules(rules, "", 3))
	if len(got) != 3 || got[0] != "AUDRULE-000002" || got[1] != "AUDRULE-000003" || got[2] != "AUDRULE-000004" {
		t.Errorf("severity then id, limited: %v", got)
	}
	if got := ids(PickRules(rules, "splunk", 10)); len(got) != 3 || got[0] != "AUDRULE-000003" {
		t.Errorf("a rule with no splunk translation must not be offered for splunk: %v", got)
	}
	if len(rules) != 4 || rules[0].ID != "AUDRULE-000005" {
		t.Error("PickRules reordered the caller's slice")
	}
}

func TestBackendLabelAndQueryNote(t *testing.T) {
	if BackendLabel("qradar") != "IBM QRadar" || BackendLabel("microsoft_sentinel") != "Microsoft Sentinel" || BackendLabel("x") != "x" {
		t.Error("backend labels")
	}
	mapped := QueryNote("pipeline", "Sysmon event 1")
	if !strings.Contains(mapped, "only matches if") || !strings.Contains(mapped, "Sysmon event 1") {
		t.Errorf("mapped note = %q", mapped)
	}
	generic := QueryNote("generic", "")
	if !strings.Contains(strings.ToLower(generic), "adapt") || strings.Contains(generic, "only matches if") {
		t.Errorf("generic note = %q", generic)
	}
}

func asmt(s Status) *Assessment {
	return &Assessment{TechniqueID: "T1059.001", Classification: Classification{Status: s, Reason: "r"}}
}

// A deployment is only "closed" by a reviewed detection on a re-test that actually ran the technique. Anything less
// stays open or unproven; nothing is inferred from the rule having been deployed.
func TestDeploymentStatus(t *testing.T) {
	cases := []struct {
		name             string
		linked, finished bool
		retest           *Assessment
		want             string
	}{
		{"deployed, no re-test yet", false, false, nil, DeploymentDeployed},
		{"re-test linked but the run is still going", true, false, nil, DeploymentRetestRunning},
		{"re-test finished, reviewed detection", true, true, asmt(Detected), DeploymentClosed},
		{"re-test finished, reviewed miss again", true, true, asmt(DetectionGap), DeploymentStillGap},
		{"re-test finished, nobody has verified it", true, true, asmt(Unknown), DeploymentAwaitingVerification},
		{"re-test finished, technique errored", true, true, asmt(ExecutionError), DeploymentNotRetested},
		{"re-test finished, technique skipped", true, true, asmt(Skipped), DeploymentNotRetested},
		{"re-test finished, technique absent from it", true, true, nil, DeploymentNotRetested},
	}
	for _, c := range cases {
		got, detail := DeploymentStatus(c.linked, c.finished, c.retest)
		if got != c.want || detail == "" {
			t.Errorf("%s: got %q (detail %q), want %q with a detail", c.name, got, detail, c.want)
		}
	}
	_, closed := DeploymentStatus(true, true, asmt(Detected))
	if !strings.Contains(closed, "does not confirm") {
		t.Errorf("a closed deployment must say Audspect does not confirm which rule fired: %q", closed)
	}
}
