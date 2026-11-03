package detectgap

import (
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
