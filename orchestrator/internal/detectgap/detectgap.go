// Package detectgap classifies what happened to each technique in a run, from evidence only, and says whether the
// rule library has a rule that could close a gap.
//
// A "detection gap" is a strong claim: the attack ran to completion and a reviewed check found no alert. It is never
// inferred from silence. A technique nobody verified is Unknown, an engine failure is an Execution error, and a
// technique a control blocked produced nothing alertable. Separately, a rule being available says nothing about
// whether it would detect the attack: that is never validated here and is always reported as such.
package detectgap

import (
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/verification"
)

type Status string

const (
	Detected       Status = "Detected"
	DetectionGap   Status = "Detection gap"
	ExecutionError Status = "Execution error"
	Skipped        Status = "Skipped"
	Unknown        Status = "Unknown"
)

// Rule availability labels. They describe the library, not the rule's effectiveness.
const (
	RuleAvailable                 = "Rule available"
	NoRuleAvailable               = "No rule available"
	BackendTranslationUnavailable = "Backend translation unavailable"
)

// Effectiveness is constant on purpose: no rule has been tested against real telemetry, so the product must not
// imply one would catch the attack.
const Effectiveness = "Not validated"

// Attestation is one analyst or connector verdict about a technique in a run.
type Attestation struct {
	Result string // verification.Result*
	State  string // verification.State*
}

// Technique is everything known about one technique in one run.
type Technique struct {
	TechniqueID  string
	Outcomes     map[models.CheckResult]int // how many steps ended in each result
	Attestations []Attestation
}

type Classification struct {
	Status Status `json:"status"`
	Reason string `json:"reason"`
}

// Classify applies the evidence rules. Only an Approved attestation counts: Pending, NeedsReview and Rejected are
// unresolved.
func Classify(t Technique) Classification {
	var detected, missed, notApplicable, unresolved bool
	for _, a := range t.Attestations {
		if a.State != verification.StateApproved {
			unresolved = true
			continue
		}
		switch a.Result {
		case verification.ResultDetected:
			detected = true
		case verification.ResultNotDetected:
			missed = true
		case verification.ResultNotApplicable:
			notApplicable = true
		}
	}
	executed := t.Outcomes[models.ResultFail] > 0
	blocked := t.Outcomes[models.ResultBlocked] + t.Outcomes[models.ResultPass]

	switch {
	case detected:
		return Classification{Detected, "A reviewed verification found an alert for this technique."}
	case executed && missed:
		return Classification{DetectionGap, "The technique ran to completion and a reviewed verification found no alert."}
	case executed && notApplicable:
		return Classification{Unknown, "A reviewer marked detection not applicable for this technique."}
	case executed && unresolved:
		return Classification{Unknown, "The technique ran, and the detection verification is still awaiting review."}
	case executed:
		return Classification{Unknown, "The technique ran, but no detection verification was recorded."}
	case blocked > 0:
		return Classification{Unknown, "A control blocked the technique, so nothing alertable happened to detect."}
	case t.Outcomes[models.ResultError] > 0:
		return Classification{ExecutionError, "The engine could not execute the technique correctly, so detection was not tested."}
	case t.Outcomes[models.ResultSkipped] > 0:
		return Classification{Skipped, "The technique was skipped, so detection was not tested."}
	}
	return Classification{Unknown, "No result was recorded for this technique."}
}

// Availability labels the rules found for a technique. backend "" asks only whether any rule with any translation
// exists; otherwise at least one rule must translate to that backend.
func Availability(rules []rulelib.Rule, backend string) string {
	if len(rules) == 0 {
		return NoRuleAvailable
	}
	for _, r := range rules {
		for _, tr := range r.Translations {
			if backend == "" || tr.Backend == backend {
				return RuleAvailable
			}
		}
	}
	return BackendTranslationUnavailable
}
