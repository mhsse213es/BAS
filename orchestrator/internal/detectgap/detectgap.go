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
	"sort"
	"strings"
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

// Assessment is one technique's outcome in one run.
type Assessment struct {
	TechniqueID string
	Name        string
	Steps       map[string]int // steps by result: fail, pass, blocked, error, skipped
	Classification
}

// Assess groups a run's step results by ATT&CK technique and classifies each from the run's reviewed verifications
// (keyed by expectation id, as the Verification Store returns them). A result with no technique id is a posture check
// and is left out. Techniques come back in the order they first appear in the run.
func Assess(results []models.SimulationResult, current map[string]verification.Record) []Assessment {
	byTech := map[string]*Technique{}
	names := map[string]string{}
	var order []string
	for _, res := range results {
		id := res.Technique.ID
		if id == "" {
			continue
		}
		t := byTech[id]
		if t == nil {
			t = &Technique{TechniqueID: id, Outcomes: map[models.CheckResult]int{}}
			byTech[id] = t
			names[id] = res.Technique.Name
			order = append(order, id)
		}
		t.Outcomes[res.Result]++
	}
	for _, rec := range current {
		if t := byTech[rec.TechniqueID]; t != nil {
			t.Attestations = append(t.Attestations, Attestation{Result: rec.Result, State: rec.WorkflowState})
		}
	}
	out := make([]Assessment, 0, len(order))
	for _, id := range order {
		t := byTech[id]
		steps := map[string]int{}
		for k, v := range t.Outcomes {
			steps[string(k)] = v
		}
		out = append(out, Assessment{TechniqueID: id, Name: names[id], Steps: steps, Classification: Classify(*t)})
	}
	return out
}

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

// PickRules orders rules by severity then id, drops those with no translation for the requested SIEM (they are not
// offered as a fix for it; backend "" keeps all), and keeps at most limit. The caller's slice is not reordered.
func PickRules(rules []rulelib.Rule, backend string, limit int) []rulelib.Rule {
	sorted := append([]rulelib.Rule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := severityOrder[strings.ToLower(sorted[i].Severity)], severityOrder[strings.ToLower(sorted[j].Severity)]
		if a != b {
			return a < b
		}
		return sorted[i].ID < sorted[j].ID
	})
	var out []rulelib.Rule
	for _, r := range sorted {
		if backend != "" {
			has := false
			for _, t := range r.Translations {
				has = has || t.Backend == backend
			}
			if !has {
				continue
			}
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out
}

var backendLabels = map[string]string{
	"microsoft_sentinel": "Microsoft Sentinel",
	"microsoft_defender": "Microsoft Defender XDR",
	"splunk":             "Splunk",
	"qradar":             "IBM QRadar",
	"elastic":            "Elastic",
	"crowdstrike":        "CrowdStrike LogScale",
}

// BackendLabel is the SIEM's display name; an unknown key is returned as is.
func BackendLabel(key string) string {
	if l, ok := backendLabels[key]; ok {
		return l
	}
	return key
}

// How much is known about a translation. "validated" is reserved for a mapping that matched a positive and did not match
// a negative sample event; the rule-library generator never sets it by itself.
const (
	VerificationNone       = "none"       // generic: Sigma's own field names
	VerificationDocumented = "documented" // names from the product's documentation or an upstream pipeline, never run on events
	VerificationAssumed    = "assumed"    // our own assumption about the names, flagged unverified in the data-source note
	VerificationValidated  = "validated"  // matched a positive and not a negative sample event
)

// VerificationNote states how far a mapped query can be trusted. An unknown value is treated as the weakest claim.
func VerificationNote(v string) string {
	switch v {
	case VerificationValidated:
		return "Validated: it matched a sample event and did not match a negative one."
	case VerificationAssumed:
		return "The field names are our assumption; test this query on your own data before relying on it."
	default:
		return "The field names come from the product's documentation; this query has not yet been run against real events."
	}
}

// QueryNote is what to tell the reader beside a query. A field-mapped query only matches when its data source is
// collected; a generic one uses Sigma's own field names and must be adapted. It is never presented as ready to paste.
func QueryNote(mapping, dataSource, verification string) string {
	if mapping == "keyword" && dataSource != "" {
		return "Free-text search of the raw log message. " + dataSource + "."
	}
	if mapping == "pipeline" && dataSource != "" {
		return "Field-mapped. This only matches if you collect: " + dataSource + ". " + VerificationNote(verification)
	}
	return "Generic query using Sigma field names: adapt the field names and log source to your schema before use."
}

// ElasticCaseNote is shown beside an Elastic Lucene query that has an Elasticsearch DSL counterpart. Keep it in step
// with ELASTIC_CASE_NOTE in web/src/features/gap-model.js.
const ElasticCaseNote = "The Lucene query is case-sensitive on keyword fields; the Elasticsearch DSL query matches case-insensitively, as Sigma does."

// Deployment statuses: where a recommended rule stands after the customer says they deployed it.
const (
	DeploymentDeployed             = "Deployed"
	DeploymentRetestRunning        = "Re-test running"
	DeploymentClosed               = "Closed on re-test"
	DeploymentStillGap             = "Still a gap"
	DeploymentAwaitingVerification = "Re-test awaiting verification"
	DeploymentNotRetested          = "Technique not re-tested"
)

// DeploymentStatus says where a deployment stands. A deployment closes a gap only when a re-test run that executed
// the technique has a reviewed detection. That is evidence a detection exists, not that the deployed rule produced
// it, and the detail says so. Recording a deployment proves nothing about detection by itself.
func DeploymentStatus(retestLinked, retestFinished bool, retest *Assessment) (status, detail string) {
	switch {
	case !retestLinked:
		return DeploymentDeployed, "Deployment recorded. Re-run the technique and have the result reviewed to find out whether the gap is closed."
	case !retestFinished:
		return DeploymentRetestRunning, "The re-test run has not finished."
	case retest == nil:
		return DeploymentNotRetested, "The re-test run did not include this technique."
	}
	switch retest.Status {
	case Detected:
		return DeploymentClosed, "The re-test executed the technique and a reviewed verification found an alert. Audspect does not confirm that the deployed rule produced it."
	case DetectionGap:
		return DeploymentStillGap, "The re-test executed the technique and a reviewed verification again found no alert."
	case Unknown:
		return DeploymentAwaitingVerification, "The re-test executed the technique but no reviewed verification says whether an alert fired."
	}
	return DeploymentNotRetested, "The re-test did not execute the technique (" + string(retest.Status) + "), so it says nothing about detection."
}
