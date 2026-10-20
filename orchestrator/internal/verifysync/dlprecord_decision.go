package verifysync

import "github.com/audspect/bas/internal/reporting"

// dlpDecisionRuleVersion identifies the derivation below. It is stored on every
// row written by this rule set, so a later rule change cannot silently relabel
// earlier rows. Rows written before this column existed have a NULL rule_version.
const dlpDecisionRuleVersion = "dlp-decision-v1"

// Decision classes (plan §2). Only these values are written to decision_class.
const (
	decisionTP           = "TP"
	decisionTN           = "TN"
	decisionFP           = "FP"
	decisionFN           = "FN"
	decisionInconclusive = "Inconclusive"
	decisionUntested     = "Untested"
)

// deriveDecisionClass applies the approved B1 table. It returns nil (unknown)
// for an expectation the table does not cover, rather than guessing a class.
//
// With today's evidence it can never return TP or FP. A block is evidenced only
// by a missing sink receipt or a local marker, and both are Inconclusive. A
// correlated authoritative block event is not yet collected by any adapter, so
// it is not an input here. TP and FP become reachable only when such an event
// exists.
func deriveDecisionClass(expected, collection, observed string) *string {
	if expected != "Block" && expected != "Allow" {
		return nil
	}
	var class string
	switch {
	case observed == reporting.ObservationUnknown:
		// No observation: a skipped step, or a step that never ran.
		class = decisionUntested
	case collection == "sink-receipt" && observed == reporting.ObservationSucceeded:
		// A receipt confirms the transfer happened, so it was not blocked.
		if expected == "Block" {
			class = decisionFN
		} else {
			class = decisionTN
		}
	default:
		// Sink receipt absent (observed Blocked), or a self-reported local marker.
		// Neither is an authoritative event, so neither decides the outcome.
		class = decisionInconclusive
	}
	return &class
}

// evidenceSourceFor maps the collection method onto the plan's evidence_source
// values. An empty method means no observation was made.
func evidenceSourceFor(collection string) string {
	switch collection {
	case "sink-receipt", "local-marker":
		return collection
	default:
		return "none"
	}
}
