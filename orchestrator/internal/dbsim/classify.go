package dbsim

import (
	"strings"

	"github.com/audspect/bas/internal/dlpreport"
)

// Rule names of the lab detection rules (lab/dbsim/elastic/*.json "name"). The
// generic rule fires for ANY statement that begins with the dbsim marker, so it
// says nothing about classification (ruling R-AM); the classification rule fires
// only for statements touching the classified fixture table. They are policy
// data: a deployment names its own classification rule in
// dbrun.StepInput.ClassificationRuleName.
const (
	GenericMarkerRuleName     = "BAS dbsim marker in database audit event"
	LabClassificationRuleName = "BAS dbsim classified-fixture read"
)

// ClassifyByRule is the DB-07 verdict (ruling R-AM). It judges only whether the
// CLASSIFICATION-SPECIFIC rule named by rule fired for this probe's marker.
// correlatedRules are the rule names of the alerts the correlator attributed to
// this probe (exact or strong marker match); o must carry the correlation.
//
//	Correct        a marker-correlated alert came from the classification rule.
//	Incorrect      the read was allowed, the SIEM provably saw the statement
//	               (on-time, marker-correlated telemetry) and no alert came from
//	               the classification rule.
//	Unknown        telemetry is unverifiable, absent, delayed or ambiguous:
//	               missing evidence is never read as a miss.
//	NotEvaluated   no rule is configured (or it is the generic marker rule), the
//	               read did not complete, or it was denied (nothing was read).
//
// hiddenStrong is the number of strong-contextual alerts the correlator set aside
// because exact-marker alerts existed. The second return value is a limitation
// sentence for the report.
func ClassifyByRule(rule string, o Outcome, correlatedRules []string, hiddenStrong int) (dlpreport.ClassificationOutcome, string) {
	rule = strings.TrimSpace(rule)
	switch {
	case rule == "":
		return dlpreport.ClassificationNotEvaluated, "Classification not evaluated: no classification rule is configured (ClassificationRuleName is empty), so a rule-specific verdict is impossible; a generic marker alert cannot stand in for one."
	case strings.EqualFold(rule, GenericMarkerRuleName):
		return dlpreport.ClassificationNotEvaluated, "Classification not evaluated: the configured classification rule is the generic marker rule, which fires for any marker statement and therefore cannot classify."
	case !ProbeCompleted(o) || o.Probe.Denied:
		return dlpreport.ClassificationNotEvaluated, "Classification not evaluated: the read did not complete or was denied, so no classified data was read."
	case !o.Corr.Evaluated:
		return dlpreport.ClassificationUnknown, "Classification unknown: no detection telemetry was correlated, so a silent classification rule cannot be told from a missing alert pipeline."
	}
	// Rule identity is compared case-exactly. A name that differs only in case or
	// surrounding space is a misconfiguration, an empty name cannot be attributed,
	// and strong-contextual alerts hidden behind exact ones may have held the
	// classification alert: none of those is a control failure, so none is Incorrect.
	exact, near, empty := false, false, false
	for _, r := range correlatedRules {
		switch {
		case r == rule:
			exact = true
		case strings.TrimSpace(r) == "":
			empty = true
		case strings.EqualFold(strings.TrimSpace(r), rule):
			near = true
		}
	}
	if exact && (o.Corr.Match == MatchExactMarker || o.Corr.Match == MatchStrongContextual) {
		// A rule-identity verdict: also granted when telemetry is Delayed (the
		// rule did fire for this marker; latency is graded by the detection
		// dimension, not here).
		return dlpreport.ClassificationCorrect, "Classification correct: the classification rule raised an alert correlated to this probe's marker."
	}
	if empty || near || hiddenStrong > 0 {
		return dlpreport.ClassificationUnknown, "Classification unknown: the correlated alerts cannot rule out the classification rule (an alert without a rule name, a rule name differing only in case or spacing from the configured one, or strong-contextual alerts set aside behind exact-marker ones)."
	}
	if o.Corr.Telemetry == dlpreport.TelemetryPresent && (o.Corr.Match == MatchExactMarker || o.Corr.Match == MatchStrongContextual) {
		return dlpreport.ClassificationIncorrect, "Classification incorrect: the read was allowed and the SIEM raised marker-correlated alerts for it, but none came from the classification rule."
	}
	return dlpreport.ClassificationUnknown, "Classification unknown: detection telemetry for this read was not verifiably present (absent, delayed, ambiguous or unverifiable), so the silence of the classification rule proves nothing."
}
