package wafdetection

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// AlertScenario is the claim that the alerting pipeline correctly
// reflects an already-derived claim verdict: an alert exists when (and
// only when) one was warranted.
type AlertScenario struct {
	ID          string
	Description string
	Provenance  string
}

// NewAlertScenario validates at construction time, never at render time.
func NewAlertScenario(id string, description string, provenance string) (AlertScenario, error) {
	if id == "" {
		return AlertScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return AlertScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return AlertScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return AlertScenario{ID: id, Description: description, Provenance: provenance}, nil
}

// AlertVerdict is the outcome of comparing an already-derived claim
// verdict against whether an alert actually exists for it.
type AlertVerdict string

const (
	AlertCorrect      AlertVerdict = "correct"
	AlertMissing      AlertVerdict = "missing"
	AlertSpurious     AlertVerdict = "spurious"
	AlertInconclusive AlertVerdict = "inconclusive"
)

// alertWarranted reports whether the underlying verdict is one that
// should have produced an alert: the WAF actually enforced a block or
// recognized the request (Blocked, DetectedButAllowed). A Missed verdict
// means nothing was even detected -- that is a detection-pipeline gap,
// not an alerting-pipeline failure, so it is deliberately not warranted
// here; neither is Allowed (nothing to alert on) or IncorrectlyBlocked
// (a false-positive claim, out of this scenario's scope).
func alertWarranted(v wafval.Verdict) bool {
	return v == wafval.VerdictBlocked || v == wafval.VerdictDetectedButAllowed
}

// EvaluateAlertCorrelation takes underlyingVerdict as a bare input --
// already computed elsewhere, by whatever claim-evaluating phase
// produced it -- and never re-derives one. An incomplete/unavailable
// search is never conflated with a confirmed absence: only
// CoverageSearchedVerifiedNone counts as a verified absence.
func EvaluateAlertCorrelation(underlyingVerdict wafval.Verdict, alertEvidence wafval.CollectionResult) (AlertVerdict, string, error) {
	warranted := alertWarranted(underlyingVerdict)
	hasAlert := alertEvidence.Coverage == wafval.CoverageFound && len(alertEvidence.Observations) > 0
	verifiedAbsent := alertEvidence.Coverage == wafval.CoverageSearchedVerifiedNone

	switch {
	case warranted && hasAlert:
		return AlertCorrect, "alert correctly generated for a detected/blocked request", nil
	case warranted && verifiedAbsent:
		return AlertMissing, "request was blocked/detected but no alert was found despite a verified-complete search", nil
	case warranted && !hasAlert && !verifiedAbsent:
		return AlertInconclusive, "alert-channel search was incomplete or unavailable; cannot confirm whether an alert exists", nil
	case !warranted && hasAlert:
		return AlertSpurious, "an alert was generated for a request that was neither blocked nor detected", nil
	default:
		return AlertCorrect, "no alert generated, correctly, for a request that did not warrant one", nil
	}
}
