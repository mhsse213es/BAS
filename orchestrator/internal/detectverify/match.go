package detectverify

import (
	"encoding/json"
	"strings"
	"time"
)

// normalizedAlert is the vendor-agnostic shape a connector reduces its raw
// query response into before matchAlerts decides a verdict. Each connector
// (sentinel.go, defenderxdr.go) does its own parsing but produces this.
type normalizedAlert struct {
	AlertID          string
	RuleName         string
	Timestamp        time.Time
	Severity         string
	Techniques       []string // ATT&CK technique IDs tagged on the alert, if any
	InvestigationURL string
	RawJSON          json.RawMessage
}

// matchAlerts decides Detected/NotDetected and confidence from the alerts a
// connector already scoped to the request's host + time window (that scoping
// happens in the connector's query itself — this function only judges
// technique-tag confidence and picks the earliest matching alert).
//
// High confidence: the earliest alert tagged with the requested technique.
// Medium confidence: no alert carries a technique tag (older/custom rules
// often don't), so the earliest alert of any kind is used instead.
func matchAlerts(req VerifyRequest, alerts []normalizedAlert) VerifyResult {
	if len(alerts) == 0 {
		return VerifyResult{Verdict: VerdictNotDetected}
	}

	var best *normalizedAlert
	confidence := ConfidenceHigh
	for i := range alerts {
		a := &alerts[i]
		if !containsTechnique(a.Techniques, req.TechniqueID) {
			continue
		}
		if best == nil || a.Timestamp.Before(best.Timestamp) {
			best = a
		}
	}
	if best == nil {
		confidence = ConfidenceMedium
		for i := range alerts {
			a := &alerts[i]
			if best == nil || a.Timestamp.Before(best.Timestamp) {
				best = a
			}
		}
	}

	matched := make([]MatchedAlert, 0, len(alerts))
	for _, a := range alerts {
		matched = append(matched, MatchedAlert{
			AlertID: a.AlertID, RuleName: a.RuleName, Timestamp: a.Timestamp,
			Severity: a.Severity, RawJSON: a.RawJSON,
		})
	}

	return VerifyResult{
		Verdict:          VerdictDetected,
		Confidence:       confidence,
		MatchedAlerts:    matched,
		DetectionLatency: best.Timestamp.Sub(req.StepExecutedAt),
		InvestigationURL: best.InvestigationURL,
	}
}

func containsTechnique(techniques []string, want string) bool {
	if want == "" {
		return false
	}
	for _, t := range techniques {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}
