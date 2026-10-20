package api

import (
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/killchain"
)

// observationFromVerify reduces one vendor check to a killchain observation.
// The vendor call reports neither telemetry health nor window completeness, so
// neither is ever set here. The verdict engine therefore refuses to score a
// not-detected result until that evidence is supplied elsewhere.
func observationFromVerify(provider string, res detectverify.VerifyResult, err error) killchain.DetectionObservation {
	o := killchain.DetectionObservation{Provider: provider}
	if err != nil {
		o.Verdict = killchain.ObservationError
		return o
	}
	switch res.Verdict {
	case detectverify.VerdictDetected:
		o.Verdict = killchain.ObservationDetected
		if len(res.MatchedAlerts) > 0 {
			o.AlertID = res.MatchedAlerts[0].AlertID
		}
	case detectverify.VerdictNotDetected:
		o.Verdict = killchain.ObservationNotDetected
	default:
		o.Verdict = killchain.ObservationError
	}
	return o
}
