package api

import (
	"errors"
	"testing"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/killchain"
)

func TestObservationFromVerify_DetectedCarriesFirstAlert(t *testing.T) {
	res := detectverify.VerifyResult{
		Verdict:       detectverify.VerdictDetected,
		MatchedAlerts: []detectverify.MatchedAlert{{AlertID: "alert-1"}, {AlertID: "alert-2"}},
	}
	o := observationFromVerify("sentinel", res, nil)
	if o.Verdict != killchain.ObservationDetected || o.AlertID != "alert-1" || o.Provider != "sentinel" {
		t.Fatalf("got %+v", o)
	}
}

func TestObservationFromVerify_NotDetectedAssertsNoHealthOrWindow(t *testing.T) {
	res := detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}
	o := observationFromVerify("sentinel", res, nil)
	if o.Verdict != killchain.ObservationNotDetected {
		t.Fatalf("verdict = %s", o.Verdict)
	}
	if o.TelemetryHealth != "" || o.WindowComplete != "" {
		t.Fatalf("the vendor call reports neither health nor window, so none may be asserted: %+v", o)
	}
}

func TestObservationFromVerify_ErrorIsAnErrorObservation(t *testing.T) {
	o := observationFromVerify("sentinel", detectverify.VerifyResult{}, errors.New("timeout"))
	if o.Verdict != killchain.ObservationError {
		t.Fatalf("verdict = %s, want error", o.Verdict)
	}
}

// An unrecognised verdict string is never guessed into detected or not detected.
func TestObservationFromVerify_UnknownVerdictIsAnError(t *testing.T) {
	o := observationFromVerify("sentinel", detectverify.VerifyResult{Verdict: "Maybe"}, nil)
	if o.Verdict != killchain.ObservationError {
		t.Fatalf("verdict = %s, want error", o.Verdict)
	}
}
