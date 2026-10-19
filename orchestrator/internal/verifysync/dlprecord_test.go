package verifysync

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dlpreport"
	"github.com/audspect/bas/internal/reporting"
)

func dlpVerdict(observed, collection string, override *reporting.OverrideEvidence) reporting.VerificationResult {
	return reporting.VerificationResult{
		ExpectedID:      "exp-x",
		TechniqueID:     "T1048.002",
		ExpectedOutcome: "Block",
		ObservedOutcome: observed,
		Comparison:      reporting.Mismatch,
		Status:          reporting.StatusNotDetected,
		DLPEvidence: &reporting.DLPEvidence{
			CollectionMethod: collection,
			Limitations:      "lim",
			Override:         override,
		},
	}
}

func TestDeriveDLPEnforcement_PrecedenceAndNoOverclaim(t *testing.T) {
	override := &reporting.OverrideEvidence{Occurred: true}
	cases := []struct {
		name     string
		observed string
		coll     string
		ov       *reporting.OverrideEvidence
		want     dlpreport.EnforcementOutcome
	}{
		{"override wins over a block", reporting.ObservationBlocked, "local-marker", override, dlpreport.EnforcementOverridden},
		{"override wins over a sink-confirmed success", reporting.ObservationSucceeded, "sink-receipt", override, dlpreport.EnforcementOverridden},
		{"self-reported block is Blocked", reporting.ObservationBlocked, "local-marker", nil, dlpreport.EnforcementBlocked},
		{"missing sink receipt is never a Blocked", reporting.ObservationBlocked, "sink-receipt", nil, dlpreport.EnforcementUnknown},
		{"sink-confirmed success is Allowed", reporting.ObservationSucceeded, "sink-receipt", nil, dlpreport.EnforcementAllowed},
		{"self-reported success is never Allowed", reporting.ObservationSucceeded, "local-marker", nil, dlpreport.EnforcementUnknown},
		{"no observation is Unknown", reporting.ObservationUnknown, "", nil, dlpreport.EnforcementUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := deriveDLPEnforcement(c.observed, &reporting.DLPEvidence{CollectionMethod: c.coll, Override: c.ov})
			if got != c.want {
				t.Fatalf("enforcement = %s, want %s", got, c.want)
			}
		})
	}
}

func TestDLPEntry_KeepsComparisonAndNeverClassifiesAsCorrect(t *testing.T) {
	e := dlpEntryFromVerdict("sc-1", dlpVerdict(reporting.ObservationBlocked, "local-marker", nil))
	if e.Comparison != string(reporting.Mismatch) {
		t.Fatalf("comparison = %q, want the verbatim Mismatch", e.Comparison)
	}
	if e.Record.Classification != dlpreport.ClassificationNotEvaluated {
		t.Fatalf("classification = %s, want NotEvaluated: a policy match is not a classification measurement", e.Record.Classification)
	}
	if e.Record.Telemetry != dlpreport.TelemetryUnverifiable || e.Record.Response != dlpreport.ResponseNotTested {
		t.Fatalf("telemetry/response overclaimed: %s / %s", e.Record.Telemetry, e.Record.Response)
	}
	if err := e.Record.Validate(); err != nil {
		t.Fatalf("record fails its own Validate: %v", err)
	}
	if !strings.Contains(e.Record.Limitations, "self-reported") {
		t.Fatalf("limitations must say the block is self-reported, got %q", e.Record.Limitations)
	}
}

func TestDLPEntriesFromVerdicts_NonDLPVerdictsProduceNothing(t *testing.T) {
	verdicts := []reporting.VerificationResult{
		{ExpectedID: "endpoint-exp", TechniqueID: "T1003"},
		dlpVerdict(reporting.ObservationSucceeded, "sink-receipt", nil),
	}
	got := dlpEntriesFromVerdicts("sc-1", verdicts)
	if len(got) != 1 || got[0].Record.Enforcement != dlpreport.EnforcementAllowed {
		t.Fatalf("got %d entries, want exactly the one DLP verdict as Allowed: %+v", len(got), got)
	}
}
