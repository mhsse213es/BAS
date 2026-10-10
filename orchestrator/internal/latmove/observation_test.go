package latmove

import "testing"

func TestClassifyAttempt_MarkerFoundIsExecuted(t *testing.T) {
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}}
	if got := ClassifyAttempt(obs); got != ResultExecuted {
		t.Fatalf("result = %q, want executed", got)
	}
}

func TestClassifyAttempt_UncorrelatedMarkerIsIndeterminate(t *testing.T) {
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: false, Found: true}}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (can't trust an uncorrelated check)", got)
	}
}

func TestClassifyAttempt_CallSuccessAloneIsNotExecuted(t *testing.T) {
	// "verify postconditions, not command-success": a reported success with no
	// marker confirmation must NOT be Executed.
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got == ResultExecuted {
		t.Fatal("a call-reported success alone must never establish Executed")
	}
}

func TestClassifyAttempt_AbsentMarkerWithDenialIsAccessDenied(t *testing.T) {
	obs := Observation{Call: CallAccessDenied, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got != ResultAccessDenied {
		t.Fatalf("result = %q, want access_denied", got)
	}
}

func TestClassifyAttempt_AbsentMarkerNoDenialSignalIsIndeterminate(t *testing.T) {
	obs := Observation{Call: CallUnknown, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (absent marker alone never proves denial)", got)
	}
}

func TestClassifyAttempt_CorroborationNeverDeterminesResultAlone(t *testing.T) {
	// Strong corroboration (parent process + WMI-Activity) with an uncorrelated
	// marker must still be Indeterminate -- corroboration never decides alone.
	obs := Observation{
		Call:          CallSucceeded,
		Marker:        MarkerCheck{Correlated: false, Found: false},
		Corroboration: Corroboration{ParentProcessObserved: true, ParentProcessName: "WmiPrvSE.exe", WMIActivityLogged: true},
	}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (corroboration alone must not decide)", got)
	}
}

func TestClassifyAttempt_ErroredCallWithAbsentMarkerIsIndeterminate(t *testing.T) {
	obs := Observation{Call: CallErrored, Marker: MarkerCheck{Correlated: true, Found: false}}
	if got := ClassifyAttempt(obs); got != ResultIndeterminate {
		t.Fatalf("result = %q, want indeterminate (a generic error is not a denial signal)", got)
	}
}
