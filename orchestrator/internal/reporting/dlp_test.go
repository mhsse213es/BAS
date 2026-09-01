package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestDLPComparator(t *testing.T) {
	c := dlpComparator{}
	cases := []struct {
		name, expected, observed string
		want                     ComparisonResult
	}{
		{"expect Block, observe Blocked", "Block", ObservationBlocked, Match},
		{"expect Block, observe Succeeded", "Block", ObservationSucceeded, Mismatch},
		{"expect Block, observe Unknown", "Block", ObservationUnknown, MissingEvidence},
		{"expect Allow, observe Succeeded", "Allow", ObservationSucceeded, Match},
		{"expect Allow, observe Blocked", "Allow", ObservationBlocked, Mismatch},
		{"expect Allow, observe Unknown", "Allow", ObservationUnknown, MissingEvidence},
		{"expect Warn, observe Blocked", "Warn", ObservationBlocked, Mismatch},
		{"expect Warn, observe Succeeded", "Warn", ObservationSucceeded, MissingEvidence},
		{"expect Warn, observe Unknown", "Warn", ObservationUnknown, MissingEvidence},
		{"expect Justify, observe Succeeded", "Justify", ObservationSucceeded, MissingEvidence},
		{"expect Audit, observe Succeeded", "Audit", ObservationSucceeded, MissingEvidence},
		{"expect Quarantine, observe Blocked", "Quarantine", ObservationBlocked, Mismatch},
		{"garbage observed value", "Block", "not-a-real-token", MissingEvidence},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			if got := c.Compare(c2.expected, c2.observed); got != c2.want {
				t.Errorf("Compare(%q,%q) = %v want %v", c2.expected, c2.observed, got, c2.want)
			}
		})
	}
}

func TestDLPComparatorRegistered(t *testing.T) {
	if _, ok := comparatorFor("dlp").(dlpComparator); !ok {
		t.Error("comparatorFor(\"dlp\") should return the registered dlpComparator")
	}
}

func dlpExp(id, expectedOutcome string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID:              id,
		Provider:        "trellix_dlp",
		Type:            scenario.DomainDLP,
		OutcomeFamily:   "dlp",
		ExpectedOutcome: expectedOutcome,
		Verification:    scenario.VerificationAutomatic,
		Confidence:      scenario.ConfidenceRequired,
		Finding:         scenario.ExpectedFinding{Title: "t", Severity: "High"},
	}
}

func TestDLPVerifier(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")

	// marker present, blocked, matches expected Block → Detected
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output\nDLP_OBSERVATION: OperationBlocked\n"})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("blocked-match: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// marker present, succeeded, mismatches expected Block → NotDetected
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output\nDLP_OBSERVATION: OperationSucceeded\n"})
	if r.Status != StatusNotDetected || r.Comparison != Mismatch {
		t.Errorf("succeeded-mismatch: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// no marker at all → Unknown, never a false Detected/NotDetected
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output with no marker at all"})
	if r.Status != StatusUnknown || r.Comparison != MissingEvidence {
		t.Errorf("no-marker: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// marker present but with an unrecognized token → Unknown, never guessed
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: SomeGarbageToken"})
	if r.Status != StatusUnknown || r.Comparison != MissingEvidence {
		t.Errorf("garbage-token: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// marker not on the last line — must still be found
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked\nsome trailing cleanup line"})
	if r.Status != StatusDetected {
		t.Errorf("marker-not-last-line: got status=%s want Detected", r.Status)
	}

	// ExpectedOutcome/ObservedOutcome are populated for diagnostics
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.ExpectedOutcome != "Block" || r.ObservedOutcome != ObservationBlocked {
		t.Errorf("outcome fields: got expected=%q observed=%q", r.ExpectedOutcome, r.ObservedOutcome)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestDLPVerifier_SinkPrimary_TokenReceived(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	// Sink says the token WAS received -- data reached the destination, DLP
	// failed to catch it -- regardless of what any local marker claims.
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "DLP_OBSERVATION: OperationBlocked", // local script thought it was blocked
		SinkTokenObserved: boolPtr(true),                       // but the sink proves it actually arrived
	})
	if r.Status != StatusNotDetected || r.Comparison != Mismatch {
		t.Errorf("sink-received must be authoritative (Succeeded) even when the local marker disagrees: got status=%s comparison=%v", r.Status, r.Comparison)
	}
	if r.ObservedOutcome != ObservationSucceeded {
		t.Errorf("ObservedOutcome = %q, want %q", r.ObservedOutcome, ObservationSucceeded)
	}
}

func TestDLPVerifier_SinkPrimary_TokenNotReceived(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("token-not-received must resolve Blocked: got status=%s comparison=%v", r.Status, r.Comparison)
	}
	if r.ObservedOutcome != ObservationBlocked {
		t.Errorf("ObservedOutcome = %q, want %q", r.ObservedOutcome, ObservationBlocked)
	}
}

func TestDLPVerifier_NoSinkToken_UnaffectedByNewLogic(t *testing.T) {
	// Regression test: the existing 5 local-marker-only
	// dlp-exfiltration-validation.yaml steps never set SinkTokenObserved --
	// nil must still take the pre-existing local-marker regex path exactly
	// as before this task.
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "DLP_OBSERVATION: OperationBlocked",
		// SinkTokenObserved deliberately left nil.
	})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("nil SinkTokenObserved must fall back to the local-marker path: got status=%s comparison=%v", r.Status, r.Comparison)
	}
}

func TestDLPVerifier_SkipMarker_TakesPrecedenceOverSinkTokenObserved(t *testing.T) {
	// A step whose client tool was absent never attempted a transfer, so
	// SinkTokenObserved=false here is NOT evidence of a blocked
	// exfiltration -- it's the absence of an attempt. Without this check,
	// this would resolve to ObservationBlocked and likely grade as a
	// false "DLP successfully blocked it."
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "skip: sftp.exe (OpenSSH Client) not found on this endpoint",
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusUnknown {
		t.Errorf("Status = %s, want %s (a skip: marker must never resolve to Blocked)", r.Status, StatusUnknown)
	}
	if r.Comparison != MissingEvidence {
		t.Errorf("Comparison = %v, want MissingEvidence", r.Comparison)
	}
}

func TestDLPVerifier_SkipMarker_CaseInsensitiveAndWhitespaceTolerant(t *testing.T) {
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "  SKIP: sftp.exe not found\nDLP_OBSERVATION: OperationBlocked",
		SinkTokenObserved: boolPtr(true), // even a true receipt must not override a genuine skip
	})
	if r.Status != StatusUnknown {
		t.Errorf("Status = %s, want %s", r.Status, StatusUnknown)
	}
}

func TestDLPVerifier_NoSkipMarker_SinkPrimaryStillWorks(t *testing.T) {
	// Regression: HTTPS/DNS steps never emit skip: -- confirm the new
	// check doesn't touch their existing sink-primary resolution.
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "EXEC T1567: exfiltration attempt sent. [BAS-SIM-DLP-HTTPS]",
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("Status=%s Comparison=%v, want StatusDetected/Match (unaffected by the new skip: check)", r.Status, r.Comparison)
	}
}
