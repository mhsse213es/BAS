package reporting

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
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
	// Priority 4: a recognized skip: marker now resolves the more specific
	// StatusNotTested rather than the generic StatusUnknown -- Comparison
	// stays MissingEvidence either way (see dlpComparator's own unchanged
	// truth table).
	if r.Status != StatusNotTested {
		t.Errorf("Status = %s, want %s (a skip: marker must never resolve to Blocked)", r.Status, StatusNotTested)
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
	if r.Status != StatusNotTested {
		t.Errorf("Status = %s, want %s", r.Status, StatusNotTested)
	}
}

// Review Focus (Task 2): evidenceByTechnique must carry the real step's own
// StepName alongside its other per-step fields through the existing
// TechniqueID-collapse -- a one-field, additive change that changes no
// existing field's value.
func TestEvidenceByTechnique_PopulatesStepName(t *testing.T) {
	results := []models.SimulationResult{
		{ID: "T1567", StepName: "DLP Validation — HTTPS Exfiltration of Visa Card Record (T1567)", RawOutput: "x"},
	}
	ev := evidenceByTechnique(results)
	got := ev["T1567"]
	if got.StepName != "DLP Validation — HTTPS Exfiltration of Visa Card Record (T1567)" {
		t.Errorf("StepName = %q, want the real step name carried through", got.StepName)
	}
}

// --- Task 3: DLPEvidence wiring ---

func TestDLPVerifier_DLPEvidence_AlwaysPopulated(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.DLPEvidence == nil {
		t.Fatal("DLPEvidence must always be populated by dlpVerifier, got nil")
	}
	if r.DLPEvidence.Limitations == "" {
		t.Error("Limitations must always be explained, got empty string")
	}
}

func TestDLPVerifier_DLPEvidence_CollectionMethod_SinkReceipt(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{SinkTokenObserved: boolPtr(true)})
	if r.DLPEvidence.CollectionMethod != "sink-receipt" {
		t.Errorf("CollectionMethod = %q, want %q", r.DLPEvidence.CollectionMethod, "sink-receipt")
	}
}

func TestDLPVerifier_DLPEvidence_CollectionMethod_LocalMarker(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.DLPEvidence.CollectionMethod != "local-marker" {
		t.Errorf("CollectionMethod = %q, want %q", r.DLPEvidence.CollectionMethod, "local-marker")
	}
}

// Review Focus: missing provenance (no sink token, no marker, or a skip) must
// never be papered over -- CollectionMethod and CorrelationID stay empty, not
// a guessed or invented value.
func TestDLPVerifier_DLPEvidence_MissingProvenance_SkipPath(t *testing.T) {
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "skip: sftp.exe not found"})
	if r.DLPEvidence.CollectionMethod != "" {
		t.Errorf("CollectionMethod = %q, want empty for a skipped step", r.DLPEvidence.CollectionMethod)
	}
	if r.DLPEvidence.CorrelationID != "" {
		t.Errorf("CorrelationID = %q, want empty (never invented)", r.DLPEvidence.CorrelationID)
	}
}

func TestDLPVerifier_DLPEvidence_MissingProvenance_NoMarkerNoSinkToken(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "no marker here at all"})
	if r.DLPEvidence.CollectionMethod != "" {
		t.Errorf("CollectionMethod = %q, want empty when nothing usable was collected", r.DLPEvidence.CollectionMethod)
	}
	if r.DLPEvidence.CorrelationID != "" {
		t.Errorf("CorrelationID = %q, want empty (never invented)", r.DLPEvidence.CorrelationID)
	}
}

// Review Focus: an unknown/missing-evidence outcome's Limitations must say
// it's inconclusive, never imply a confirmed failure.
func TestDLPVerifier_DLPEvidence_Limitations_UnknownOutcome(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "no marker here at all"})
	lim := strings.ToLower(r.DLPEvidence.Limitations)
	if !strings.Contains(lim, "no usable observation") && !strings.Contains(lim, "not evidence") {
		t.Errorf("Limitations = %q, want it to say the outcome is inconclusive, not a failure", r.DLPEvidence.Limitations)
	}
}

// Review Focus: this is the user's own example -- a Warn was expected, the
// step only confirmed completion. Limitations must say that is unverified,
// never that the warning failed to appear.
func TestDLPVerifier_DLPEvidence_Limitations_SoftOutcomeUnverifiedBySuccessAlone(t *testing.T) {
	exp := dlpExp("dlp-usb-warn", "Warn")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationSucceeded"})
	if r.Comparison != MissingEvidence {
		t.Fatalf("Comparison = %v, want MissingEvidence", r.Comparison)
	}
	lim := strings.ToLower(r.DLPEvidence.Limitations)
	if !strings.Contains(lim, "warn") || !strings.Contains(lim, "unverif") {
		t.Errorf("Limitations = %q, want it to name Warn as unverified by bare completion", r.DLPEvidence.Limitations)
	}
}

func TestDLPVerifier_DLPEvidence_Limitations_ConfirmedMismatch(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{SinkTokenObserved: boolPtr(true)})
	if r.Comparison != Mismatch {
		t.Fatalf("Comparison = %v, want Mismatch", r.Comparison)
	}
	lim := strings.ToLower(r.DLPEvidence.Limitations)
	if !strings.Contains(lim, "fail") && !strings.Contains(lim, "deviat") {
		t.Errorf("Limitations = %q, want it to state a confirmed enforcement failure/deviation", r.DLPEvidence.Limitations)
	}
}

// Review Focus: fixture linkage must be an exact match on the real step
// name, never a guess -- a real catalogued dlpfixture entry resolves, an
// unknown step name does not.
func TestDLPVerifier_DLPEvidence_FixtureID_ResolvesFromRealStepName(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		StepName:  "DLP Validation — HTTPS Exfiltration of Visa Card Record (T1567)",
		RawOutput: "DLP_OBSERVATION: OperationBlocked",
	})
	if r.DLPEvidence.FixtureID != "visa-card-record" {
		t.Errorf("FixtureID = %q, want %q", r.DLPEvidence.FixtureID, "visa-card-record")
	}
}

func TestDLPVerifier_DLPEvidence_FixtureID_EmptyWhenStepNameUnknown(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		StepName:  "this step name is not in the catalog",
		RawOutput: "DLP_OBSERVATION: OperationBlocked",
	})
	if r.DLPEvidence.FixtureID != "" {
		t.Errorf("FixtureID = %q, want empty for an uncatalogued step name", r.DLPEvidence.FixtureID)
	}
}

func TestDLPVerifier_DLPEvidence_FixtureID_EmptyWhenStepNameAbsent(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.DLPEvidence.FixtureID != "" {
		t.Errorf("FixtureID = %q, want empty when StepEvidence carries no step name at all", r.DLPEvidence.FixtureID)
	}
}

// Review Focus: backward compatibility -- a VerificationResult serialized
// before this change (DLPEvidence absent) must still deserialize cleanly to
// nil, and a new one must round-trip and omit the field when nil so old
// consumers never see it.
func TestVerificationResult_DLPEvidence_JSONBackwardCompatible(t *testing.T) {
	oldShape := `{"ExpectedID":"e1","Status":"Detected"}`
	var r VerificationResult
	if err := json.Unmarshal([]byte(oldShape), &r); err != nil {
		t.Fatalf("Unmarshal old-shape JSON: %v", err)
	}
	if r.DLPEvidence != nil {
		t.Errorf("DLPEvidence = %+v, want nil when the stored JSON predates this field", r.DLPEvidence)
	}

	b, err := json.Marshal(VerificationResult{ExpectedID: "e2"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "DLPEvidence") {
		t.Errorf("marshaled JSON %s should omit DLPEvidence when nil", b)
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

// --- Priority 4: capability-aware NOT_TESTED resolver (narrow scope) ---

func TestDLPVerifier_NotTested_ClientToolAbsent(t *testing.T) {
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "skip: sftp.exe (OpenSSH Client) not found on this endpoint",
	})
	if r.Status != StatusNotTested {
		t.Errorf("Status = %s, want %s", r.Status, StatusNotTested)
	}
	if r.Comparison != MissingEvidence {
		t.Errorf("Comparison = %v, want MissingEvidence (unchanged)", r.Comparison)
	}
}

func TestDLPVerifier_NotTested_TechniqueInapplicable(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "skip: no removable drive letter available on this endpoint",
	})
	if r.Status != StatusNotTested {
		t.Errorf("Status = %s, want %s", r.Status, StatusNotTested)
	}
	if r.Comparison != MissingEvidence {
		t.Errorf("Comparison = %v, want MissingEvidence (unchanged)", r.Comparison)
	}
}

// Review Focus: a skip MUST still take precedence over SinkTokenObserved,
// exactly as before -- this is a regression guard on top of the pre-existing
// TestDLPVerifier_SkipMarker_TakesPrecedenceOverSinkTokenObserved, now also
// checking the new, more specific status.
func TestDLPVerifier_NotTested_TakesPrecedenceOverSinkTokenObserved(t *testing.T) {
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "skip: sftp.exe (OpenSSH Client) not found on this endpoint",
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusNotTested {
		t.Errorf("Status = %s, want %s (a skip: marker must never resolve via the sink-token path)", r.Status, StatusNotTested)
	}
}

// Review Focus: StatusUnknown must stay exactly as before for genuinely
// ambiguous evidence -- no marker, or an unrecognized marker that is NOT a
// skip -- never promoted to StatusNotTested.
func TestDLPVerifier_StatusUnknown_UnaffectedByNotTestedChange_NoMarker(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output with no marker at all"})
	if r.Status != StatusUnknown {
		t.Errorf("Status = %s, want %s", r.Status, StatusUnknown)
	}
}

func TestDLPVerifier_StatusUnknown_UnaffectedByNotTestedChange_GarbageMarker(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: SomeGarbageToken"})
	if r.Status != StatusUnknown {
		t.Errorf("Status = %s, want %s (an unrecognized marker is not a skip)", r.Status, StatusUnknown)
	}
}

// Review Focus: the marker convention itself is untouched -- arbitrary
// output that merely CONTAINS the word "skip" without matching the real
// "skip:" first-line convention must never resolve to StatusNotTested.
func TestDLPVerifier_NotTested_DoesNotFireOnLooseSkipMention(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "the script decided not to skip this step\nDLP_OBSERVATION: OperationBlocked",
	})
	if r.Status == StatusNotTested {
		t.Errorf("Status = %s, a loose mention of \"skip\" must never trigger StatusNotTested", r.Status)
	}
}

func TestDLPVerifier_NotTested_LimitationsStatePreconditionAbsent(t *testing.T) {
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "skip: sftp.exe (OpenSSH Client) not found on this endpoint",
	})
	lim := strings.ToLower(r.DLPEvidence.Limitations)
	if strings.Contains(lim, "may have been skipped") {
		t.Errorf("Limitations = %q, must not hedge once Status distinguishes NotTested from Unknown", r.DLPEvidence.Limitations)
	}
	if !strings.Contains(lim, "did not run") && !strings.Contains(lim, "not run") {
		t.Errorf("Limitations = %q, want it to state plainly that this step did not run", r.DLPEvidence.Limitations)
	}
}

func TestDLPVerifier_StatusUnknown_LimitationsStayInconclusive(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output with no marker at all"})
	lim := strings.ToLower(r.DLPEvidence.Limitations)
	if !strings.Contains(lim, "no usable observation") {
		t.Errorf("Limitations = %q, want the inconclusive phrasing unchanged for the non-skip ambiguous case", r.DLPEvidence.Limitations)
	}
}

// Review Focus: a result stored before this change (Status="Unknown", no
// awareness of StatusNotTested) must still deserialize and behave the same.
func TestVerificationResult_NotTested_LegacyResultUnaffected(t *testing.T) {
	oldShape := `{"ExpectedID":"e1","Status":"Unknown"}`
	var r VerificationResult
	if err := json.Unmarshal([]byte(oldShape), &r); err != nil {
		t.Fatalf("Unmarshal old-shape JSON: %v", err)
	}
	if r.Status != StatusUnknown {
		t.Errorf("Status = %q, want %q unchanged for a legacy stored result", r.Status, StatusUnknown)
	}
}
