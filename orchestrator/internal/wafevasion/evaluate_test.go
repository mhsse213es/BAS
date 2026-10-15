package wafevasion

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func mustVectorByID(t *testing.T, id string) wafcatalog.AttackVector {
	t.Helper()
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %q not found in AudspectWAFAttackCatalog", id)
	return wafcatalog.AttackVector{}
}

func mustEVADE001(t *testing.T) EvasionScenario {
	t.Helper()
	s, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002",
		"plain SQLi payload in the query parameter",
		"the identical SQLi payload, double-URL-encoded",
		"the origin application URL-decodes query parameters twice before passing them to the query layer, so the double-encoded form decodes to the identical payload",
		"manually authored")
	if err != nil {
		t.Fatalf("NewEvasionScenario: %v", err)
	}
	return s
}

func testWindow() wafval.TimeWindow {
	now := time.Now()
	return wafval.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
}

// Review Focus: a vector whose ID doesn't match scenario.AttackVectorID is
// a caller bug and must be rejected.
func TestEvaluateEvasionGap_VectorIDMismatch_ReturnsError(t *testing.T) {
	scenario := mustEVADE001(t) // references SQLI-002
	wrongVector := mustVectorByID(t, "PATHTRAV-001")
	key := wafval.CorrelationKey{TestExecutionID: "e", RequestID: "r", Target: "t", Window: testWindow()}
	_, _, err := EvaluateEvasionGap(scenario, wrongVector, "pb", nil, key, nil, key, true)
	if err == nil {
		t.Fatal("want error when vector.ID does not match scenario.AttackVectorID, got nil")
	}
}

func blockedEvidence(eventID, requestID string, now time.Time) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: eventID, RequestID: requestID, ObservedAt: now, Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
}

func missedEvidence(eventID, requestID string, now time.Time) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageSearchedVerifiedNone, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: eventID, RequestID: requestID, ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
}

func allowedButDetectedEvidence(eventID, requestID string, now time.Time) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{Mechanism: wafval.MechanismWAFEngine, Coverage: wafval.CoverageFound, Observations: []wafval.Observation{
			{Mechanism: wafval.MechanismWAFEngine, EventID: eventID, RequestID: requestID, ObservedAt: now, Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown, EvidenceKind: wafval.EvidenceObserved},
		}},
	}
}

// Review Focus, and spec §8 item 4: an unconfirmed origin-equivalence must
// never read as a real evasion bypass, even though the two legs visibly
// differ.
func TestEvaluateEvasionGap_UnconfirmedEquivalence_YieldsInconclusive(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		missedEvidence("v1", "r2", now), evasiveKey,
		false)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- an unconfirmed origin-equivalence must never read as a real evasion bypass", verdict, wafval.VerdictInconclusive)
	}
}

// Review Focus, and spec §8 item 5: a canonical leg that was never reliably
// blocked makes the evasion comparison moot -- it must resolve to
// Inconclusive, not a false "no gap".
func TestEvaluateEvasionGap_CanonicalNotReliablyBlocked_YieldsInconclusive(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		missedEvidence("c1", "r1", now), canonicalKey, // canonical itself missed
		missedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("Verdict = %q, want %q -- a canonical leg that was never reliably blocked must not yield a false bypass or false no-gap verdict", verdict, wafval.VerdictInconclusive)
	}
}

// Spec §8 item 6: confirmed equivalence, reliably blocked canonical,
// missed evasive leg -> a genuine evasion bypass.
func TestEvaluateEvasionGap_ConfirmedEquivalence_EvasiveMissed_YieldsMissed(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, reason, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		missedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("Verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
	if reason == "" {
		t.Error("want a non-empty evasion-attribution reason")
	}
}

func TestEvaluateEvasionGap_ConfirmedEquivalence_EvasiveDetectedButAllowed_YieldsDetectedButAllowed(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		allowedButDetectedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictDetectedButAllowed {
		t.Errorf("Verdict = %q, want %q", verdict, wafval.VerdictDetectedButAllowed)
	}
}

func TestEvaluateEvasionGap_ConfirmedEquivalence_EvasiveBlocked_YieldsBlocked(t *testing.T) {
	scenario := mustEVADE001(t)
	vector := mustVectorByID(t, "SQLI-002")
	now := time.Now()
	window := testWindow()
	canonicalKey := wafval.CorrelationKey{TestExecutionID: "e1", RequestID: "r1", Target: "example.test", Window: window}
	evasiveKey := wafval.CorrelationKey{TestExecutionID: "e2", RequestID: "r2", Target: "example.test", Window: window}

	verdict, _, err := EvaluateEvasionGap(scenario, vector, "owasp-crs-default",
		blockedEvidence("c1", "r1", now), canonicalKey,
		blockedEvidence("v1", "r2", now), evasiveKey,
		true)
	if err != nil {
		t.Fatalf("EvaluateEvasionGap: %v", err)
	}
	if verdict != wafval.VerdictBlocked {
		t.Errorf("Verdict = %q, want %q -- no evasion gap should be demonstrated when the evasive leg is still blocked", verdict, wafval.VerdictBlocked)
	}
}
