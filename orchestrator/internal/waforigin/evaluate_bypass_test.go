package waforigin

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

func mustSQLIVector(t *testing.T) wafcatalog.AttackVector {
	t.Helper()
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range catalog {
		if v.ID == "SQLI-001" {
			return v
		}
	}
	t.Fatal("SQLI-001 not found in wafcatalog.AudspectWAFAttackCatalog()")
	return wafcatalog.AttackVector{}
}

// blockedEvidence/missedEvidence each supply BOTH a WAFEngine and an
// OriginApp CollectionResult. wafval's ClaimPrevention completeness
// requires MechanismWAFEngine present at minimum (else Insufficient ->
// forced Inconclusive), and reaches CompletenessComplete/ConfidenceHigh
// only when MechanismOriginApp is also present (see
// orchestrator/internal/wafval/evaluate.go's deriveCompleteness) --
// a single-mechanism fixture is not enough evidence to reach a
// trustworthy verdict either way.
func blockedEvidence(key wafval.CorrelationKey) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{
			Mechanism: wafval.MechanismWAFEngine,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismWAFEngine, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementBlocked, Detection: wafval.DetectionMatched, Origin: wafval.OriginUnknown,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
		{
			Mechanism: wafval.MechanismOriginApp,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismOriginApp, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginNotObserved,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
	}
}

// missedEvidence models the attack reaching the origin neither detected
// nor blocked -- for a ClaimPrevention leg this resolves to VerdictMissed
// (wafval.derivePrevention: Enforcement=Allowed + Detection=NotMatched),
// never VerdictAllowed, which is unreachable for ClaimPrevention.
func missedEvidence(key wafval.CorrelationKey) []wafval.CollectionResult {
	return []wafval.CollectionResult{
		{
			Mechanism: wafval.MechanismWAFEngine,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismWAFEngine, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionNotMatched, Origin: wafval.OriginUnknown,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
		{
			Mechanism: wafval.MechanismOriginApp,
			Coverage:  wafval.CoverageFound,
			Observations: []wafval.Observation{{
				Mechanism: wafval.MechanismOriginApp, RequestID: key.RequestID,
				Enforcement: wafval.EnforcementUnknown, Detection: wafval.DetectionUnknown, Origin: wafval.OriginReceived,
				EvidenceKind: wafval.EvidenceObserved,
			}},
		},
	}
}

func testKey(id string) wafval.CorrelationKey {
	now := time.Now()
	return wafval.CorrelationKey{TestExecutionID: id, RequestID: id, Target: "test", Window: wafval.TimeWindow{Start: now, End: now.Add(time.Second)}}
}

func TestEvaluateBypassScenario_VectorIDMismatch_Rejected(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	wrongVector := mustSQLIVector(t)
	wrongVector.ID = "SQLI-999"
	_, _, err = EvaluateBypassScenario(scenario, wrongVector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), missedEvidence(testKey("bypass")), testKey("bypass"))
	if err == nil {
		t.Fatal("want error for vector.ID/scenario.AttackVectorID mismatch, got nil")
	}
}

func TestEvaluateBypassScenario_UntrustworthyBaseline_ReturnsInconclusive(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	verdict, _, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		nil, testKey("baseline"), missedEvidence(testKey("bypass")), testKey("bypass"))
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictInconclusive {
		t.Errorf("verdict = %q, want %q (no baseline evidence collected)", verdict, wafval.VerdictInconclusive)
	}
}

// Review Focus: the gap case must return VerdictMissed specifically --
// VerdictAllowed is unreachable here since the malicious leg's claim is
// always ClaimPrevention (see wafval.derivePrevention: VerdictAllowed is
// reserved for ClaimFalsePositive).
func TestEvaluateBypassScenario_MissedBypass_ReturnsMissed(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-002", WeaknessDirectOriginReachability, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	verdict, reason, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), missedEvidence(testKey("bypass")), testKey("bypass"))
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictMissed {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictMissed)
	}
	if reason == "" {
		t.Error("reason must not be empty")
	}
}

func TestEvaluateBypassScenario_TrustworthyBlockedBypass_ReturnsBlocked(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-003", WeaknessFailOpenOnUnavailability, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	verdict, _, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), blockedEvidence(testKey("bypass")), testKey("bypass"))
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictBlocked {
		t.Errorf("verdict = %q, want %q (bypass still blocked -- no gap)", verdict, wafval.VerdictBlocked)
	}
}

func TestEvaluateBypassScenario_DetectedButAllowedBypass_ReturnsDetectedButAllowed(t *testing.T) {
	scenario, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "baseline", "bypass", "x")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	vector := mustSQLIVector(t)
	key := testKey("bypass")
	detectedButAllowed := []wafval.CollectionResult{{
		Mechanism: wafval.MechanismWAFEngine,
		Coverage:  wafval.CoverageFound,
		Observations: []wafval.Observation{{
			Mechanism: wafval.MechanismWAFEngine, RequestID: key.RequestID,
			Enforcement: wafval.EnforcementAllowed, Detection: wafval.DetectionMatched, Origin: wafval.OriginReceived,
			EvidenceKind: wafval.EvidenceObserved,
		}},
	}}
	verdict, _, err := EvaluateBypassScenario(scenario, vector, "owasp-crs-default",
		blockedEvidence(testKey("baseline")), testKey("baseline"), detectedButAllowed, key)
	if err != nil {
		t.Fatalf("EvaluateBypassScenario: %v", err)
	}
	if verdict != wafval.VerdictDetectedButAllowed {
		t.Errorf("verdict = %q, want %q", verdict, wafval.VerdictDetectedButAllowed)
	}
}
