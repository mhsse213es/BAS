package waforigin

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func mustPathTravVector(t *testing.T) wafcatalog.AttackVector {
	t.Helper()
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	for _, v := range catalog {
		if v.ID == "PATHTRAV-001" {
			return v
		}
	}
	t.Fatal("PATHTRAV-001 not found in wafcatalog.AudspectWAFAttackCatalog()")
	return wafcatalog.AttackVector{}
}

func TestNewConsistencyScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "manually authored")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	if s.ID != "WAFORIGIN-005" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFORIGIN-005")
	}
}

func TestNewConsistencyScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewConsistencyScenario("", "PATHTRAV-001", "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewConsistencyScenario_EmptyAttackVectorID_Rejected(t *testing.T) {
	_, err := NewConsistencyScenario("WAFORIGIN-005", "", "x")
	if err == nil {
		t.Fatal("want error for empty AttackVectorID, got nil")
	}
}

func TestNewConsistencyScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestEvaluateConfigurationConsistency_VectorIDMismatch_Rejected(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	wrongVector := mustPathTravVector(t)
	wrongVector.ID = "PATHTRAV-999"
	_, _, err = EvaluateConfigurationConsistency(scenario, wrongVector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: blockedEvidence(testKey("b")), Key: testKey("b")},
	})
	if err == nil {
		t.Fatal("want error for vector.ID/scenario.AttackVectorID mismatch, got nil")
	}
}

func TestEvaluateConfigurationConsistency_FewerThanTwoTrustworthyResults_ReturnsInconclusive(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	vector := mustPathTravVector(t)
	verdict, _, err := EvaluateConfigurationConsistency(scenario, vector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: nil, Key: testKey("b")},
	})
	if err != nil {
		t.Fatalf("EvaluateConfigurationConsistency: %v", err)
	}
	if verdict != ConsistencyInconclusive {
		t.Errorf("verdict = %q, want %q", verdict, ConsistencyInconclusive)
	}
}

func TestEvaluateConfigurationConsistency_AgreeingTrustworthyResults_ReturnsConfirmed(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	vector := mustPathTravVector(t)
	verdict, _, err := EvaluateConfigurationConsistency(scenario, vector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: blockedEvidence(testKey("b")), Key: testKey("b")},
	})
	if err != nil {
		t.Fatalf("EvaluateConfigurationConsistency: %v", err)
	}
	if verdict != ConsistencyConfirmed {
		t.Errorf("verdict = %q, want %q", verdict, ConsistencyConfirmed)
	}
}

// Review Focus: the drift reason string must name both disagreeing nodes.
func TestEvaluateConfigurationConsistency_DisagreeingTrustworthyResults_ReturnsDriftNamingBothNodes(t *testing.T) {
	scenario, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001", "x")
	if err != nil {
		t.Fatalf("NewConsistencyScenario: %v", err)
	}
	vector := mustPathTravVector(t)
	verdict, reason, err := EvaluateConfigurationConsistency(scenario, vector, "owasp-crs-default", []NodeEvidence{
		{NodeID: "node-a", Evidence: blockedEvidence(testKey("a")), Key: testKey("a")},
		{NodeID: "node-b", Evidence: missedEvidence(testKey("b")), Key: testKey("b")},
	})
	if err != nil {
		t.Fatalf("EvaluateConfigurationConsistency: %v", err)
	}
	if verdict != ConsistencyDrift {
		t.Errorf("verdict = %q, want %q", verdict, ConsistencyDrift)
	}
	if !strings.Contains(reason, "node-a") || !strings.Contains(reason, "node-b") {
		t.Errorf("reason = %q, want it to name both %q and %q", reason, "node-a", "node-b")
	}
}
