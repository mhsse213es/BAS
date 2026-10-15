package waforigin

import "testing"

func TestNewBypassScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001",
		"https://app.example.com/search via the production CDN/WAF edge",
		"the same payload sent to an undocumented secondary vhost never registered with the WAF",
		"manually authored")
	if err != nil {
		t.Fatalf("NewBypassScenario: %v", err)
	}
	if s.ID != "WAFORIGIN-001" {
		t.Errorf("ID = %q, want %q", s.ID, "WAFORIGIN-001")
	}
}

func TestNewBypassScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewBypassScenario("", WeaknessRoutingCoverageGap, "SQLI-001", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

// Review Focus: a WeaknessType whose Kind() is not KindBypassPair must be
// rejected, including an unknown value -- not silently accepted.
func TestNewBypassScenario_WeaknessFromAnotherKind_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessTLSProxyBehavior, "SQLI-001", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for a WeaknessType whose Kind() is KindProtocolClaim, got nil")
	}
}

func TestNewBypassScenario_UnknownWeakness_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessType("bogus"), "SQLI-001", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for an unknown WeaknessType, got nil")
	}
}

func TestNewBypassScenario_EmptyAttackVectorID_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "", "x", "y", "z")
	if err == nil {
		t.Fatal("want error for empty AttackVectorID, got nil")
	}
}

func TestNewBypassScenario_EmptyBaselinePathDescription_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "", "y", "z")
	if err == nil {
		t.Fatal("want error for empty BaselinePathDescription, got nil")
	}
}

func TestNewBypassScenario_EmptyBypassPathDescription_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "x", "", "z")
	if err == nil {
		t.Fatal("want error for empty BypassPathDescription, got nil")
	}
}

func TestNewBypassScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001", "x", "y", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}
