package adprimitive

import "testing"

func findPrimitive(id string) (Primitive, bool) {
	for _, p := range KerberoastingCatalog {
		if p.ID == id {
			return p, true
		}
	}
	return Primitive{}, false
}

func TestKerberoastingCatalog_Stage1And2ShareTechniqueIDButAreDistinctPrimitives(t *testing.T) {
	enum, ok := findPrimitive("spn-enumerate")
	if !ok || enum.TechniqueID != "T1558.003" {
		t.Fatalf("expected spn-enumerate with TechniqueID T1558.003, got %+v (ok=%v)", enum, ok)
	}
	kerb, ok := findPrimitive("kerberoast-tgs-request")
	if !ok || kerb.TechniqueID != "T1558.003" {
		t.Fatalf("expected kerberoast-tgs-request with TechniqueID T1558.003, got %+v (ok=%v)", kerb, ok)
	}
	if enum.ID == kerb.ID {
		t.Fatal("spn-enumerate and kerberoast-tgs-request must be distinct catalog entries despite sharing a TechniqueID")
	}
}

func TestKerberoastingCatalog_EnumeratePostconditionSatisfiesKerberoastPrerequisite(t *testing.T) {
	enum, _ := findPrimitive("spn-enumerate")
	kerb, _ := findPrimitive("kerberoast-tgs-request")

	satisfied := false
	for _, have := range enum.Postconditions {
		for _, need := range kerb.Prerequisites.Capabilities {
			if have == need {
				satisfied = true
			}
		}
	}
	if !satisfied {
		t.Fatalf("expected spn-enumerate's postcondition %+v to satisfy kerberoast-tgs-request's prerequisite %+v", enum.Postconditions, kerb.Prerequisites.Capabilities)
	}
}

func TestKerberoastingCatalog_ASREPDiscoverDoesNotClaimCredentialCapability(t *testing.T) {
	asrep, ok := findPrimitive("asrep-roast-discover")
	if !ok || asrep.TechniqueID != "T1558.004" {
		t.Fatalf("expected asrep-roast-discover with TechniqueID T1558.004, got %+v (ok=%v)", asrep, ok)
	}
	for _, cap := range asrep.Postconditions {
		if cap.Kind == CapServiceAccountCredential || cap.Kind == CapNTLMHash || cap.Kind == CapDomainCredentialMaterial || cap.Kind == CapTicket {
			t.Fatalf("asrep-roast-discover must not claim a credential-bearing postcondition (the real scenario step only discovers roastable accounts, never requests or cracks a ticket), got %+v", cap)
		}
	}
}
