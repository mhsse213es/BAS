package adenv

import "testing"

func TestHasGPOWriteAccess(t *testing.T) {
	g := GPO{Name: "Workstation Policy", WritePrincipals: []string{"helpdesk"}}
	if !HasGPOWriteAccess(g, "helpdesk") {
		t.Fatal("a principal listed in WritePrincipals must have write access")
	}
	if HasGPOWriteAccess(g, "nobody") {
		t.Fatal("a principal not listed must not have write access")
	}
}

func TestGPOAffectsScope(t *testing.T) {
	if !GPOAffectsScope(GPO{LinkedOUs: []string{"OU=Workstations,DC=corp"}}) {
		t.Fatal("a GPO linked to an OU affects scope")
	}
	if GPOAffectsScope(GPO{}) {
		t.Fatal("an unlinked GPO affects no scope")
	}
}
