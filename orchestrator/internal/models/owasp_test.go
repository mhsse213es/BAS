package models

import (
	"slices"
	"testing"
)

func TestOWASP2021Complete(t *testing.T) {
	if len(OWASP2021) != 10 {
		t.Fatalf("expected 10 OWASP 2021 risks, got %d", len(OWASP2021))
	}
	seen := map[string]bool{}
	for _, r := range OWASP2021 {
		if r.ID == "" || r.Name == "" || r.Version != "2021" {
			t.Errorf("incomplete risk: %+v", r)
		}
		if seen[r.ID] {
			t.Errorf("duplicate risk id %q", r.ID)
		}
		seen[r.ID] = true
	}
}

// TestOWASPMapReferencesValidRisks ensures every risk ID used in the technique
// map is a real OWASP 2021 category — guards against typos like "A11:2021".
func TestOWASPMapReferencesValidRisks(t *testing.T) {
	valid := map[string]bool{}
	for _, r := range OWASP2021 {
		valid[r.ID] = true
	}
	for tech, risks := range owaspByTechnique {
		if len(risks) == 0 {
			t.Errorf("%s has an empty OWASP list", tech)
		}
		seen := map[string]bool{}
		for _, r := range risks {
			if !valid[r] {
				t.Errorf("%s maps to unknown OWASP risk %q", tech, r)
			}
			if seen[r] {
				t.Errorf("%s has duplicate risk %q", tech, r)
			}
			seen[r] = true
		}
	}
}

func TestLookupOWASPResolvesSubtechniques(t *testing.T) {
	base := LookupOWASP("T1078")
	sub := LookupOWASP("T1078.001")
	if len(base) == 0 || len(sub) != len(base) {
		t.Fatalf("sub-technique should resolve to base mapping: base=%v sub=%v", base, sub)
	}

	// Spot-check a few well-known mappings.
	cases := map[string]string{
		"T1190":     "A03:2021", // Injection
		"T1110":     "A07:2021", // Auth failures
		"T1003":     "A02:2021", // Cryptographic failures
		"T1070.001": "A09:2021", // Logging/monitoring failures
	}
	for tech, want := range cases {
		if !slices.Contains(LookupOWASP(tech), want) {
			t.Errorf("LookupOWASP(%s) = %v, want to include %s", tech, LookupOWASP(tech), want)
		}
	}

	if LookupOWASP("T9999") != nil {
		t.Errorf("unmapped technique should return nil")
	}
}
