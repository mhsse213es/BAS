package rwtaxonomy

import "testing"

func TestTechniqueDomain_AllValuesAreValidDomains(t *testing.T) {
	for id, d := range TechniqueDomain {
		if !d.Valid() {
			t.Errorf("TechniqueDomain[%q] = %q, not a valid Domain", id, d)
		}
	}
}

func TestTechniqueDomain_AllKeysAreWellFormedTechniqueIDs(t *testing.T) {
	for id := range TechniqueDomain {
		if !techniqueIDPattern.MatchString(id) {
			t.Errorf("TechniqueDomain key %q does not match a valid MITRE technique ID pattern", id)
		}
	}
}

func TestTechniqueIDPattern_RejectsMalformedIDs(t *testing.T) {
	invalid := []string{"1486", "T148", "T14866", "T1486.00", "T1486.0000", "t1486", "T1486.", ""}
	for _, id := range invalid {
		if techniqueIDPattern.MatchString(id) {
			t.Errorf("techniqueIDPattern matched invalid ID %q, want no match", id)
		}
	}
}

func TestTechniqueIDPattern_AcceptsWellFormedIDs(t *testing.T) {
	valid := []string{"T1486", "T1021.001", "T1543.003"}
	for _, id := range valid {
		if !techniqueIDPattern.MatchString(id) {
			t.Errorf("techniqueIDPattern did not match valid ID %q, want match", id)
		}
	}
}

func TestDomainFor_KnownTechniqueReturnsTrueAndItsDomain(t *testing.T) {
	d, ok := DomainFor("T1486")
	if !ok {
		t.Fatal("ok = false for T1486, want true")
	}
	if d != DomainEncryptionAndDestruction {
		t.Errorf("DomainFor(\"T1486\") = %q, want %q", d, DomainEncryptionAndDestruction)
	}
}

func TestDomainFor_UnknownTechniqueReturnsFalse(t *testing.T) {
	_, ok := DomainFor("T9999")
	if ok {
		t.Fatal("ok = true for an unmapped technique ID, want false")
	}
}
