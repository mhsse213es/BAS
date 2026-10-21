package regulatory

import (
	"slices"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
)

func valid() Mapping {
	return Mapping{
		ControlRef: "IN-DPDP-S12", Framework: "DPDP Act", Clause: "Section 12", SourceProvision: "Section 12",
		Version: "2023", SourceURL: "https://example.gov/act.pdf", MappedScenarios: []string{"API-BAS-DATA-011"},
		Commencement: CommencementNotVerified, Status: StatusUnverified,
	}
}

// reviewed is a complete verified mapping. Each test removes one piece of it.
func reviewed() Mapping {
	m := valid()
	m.Status = StatusVerified
	m.Reviewer = "reviewer-name"
	m.ReviewedOn = "2026-10-21"
	m.ApplicabilityConds = []string{"processing of digital personal data"}
	m.Commencement = CommencementVerified
	m.EffectiveDate = "2026-01-01"
	m.CommencementSource = "https://example.gov/notification.pdf"
	return m
}

func TestRegistryLoadsAndValidates(t *testing.T) {
	ms, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("registry is empty")
	}
	for _, m := range ms {
		if m.Status != StatusUnverified {
			t.Errorf("%s: status %q; a record ships unverified until reviewed", m.ControlRef, m.Status)
		}
	}
}

// A mapping must name its source and version, and must be a control reference.
func TestValidateRequiresProvenance(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Mapping)
	}{
		{"no version", func(m *Mapping) { m.Version = "" }},
		{"no source url", func(m *Mapping) { m.SourceURL = "" }},
		{"http source url", func(m *Mapping) { m.SourceURL = "http://example.gov/act.pdf" }},
		{"bad control ref", func(m *Mapping) { m.ControlRef = "dpdp s12" }},
		{"no mapped scenario", func(m *Mapping) { m.MappedScenarios = nil }},
		{"bad scenario id", func(m *Mapping) { m.MappedScenarios = []string{"DATA-011"} }},
		{"unknown status", func(m *Mapping) { m.Status = "reviewed" }},
	}
	for _, c := range cases {
		m := valid()
		c.edit(&m)
		if err := Validate(m); err == nil {
			t.Errorf("%s: accepted, want rejected", c.name)
		}
	}
	if err := Validate(valid()); err != nil {
		t.Errorf("a complete unverified mapping was rejected: %v", err)
	}
}

// A source URL alone does not make a mapping verified. Each piece of the review record is required.
func TestVerifiedRequiresTheFullReviewRecord(t *testing.T) {
	if err := Validate(reviewed()); err != nil {
		t.Fatalf("a complete reviewed mapping was rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*Mapping)
	}{
		{"no reviewer", func(m *Mapping) { m.Reviewer = "" }},
		{"no review date", func(m *Mapping) { m.ReviewedOn = "" }},
		{"no exact provision", func(m *Mapping) { m.SourceProvision = "" }},
		{"no applicability conditions", func(m *Mapping) { m.ApplicabilityConds = nil }},
		{"commencement not verified", func(m *Mapping) { m.Commencement = CommencementNotVerified }},
		{"no effective date", func(m *Mapping) { m.EffectiveDate = "" }},
		{"no commencement source", func(m *Mapping) { m.CommencementSource = "" }},
		{"http commencement source", func(m *Mapping) { m.CommencementSource = "http://example.gov/n.pdf" }},
	}
	for _, c := range cases {
		m := reviewed()
		c.edit(&m)
		if err := Validate(m); err == nil {
			t.Errorf("%s: verified mapping accepted, want rejected", c.name)
		}
	}
}

// An unverified mapping must not carry an invented date, and must not claim its commencement is verified.
func TestUnverifiedCarriesNoInventedDate(t *testing.T) {
	m := valid()
	m.EffectiveDate = "2023-08-11"
	if err := Validate(m); err == nil {
		t.Error("an unverified mapping with an effective date was accepted")
	}
	m = valid()
	m.Commencement = CommencementVerified
	if err := Validate(m); err == nil {
		t.Error("an unverified mapping claiming verified commencement was accepted")
	}
}

// Every scenario's regulatory reference resolves in the registry, and every registry entry names scenarios that list it
// back. The two sides cannot drift apart.
func TestRegistryAndCatalogAgree(t *testing.T) {
	ms, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	scenarios, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	refs := map[string]Mapping{}
	for _, m := range ms {
		refs[m.ControlRef] = m
	}
	for _, s := range scenarios {
		for _, ref := range s.RegulatoryMapping {
			m, ok := refs[ref]
			if !ok {
				t.Errorf("%s cites %s, which is not in the registry", s.ID, ref)
				continue
			}
			if !slices.Contains(m.MappedScenarios, s.ID) {
				t.Errorf("%s cites %s, but the registry does not list the scenario", s.ID, ref)
			}
		}
	}
	ids := map[string]bool{}
	for _, s := range scenarios {
		ids[s.ID] = true
	}
	for _, m := range ms {
		for _, id := range m.MappedScenarios {
			if !ids[id] {
				t.Errorf("%s maps %s, which is not in the catalogue", m.ControlRef, id)
			}
		}
	}
}
