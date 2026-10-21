package regulatory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
)

func load(t *testing.T) Registry {
	t.Helper()
	r, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r
}

func byRef(t *testing.T, r Registry, ref string) Mapping {
	t.Helper()
	for _, m := range r.Mappings {
		if m.ControlRef == ref {
			return m
		}
	}
	t.Fatalf("no mapping %s in the registry", ref)
	return Mapping{}
}

// The committed registry's records are the bases for every case below, so the tests check real records.
func dpdp(t *testing.T) Mapping { return byRef(t, load(t), "IN-DPDP-S12-3") }
func pdpl(t *testing.T) Mapping { return byRef(t, load(t), "UAE-PDPL-A15-2") }

// Every mapped source is a committed file, and its hash is the hash of those exact bytes. A changed or missing file fails.
func TestSourcesMatchTheirHashes(t *testing.T) {
	r := load(t)
	check := func(ref, file, want string) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s: source file %s: %v", ref, file, err)
			return
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: %s hashes to %s, registry records %s", ref, file, got, want)
		}
	}
	for _, m := range r.Mappings {
		check(m.ControlRef, m.SourceFile, m.SourceSHA256)
	}
	for _, u := range r.Unmapped {
		check(u.ObligationRef, u.SourceFile, u.SourceSHA256)
	}
}

func TestRegistryLoadsWithCandidatesAndUnmapped(t *testing.T) {
	r := load(t)
	if len(r.Mappings) == 0 {
		t.Fatal("no mappings")
	}
	// DPDP s12(3) stays unverified: its commencement is not verified. The other mappings are verified only with a named
	// reviewer and the reviewed hash equal to the committed source hash, which Validate enforces.
	for _, m := range r.Mappings {
		if m.ControlRef == "IN-DPDP-S12-3" {
			if m.Status != StatusUnverified {
				t.Errorf("DPDP s12(3): status %q; it must stay unverified until its commencement is verified", m.Status)
			}
			continue
		}
		if m.Status != StatusVerified || m.Reviewer == "" || m.ReviewedHash != m.SourceSHA256 {
			t.Errorf("%s: status %q, reviewer %q; expected a verified mapping with a reviewer", m.ControlRef, m.Status, m.Reviewer)
		}
	}
	if len(r.Unmapped) == 0 {
		t.Error("no unmapped obligations recorded; the gaps must stay visible")
	}
}

// DPDP commencement is not verified: no notification is in the source set, and no effective date is recorded.
func TestDPDPCommencementIsNotInvented(t *testing.T) {
	m := dpdp(t)
	if m.Commencement != CommencementNotVerified || m.EffectiveDate != "" {
		t.Errorf("DPDP commencement %q with effective date %q; it must stay not_verified with no date", m.Commencement, m.EffectiveDate)
	}
	m.EffectiveDate = "2023-08-11"
	if err := Validate(m); err == nil {
		t.Error("a not-verified commencement with an effective date was accepted")
	}
}

func TestMappingRejectsMissingProvenance(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Mapping)
	}{
		{"no version", func(m *Mapping) { m.Version = "" }},
		{"no source url", func(m *Mapping) { m.SourceURL = "" }},
		{"http source url", func(m *Mapping) { m.SourceURL = "http://example.gov/a.pdf" }},
		{"source file outside sources", func(m *Mapping) { m.SourceFile = "../secret.pdf" }},
		{"short hash", func(m *Mapping) { m.SourceSHA256 = "abc" }},
		{"no retrieval date", func(m *Mapping) { m.RetrievedOn = "" }},
		{"no clause text", func(m *Mapping) { m.ClauseText = "" }},
		{"no applicability conditions", func(m *Mapping) { m.ApplicabilityConds = nil }},
		{"no mapped scenario", func(m *Mapping) { m.MappedScenarios = nil }},
		{"bad control ref", func(m *Mapping) { m.ControlRef = "dpdp s12" }},
	}
	for _, c := range cases {
		m := dpdp(t)
		c.edit(&m)
		if err := Validate(m); err == nil {
			t.Errorf("%s: accepted, want rejected", c.name)
		}
	}
}

// A scenario is mapped only with a coverage entry that states what it does not test.
func TestCoverageMustStateGaps(t *testing.T) {
	m := dpdp(t)
	m.ScenarioCoverage = slices.Clone(m.ScenarioCoverage)
	m.ScenarioCoverage[0].Gaps = nil
	if err := Validate(m); err == nil {
		t.Error("coverage with no stated gaps was accepted")
	}
	m = dpdp(t)
	m.ScenarioCoverage = nil
	if err := Validate(m); err == nil {
		t.Error("a mapping with no coverage entries was accepted")
	}
	m = dpdp(t)
	m.ScenarioCoverage = slices.Clone(m.ScenarioCoverage)
	m.ScenarioCoverage[0].ScenarioID = "API-BAS-AUTHZ-001"
	if err := Validate(m); err == nil {
		t.Error("coverage naming a scenario the mapping does not list was accepted")
	}
}

// A verified mapping needs the full review record. A source URL alone does not make a mapping verified.
func TestVerifiedRequiresTheReviewRecord(t *testing.T) {
	base := func() Mapping {
		m := pdpl(t)
		m.Status = StatusVerified
		m.Reviewer = "named-reviewer"
		m.ReviewedOn = "2026-10-22"
		m.ReviewedHash = m.SourceSHA256
		return m
	}
	if err := Validate(base()); err != nil {
		t.Fatalf("a complete reviewed mapping was rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*Mapping)
	}{
		{"no reviewer", func(m *Mapping) { m.Reviewer = "" }},
		{"no review date", func(m *Mapping) { m.ReviewedOn = "" }},
		{"reviewed a different file", func(m *Mapping) { m.ReviewedHash = "0000000000000000000000000000000000000000000000000000000000000000" }},
		{"commencement not verified", func(m *Mapping) { m.Commencement = CommencementNotVerified; m.EffectiveDate = "" }},
		{"no commencement evidence", func(m *Mapping) { m.CommencementEvidence = "" }},
	}
	for _, c := range cases {
		m := base()
		c.edit(&m)
		if err := Validate(m); err == nil {
			t.Errorf("%s: verified mapping accepted, want rejected", c.name)
		}
	}
}

// Obligations no scenario tests stay recorded, with a reason and the scenario that would be needed.
func TestUnmappedNeedsReasonAndRequiredScenario(t *testing.T) {
	r := load(t)
	for _, u := range r.Unmapped {
		if err := validateUnmapped(u); err != nil {
			t.Errorf("%s: %v", u.ObligationRef, err)
		}
		u.Reason = ""
		if err := validateUnmapped(u); err == nil {
			t.Errorf("%s: unmapped with no reason was accepted", u.ObligationRef)
		}
	}
}

// Every scenario's regulatory reference resolves in the registry, and each registry mapping lists the scenarios back. The
// two sides cannot drift apart.
func TestRegistryAndCatalogAgree(t *testing.T) {
	r := load(t)
	scenarios, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	refs := map[string]Mapping{}
	for _, m := range r.Mappings {
		refs[m.ControlRef] = m
	}
	ids := map[string]bool{}
	for _, s := range scenarios {
		ids[s.ID] = true
		for _, ref := range s.RegulatoryMapping {
			m, ok := refs[ref]
			if !ok {
				t.Errorf("%s cites %s, which is not a mapping in the registry", s.ID, ref)
				continue
			}
			if !slices.Contains(m.MappedScenarios, s.ID) {
				t.Errorf("%s cites %s, but the registry does not list the scenario", s.ID, ref)
			}
		}
	}
	for _, m := range r.Mappings {
		for _, id := range m.MappedScenarios {
			if !ids[id] {
				t.Errorf("%s maps %s, which is not in the catalogue", m.ControlRef, id)
			}
		}
	}
}

// A mapping is ready for human review only when every mapped scenario is implemented and validated. An implemented scenario
// that has not passed in both builds does not support the mapping, and a verified record cannot carry it.
func TestReadinessGateRequiresValidatedScenarios(t *testing.T) {
	m := pdpl(t)
	if err := ReadyForReview(m); err != nil {
		t.Fatalf("a mapping with a validated scenario was not ready: %v", err)
	}
	m.ScenarioCoverage = slices.Clone(m.ScenarioCoverage)
	m.ScenarioCoverage[0].ScenarioState = ScenarioImplementedNotValidated
	if err := ReadyForReview(m); err == nil {
		t.Error("a mapping whose scenario is implemented but not validated was ready for review")
	}
	m.Status = StatusVerified
	m.Reviewer = "named-reviewer"
	m.ReviewedOn = "2026-10-22"
	m.ReviewedHash = m.SourceSHA256
	if err := Validate(m); err == nil {
		t.Error("a verified mapping with an unvalidated scenario was accepted")
	}
}

// An unmapped obligation cannot claim its scenario is validated: a scenario that passed would be a mapping candidate instead.
func TestUnmappedCannotClaimAValidatedScenario(t *testing.T) {
	r := load(t)
	u := r.Unmapped[0]
	u.ScenarioState = ScenarioImplementedValidated
	if err := validateUnmapped(u); err == nil {
		t.Error("an unmapped obligation with a validated scenario was accepted")
	}
}
