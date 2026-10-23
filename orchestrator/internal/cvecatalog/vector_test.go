package cvecatalog

import (
	"testing"

	"github.com/audspect/bas/internal/cveval"
)

func validEntryArgs() (string, []string, Severity, AffectedProduct, string, string, cveval.ExecutionProfile, []Reference, string, ConfigFixture, ConfigFixture, string) {
	return "CVE-2021-44228",
		[]string{"CWE-502"},
		SeverityCritical,
		AffectedProduct{Name: "example:component", Ranges: []VersionRange{{Introduced: "1.0", Fixed: "2.0"}}},
		"a description",
		"preconditions text",
		cveval.ProfileFixtureOnly,
		[]Reference{{Source: "NVD", URL: "https://nvd.nist.gov/x"}},
		"2026-10-24",
		ConfigFixture{Description: "vuln", Indicator: "v1", Implies: cveval.VerdictVulnerable},
		ConfigFixture{Description: "patched", Indicator: "v2", Implies: cveval.VerdictNotVulnerable},
		"manually authored"
}

func TestNewCVEEntry_ValidArgsConstruct(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov := validEntryArgs()
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov); err != nil {
		t.Fatalf("NewCVEEntry with valid args should succeed: %v", err)
	}
}

func TestNewCVEEntry_RejectsMalformedID(t *testing.T) {
	_, cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov := validEntryArgs()
	if _, err := NewCVEEntry("not-a-cve-id", cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov); err == nil {
		t.Fatal("a malformed CVE ID must be rejected")
	}
}

func TestNewCVEEntry_RejectsMalformedCWE(t *testing.T) {
	id, _, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov := validEntryArgs()
	if _, err := NewCVEEntry(id, []string{"not-a-cwe"}, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov); err == nil {
		t.Fatal("a malformed CWE ID must be rejected")
	}
}

func TestNewCVEEntry_RejectsEmptyAffectedProductRanges(t *testing.T) {
	id, cwe, sev, _, desc, pre, prof, refs, lv, vf, pf, prov := validEntryArgs()
	if _, err := NewCVEEntry(id, cwe, sev, AffectedProduct{Name: "x"}, desc, pre, prof, refs, lv, vf, pf, prov); err == nil {
		t.Fatal("an AffectedProduct with no Ranges must be rejected")
	}
}

func TestNewCVEEntry_RejectsEmptyReferences(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, _, lv, vf, pf, prov := validEntryArgs()
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, nil, lv, vf, pf, prov); err == nil {
		t.Fatal("a CVE entry with no References must be rejected")
	}
}

func TestNewCVEEntry_RejectsBadLastVerifiedDate(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, refs, _, vf, pf, prov := validEntryArgs()
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, refs, "yesterday", vf, pf, prov); err == nil {
		t.Fatal("a non-date lastVerified value must be rejected")
	}
}

func TestNewCVEEntry_RejectsVulnerableFixtureWithWrongImplies(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, refs, lv, _, pf, prov := validEntryArgs()
	badVF := ConfigFixture{Description: "vuln", Indicator: "v1", Implies: cveval.VerdictNotVulnerable}
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, refs, lv, badVF, pf, prov); err == nil {
		t.Fatal("VulnerableFixture.Implies must be forced to VerdictVulnerable")
	}
}

func TestNewCVEEntry_RejectsPatchedFixtureWithWrongImplies(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, _, prov := validEntryArgs()
	badPF := ConfigFixture{Description: "patched", Indicator: "v2", Implies: cveval.VerdictVulnerable}
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, badPF, prov); err == nil {
		t.Fatal("PatchedFixture.Implies must be forced to VerdictNotVulnerable")
	}
}

func TestNewCVEEntry_RejectsIdenticalFixtureIndicators(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, _, prov := validEntryArgs()
	pf := ConfigFixture{Description: "patched", Indicator: vf.Indicator, Implies: cveval.VerdictNotVulnerable}
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, prov); err == nil {
		t.Fatal("identical VulnerableFixture/PatchedFixture indicators must be rejected -- otherwise no observed value could ever distinguish them")
	}
}

func TestNewCVEEntry_RejectsEmptyProvenance(t *testing.T) {
	id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, _ := validEntryArgs()
	if _, err := NewCVEEntry(id, cwe, sev, aff, desc, pre, prof, refs, lv, vf, pf, ""); err == nil {
		t.Fatal("empty provenance must be rejected")
	}
}
