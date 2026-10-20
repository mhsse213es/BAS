package panosexposure

import (
	"strings"
	"testing"
)

// Synthetic registry data for tests. Not vendor data.
const fixtureRegistry = `{
  "cve": "CVE-TEST-9001",
  "versions": [
    {"revision": 1, "verificationStatus": "verified", "verifiedAt": "2026-10-20", "source": "fixture",
     "affected": [{"introduced": "10.2.0", "fixedIn": "10.2.4"}],
     "conditions": {"requireGlobalProtect": true}},
    {"revision": 2, "verificationStatus": "unverified", "source": "fixture",
     "affected": [{"introduced": "10.2.0", "fixedIn": "10.2.5"}]}
  ]
}`

func mustParse(t *testing.T, data string) *Registry {
	t.Helper()
	reg, err := ParseRegistry([]byte(data))
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	return reg
}

func TestRegistry_BuiltinLoadsAndCarriesRevision(t *testing.T) {
	reg, err := BuiltinRegistry()
	if err != nil {
		t.Fatalf("builtin registry failed to load: %v", err)
	}
	rec, err := reg.Latest("CVE-2026-0257")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Revision != 1 || rec.Advisory.Version != "CVE-2026-0257 rev 1" {
		t.Fatalf("revision = %d, version = %q", rec.Revision, rec.Advisory.Version)
	}
	if rec.VerificationStatus != StatusVerified || rec.Source == "" {
		t.Fatalf("provenance missing: status=%q source=%q", rec.VerificationStatus, rec.Source)
	}
}

func TestRegistry_LatestSkipsNewerUnverifiedRevision(t *testing.T) {
	rec, err := mustParse(t, fixtureRegistry).Latest("CVE-TEST-9001")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Revision != 1 {
		t.Fatalf("latest selected revision %d; an unverified newer revision must never be the default", rec.Revision)
	}
}

func TestRegistry_ExplicitRevisionCanReachUnverified(t *testing.T) {
	rec, err := mustParse(t, fixtureRegistry).Get("CVE-TEST-9001", 2)
	if err != nil {
		t.Fatal(err)
	}
	if rec.VerificationStatus != StatusUnverified {
		t.Fatalf("status = %q", rec.VerificationStatus)
	}
}

func TestRegistry_NoVerifiedRevisionIsAnError(t *testing.T) {
	data := `{"cve":"CVE-TEST-9002","versions":[{"revision":1,"verificationStatus":"unverified","source":"x",
	  "affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`
	if _, err := mustParse(t, data).Latest("CVE-TEST-9002"); err == nil {
		t.Fatal("expected an error when no verified revision exists")
	}
}

func TestRegistry_UnknownCVEIsAnError(t *testing.T) {
	if _, err := mustParse(t, fixtureRegistry).Latest("CVE-NOPE-0000"); err == nil {
		t.Fatal("unknown CVE must be an error, never a guess")
	}
	if _, err := mustParse(t, fixtureRegistry).Get("CVE-TEST-9001", 99); err == nil {
		t.Fatal("unknown revision must be an error")
	}
}

func TestRegistry_RejectsInvalidData(t *testing.T) {
	bad := map[string]string{
		"duplicate revision": `{"cve":"CVE-T","versions":[
			{"revision":1,"verificationStatus":"verified","verifiedAt":"x","source":"s","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]},
			{"revision":1,"verificationStatus":"verified","verifiedAt":"x","source":"s","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`,
		"zero revision":               `{"cve":"CVE-T","versions":[{"revision":0,"verificationStatus":"verified","verifiedAt":"x","source":"s","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`,
		"verified without verifiedAt": `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"verified","source":"s","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`,
		"verified without source":     `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"verified","verifiedAt":"x","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`,
		"unknown status":              `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"maybe","source":"s","affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`,
		"unparseable range":           `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"unverified","source":"s","affected":[{"introduced":"10.2","fixedIn":"10.2.4"}]}]}`,
		"range without fix":           `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"unverified","source":"s","affected":[{"introduced":"10.2.0"}]}]}`,
		"no ranges":                   `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"unverified","source":"s","affected":[]}]}`,
		"unknown field":               `{"cve":"CVE-T","versions":[{"revision":1,"verificationStatus":"unverified","source":"s","surprise":1,"affected":[{"introduced":"10.2.0","fixedIn":"10.2.4"}]}]}`,
		"no revisions":                `{"cve":"CVE-T","versions":[]}`,
		"trailing data":               fixtureRegistry + ` {"x":1}`,
	}
	for name, data := range bad {
		if _, err := ParseRegistry([]byte(data)); err == nil {
			t.Errorf("%s: expected a load error", name)
		}
	}
}

func TestRegistry_GetReturnsCopy(t *testing.T) {
	reg := mustParse(t, fixtureRegistry)
	rec, _ := reg.Get("CVE-TEST-9001", 1)
	rec.Affected[0].FixedIn = "99.0.0"
	again, _ := reg.Get("CVE-TEST-9001", 1)
	if again.Affected[0].FixedIn != "10.2.4" {
		t.Fatal("a caller changed the registry through a returned record")
	}
}

func TestRegistry_AssessmentNamesTheRevisionUsed(t *testing.T) {
	adv, err := LoadBuiltinAdvisory("CVE-2026-0257")
	if err != nil {
		t.Fatal(err)
	}
	a := Asset{ID: "fw", Product: Product, Version: "11.2.8",
		GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriYes}
	r := AssessAt(a, adv, fixedTime)
	if r.AdvisoryVersion != "CVE-2026-0257 rev 1" {
		t.Fatalf("advisoryVersion = %q", r.AdvisoryVersion)
	}
	if !strings.Contains(strings.Join(r.Evidence, " "), "advisory:") {
		t.Fatalf("source not cited: %v", r.Evidence)
	}
}
