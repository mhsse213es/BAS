package panosexposure

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)

func hasCode(r Result, code string) bool {
	for _, c := range r.ReasonCodes {
		if c == code {
			return true
		}
	}
	return false
}

func TestExplain_UnknownListsEveryMissingCondition(t *testing.T) {
	adv, err := LoadBuiltinAdvisory("CVE-2026-0257")
	if err != nil {
		t.Fatal(err)
	}
	a := Asset{ID: "fw", Product: Product, Version: "11.2.8",
		GlobalProtect: TriYes, AuthOverride: TriUnknown, SharedOverrideCert: TriUnknown}
	r := AssessAt(a, adv, fixedTime)
	if r.Verdict != VerdictUnknown || !hasCode(r, CodeConditionUnknown) {
		t.Fatalf("verdict = %s codes = %v", r.Verdict, r.ReasonCodes)
	}
	want := []string{EvidenceAuthOverride, EvidenceSharedOverride}
	if !reflect.DeepEqual(r.MissingEvidence, want) {
		t.Fatalf("missingEvidence = %v, want %v", r.MissingEvidence, want)
	}
}

func TestExplain_UnparseableVersionNamesVersionAsMissing(t *testing.T) {
	r := AssessAt(Asset{ID: "fw", Product: Product, Version: "garbage"}, testAdvisory, fixedTime)
	if r.Verdict != VerdictUnknown || !hasCode(r, CodeVersionUnparseable) {
		t.Fatalf("verdict = %s codes = %v", r.Verdict, r.ReasonCodes)
	}
	if len(r.MissingEvidence) != 1 || r.MissingEvidence[0] != EvidenceVersion {
		t.Fatalf("missingEvidence = %v", r.MissingEvidence)
	}
}

func TestExplain_CodesMatchEachOutcome(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	base := Asset{ID: "fw", Product: Product, GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriYes}
	cases := []struct {
		name    string
		asset   Asset
		advisor Advisory
		verdict Verdict
		code    string
	}{
		{"vulnerable", withVersion(base, "11.2.8"), adv, VerdictVulnerable, CodeInAffectedRange},
		{"not affected", withVersion(base, "11.2.12"), adv, VerdictNotAffected, CodeOutsideAffectedRanges},
		{"unresolved", withVersion(base, "10.2.18"), adv, VerdictUnknown, CodeReleaseUnresolved},
		{"uncovered branch", withVersion(base, "12.0.1"), adv, VerdictUnknown, CodeBranchNotCovered},
		{"not pan-os", Asset{ID: "x", Product: "fortinet", Version: "1.0.0"}, adv, VerdictNotApplicable, CodeNotPANOS},
	}
	for _, c := range cases {
		r := AssessAt(c.asset, c.advisor, fixedTime)
		if r.Verdict != c.verdict || !hasCode(r, c.code) {
			t.Errorf("%s: verdict = %s codes = %v, want %s with %s", c.name, r.Verdict, r.ReasonCodes, c.verdict, c.code)
		}
	}
}

func TestExplain_MitigatedCarriesAbsentCode(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	a := Asset{ID: "fw", Product: Product, Version: "11.2.8", GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriNo}
	r := AssessAt(a, adv, fixedTime)
	if r.Verdict != VerdictMitigated || !hasCode(r, CodeConditionAbsent) {
		t.Fatalf("verdict = %s codes = %v", r.Verdict, r.ReasonCodes)
	}
}

func TestExplain_TimestampAndAdvisoryVersionRecorded(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	adv.Version = "2026-10-20.1"
	r := AssessAt(withVersion(exposedBase(), "11.2.8"), adv, fixedTime)
	if !r.AssessedAt.Equal(fixedTime) {
		t.Fatalf("assessedAt = %s, want %s", r.AssessedAt, fixedTime)
	}
	if r.AdvisoryVersion != "2026-10-20.1" {
		t.Fatalf("advisoryVersion = %q", r.AdvisoryVersion)
	}
}

func TestExplain_RepeatableForSameInputs(t *testing.T) {
	adv, _ := LoadBuiltinAdvisory("CVE-2026-0257")
	a := withVersion(exposedBase(), "11.2.8")
	first, _ := json.Marshal(AssessAt(a, adv, fixedTime))
	second, _ := json.Marshal(AssessAt(a, adv, fixedTime))
	if string(first) != string(second) {
		t.Fatalf("same inputs gave different results:\n%s\n%s", first, second)
	}
}

func TestExplain_JSONHasEmptyArraysNotNull(t *testing.T) {
	r := AssessAt(Asset{ID: "x", Product: "fortinet"}, testAdvisory, fixedTime)
	out, _ := json.Marshal(r)
	if strings.Contains(string(out), `"missingEvidence":null`) || strings.Contains(string(out), `"reasonCodes":null`) {
		t.Fatalf("empty lists must serialise as [] for stable API clients: %s", out)
	}
}

func exposedBase() Asset {
	return Asset{ID: "fw", Product: Product, GlobalProtect: TriYes, AuthOverride: TriYes, SharedOverrideCert: TriYes}
}

func withVersion(a Asset, v string) Asset {
	a.Version = v
	return a
}
