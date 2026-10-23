package cveval

import (
	"testing"
	"time"
)

func TestValidateResult_VulnerableRequiresEvidence(t *testing.T) {
	r := Result{CVEID: "CVE-2021-44228", Verdict: VerdictVulnerable}
	if err := ValidateResult(r); err == nil {
		t.Fatal("VULNERABLE with no Evidence.Source must be rejected")
	}
	r.Evidence.Source = SourceFixture
	if err := ValidateResult(r); err == nil {
		t.Fatal("VULNERABLE with Source set but no Evidence.Detail must be rejected")
	}
	r.Evidence.Detail = "matched the known-vulnerable fixture signature"
	if err := ValidateResult(r); err != nil {
		t.Fatalf("fully-evidenced VULNERABLE result should be valid: %v", err)
	}
}

func TestValidateResult_NotVulnerableRequiresEvidence(t *testing.T) {
	r := Result{CVEID: "CVE-2021-44228", Verdict: VerdictNotVulnerable}
	if err := ValidateResult(r); err == nil {
		t.Fatal("NOT_VULNERABLE with no evidence must be rejected")
	}
}

func TestValidateResult_ErrorAndSkippedRequireDetailNotEvidence(t *testing.T) {
	for _, v := range []Verdict{VerdictError, VerdictSkipped, VerdictInconclusive} {
		r := Result{CVEID: "CVE-2021-44228", Verdict: v}
		if err := ValidateResult(r); err == nil {
			t.Fatalf("%s with no Detail must be rejected", v)
		}
		r.Detail = "a free-text reason"
		if err := ValidateResult(r); err != nil {
			t.Fatalf("%s with Detail set but no Evidence should be valid (none required): %v", v, err)
		}
	}
}

func TestValidateResult_RejectsEmptyCVEID(t *testing.T) {
	r := Result{Verdict: VerdictSkipped, Detail: "no preconditions supplied"}
	if err := ValidateResult(r); err == nil {
		t.Fatal("a Result with no CVEID must be rejected")
	}
}

func TestValidateResult_RejectsUnknownVerdict(t *testing.T) {
	r := Result{CVEID: "CVE-2021-44228", Verdict: Verdict("maybe"), Detail: "x"}
	if err := ValidateResult(r); err == nil {
		t.Fatal("an unknown Verdict string must be rejected")
	}
}

func TestEvidence_ObservedAtIsPreserved(t *testing.T) {
	now := time.Now()
	e := Evidence{Source: SourceLabRuntime, Detail: "probe returned a callback", ObservedAt: now, Target: "10.50.0.12:8080"}
	if !e.ObservedAt.Equal(now) {
		t.Fatal("ObservedAt must be preserved verbatim")
	}
}
