package backupassurance

import (
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestClassify_ErrorTakesPrecedenceOverEverything(t *testing.T) {
	v, sr, reason := classifyObserverResult(true, true, "looks fine", errors.New("connection reset"))
	if v != controlval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR -- an observer error must always win, even when tested=true and outcome=true", v)
	}
	if sr != "" {
		t.Fatalf("SkipReason = %q, want empty for an ERROR verdict", sr)
	}
	if reason == "" {
		t.Fatal("reason is empty, want the wrapped error text")
	}
}

func TestClassify_MalformedComboIsRejectedAsErrorNotSkippedOrPass(t *testing.T) {
	// The one row a naive implementation could collapse into SKIPPED (since
	// tested=false) or PASS (since outcome=true) -- it must be neither.
	v, sr, _ := classifyObserverResult(false, true, "", nil)
	if v != controlval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR for the malformed tested=false/outcome=true combo", v)
	}
	if sr != "" {
		t.Fatalf("SkipReason = %q, want empty for an ERROR verdict", sr)
	}
}

func TestClassify_NotTestedIsSkippedNotTested(t *testing.T) {
	v, sr, _ := classifyObserverResult(false, false, "", nil)
	if v != controlval.VerdictSkipped || sr != controlval.SkipNotTested {
		t.Fatalf("got Verdict=%q SkipReason=%q, want SKIPPED/not_tested", v, sr)
	}
}

func TestClassify_TestedAndOutcomeIsPass(t *testing.T) {
	v, sr, _ := classifyObserverResult(true, true, "", nil)
	if v != controlval.VerdictPass || sr != "" {
		t.Fatalf("got Verdict=%q SkipReason=%q, want PASS/empty", v, sr)
	}
}

func TestClassify_TestedWithoutOutcomeIsFail(t *testing.T) {
	v, sr, _ := classifyObserverResult(true, false, "", nil)
	if v != controlval.VerdictFail || sr != "" {
		t.Fatalf("got Verdict=%q SkipReason=%q, want FAIL/empty", v, sr)
	}
}
