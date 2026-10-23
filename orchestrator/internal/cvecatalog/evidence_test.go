package cvecatalog

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/cveval"
)

func TestEvaluateConfigIndicator_MatchesVulnerableFixture(t *testing.T) {
	e, err := log4ShellEntry()
	if err != nil {
		t.Fatalf("log4ShellEntry: %v", err)
	}
	now := time.Now()
	r := e.EvaluateConfigIndicator(e.VulnerableFixture.Indicator, now)
	if r.Verdict != cveval.VerdictVulnerable {
		t.Fatalf("Verdict = %q, want VULNERABLE", r.Verdict)
	}
	if r.Evidence.Source != cveval.SourceFixture {
		t.Fatalf("Evidence.Source = %q, want fixture", r.Evidence.Source)
	}
	if err := cveval.ValidateResult(r); err != nil {
		t.Fatalf("resulting Result fails ValidateResult: %v", err)
	}
}

func TestEvaluateConfigIndicator_MatchesPatchedFixture(t *testing.T) {
	e, err := log4ShellEntry()
	if err != nil {
		t.Fatalf("log4ShellEntry: %v", err)
	}
	r := e.EvaluateConfigIndicator(e.PatchedFixture.Indicator, time.Now())
	if r.Verdict != cveval.VerdictNotVulnerable {
		t.Fatalf("Verdict = %q, want NOT_VULNERABLE", r.Verdict)
	}
	if err := cveval.ValidateResult(r); err != nil {
		t.Fatalf("resulting Result fails ValidateResult: %v", err)
	}
}

func TestEvaluateConfigIndicator_UnrecognizedIndicatorIsInconclusive(t *testing.T) {
	e, err := log4ShellEntry()
	if err != nil {
		t.Fatalf("log4ShellEntry: %v", err)
	}
	r := e.EvaluateConfigIndicator("log4j-core:9.9.9;some-other-shape-entirely", time.Now())
	if r.Verdict != cveval.VerdictInconclusive {
		t.Fatalf("Verdict = %q, want INCONCLUSIVE", r.Verdict)
	}
	if r.Detail == "" {
		t.Fatal("INCONCLUSIVE result must carry a Detail explaining the mismatch")
	}
}

func TestEvaluateConfigIndicator_EmptyIndicatorIsSkipped(t *testing.T) {
	e, err := log4ShellEntry()
	if err != nil {
		t.Fatalf("log4ShellEntry: %v", err)
	}
	r := e.EvaluateConfigIndicator("", time.Now())
	if r.Verdict != cveval.VerdictSkipped {
		t.Fatalf("Verdict = %q, want SKIPPED", r.Verdict)
	}
	if err := cveval.ValidateResult(r); err != nil {
		t.Fatalf("SKIPPED result fails ValidateResult: %v", err)
	}
}

func TestEvaluateConfigIndicator_NeverMatchesOnPartialSubstring(t *testing.T) {
	e, err := log4ShellEntry()
	if err != nil {
		t.Fatalf("log4ShellEntry: %v", err)
	}
	// A prefix of the real vulnerable indicator must never be treated as a match --
	// exact equality only, so a near-miss never produces false confidence.
	partial := e.VulnerableFixture.Indicator[:len(e.VulnerableFixture.Indicator)-1]
	r := e.EvaluateConfigIndicator(partial, time.Now())
	if r.Verdict != cveval.VerdictInconclusive {
		t.Fatalf("a partial-substring match must be INCONCLUSIVE, got %q", r.Verdict)
	}
}
