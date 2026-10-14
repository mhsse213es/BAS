package backupassurance

import (
	"context"
	"errors"
	"testing"
)

func allFakesPassing() Dependencies {
	return Dependencies{
		DeletionProtection:  &FakeDeletionProtectionObserver{Tested: true, Protected: true},
		Immutability:        &FakeImmutabilityObserver{Tested: true, Immutable: true},
		OfflineIsolation:    &FakeOfflineIsolationObserver{Tested: true, Isolated: true},
		PrivilegeSeparation: &FakePrivilegeSeparationObserver{Tested: true, Separated: true},
		RestoreIntegrity:    &FakeRestoreIntegrityObserver{Tested: true, ValidResult: true},
		RPORTO:              &FakeRPORTOObserver{Tested: true, Met: true},
	}
}

func TestAssessBackup_AllPassingReturnsSixResultsInFixedOrder(t *testing.T) {
	results := AssessBackup(context.Background(), allFakesPassing())
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6", len(results))
	}
	for i, r := range results {
		if r.Check != allChecks[i] {
			t.Fatalf("results[%d].Check = %q, want %q -- order must be fixed", i, r.Check, allChecks[i])
		}
		if r.Verdict != "PASS" {
			t.Fatalf("results[%d].Verdict = %q, want PASS", i, r.Verdict)
		}
		if !r.Simulated {
			t.Fatalf("results[%d].Simulated = false, want true", i)
		}
		if r.Observer == "" {
			t.Fatalf("results[%d].Observer is empty, want non-empty", i)
		}
	}
}

func TestAssessBackup_MissingObserverIsErrorNotPanic(t *testing.T) {
	deps := allFakesPassing()
	deps.RPORTO = nil // missing dependency
	results := AssessBackup(context.Background(), deps)
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6 even with a missing dependency", len(results))
	}
	var rpo CheckResult
	for _, r := range results {
		if r.Check == CheckRPORTO {
			rpo = r
		}
	}
	if rpo.Verdict != "ERROR" {
		t.Fatalf("RPORTO Verdict = %q, want ERROR for a missing observer", rpo.Verdict)
	}
	if rpo.Observer != "unconfigured" {
		t.Fatalf("RPORTO Observer = %q, want \"unconfigured\"", rpo.Observer)
	}
}

func TestAssessBackup_ObserverErrorIsError(t *testing.T) {
	deps := allFakesPassing()
	deps.Immutability = &FakeImmutabilityObserver{Err: errors.New("storage API unreachable")}
	results := AssessBackup(context.Background(), deps)
	for _, r := range results {
		if r.Check == CheckImmutability && r.Verdict != "ERROR" {
			t.Fatalf("Immutability Verdict = %q, want ERROR", r.Verdict)
		}
	}
}

// panickingObserver always panics -- used only to prove AssessBackup
// recovers per-check and the other 5 checks still produce results.
type panickingObserver struct{}

func (panickingObserver) ObserveOfflineIsolation(context.Context) (bool, bool, string, string, error) {
	panic("simulated observer crash")
}

func TestAssessBackup_PanickingObserverIsRecoveredAndOthersStillRun(t *testing.T) {
	deps := allFakesPassing()
	deps.OfflineIsolation = panickingObserver{}
	results := AssessBackup(context.Background(), deps)
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6 even when one observer panics", len(results))
	}
	for _, r := range results {
		if r.Check == CheckOfflineIsolation {
			if r.Verdict != "ERROR" || r.Observer != "panicked" {
				t.Fatalf("OfflineIsolation got Verdict=%q Observer=%q, want ERROR/\"panicked\"", r.Verdict, r.Observer)
			}
			continue
		}
		if r.Verdict != "PASS" {
			t.Fatalf("%s Verdict = %q, want PASS -- one panicking check must never affect the other 5", r.Check, r.Verdict)
		}
	}
}

func TestAssessBackup_UncapturedFakeKeyIsSkippedNotTested(t *testing.T) {
	deps := allFakesPassing()
	deps.DeletionProtection = &FakeDeletionProtectionObserver{} // zero value: never captured
	results := AssessBackup(context.Background(), deps)
	for _, r := range results {
		if r.Check == CheckDeletionProtection {
			if r.Verdict != "SKIPPED" || r.SkipReason != "not_tested" {
				t.Fatalf("got Verdict=%q SkipReason=%q, want SKIPPED/not_tested", r.Verdict, r.SkipReason)
			}
		}
	}
}
