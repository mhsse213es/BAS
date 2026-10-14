package backupassurance

import (
	"context"
	"testing"
)

func TestFakeDeletionProtectionObserver_UncapturedKeyIsNeverTested(t *testing.T) {
	f := &FakeDeletionProtectionObserver{}
	tested, protected, observerID, _, err := f.ObserveDeletionProtection(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if tested {
		t.Fatal("tested = true, want false -- an uncaptured key must never be treated as evaluated")
	}
	if protected {
		t.Fatal("protected = true, want false -- an untested check must never default to a successful outcome")
	}
	if observerID == "" {
		t.Fatal("observerID is empty, want a non-empty self-reported identity even for an untested fake")
	}
}

func TestFakeDeletionProtectionObserver_CapturedValueIsReturnedVerbatim(t *testing.T) {
	f := &FakeDeletionProtectionObserver{Tested: true, Protected: true, Reason: "object lock enabled"}
	tested, protected, _, reason, err := f.ObserveDeletionProtection(context.Background())
	if err != nil || !tested || !protected || reason != "object lock enabled" {
		t.Fatalf("got tested=%v protected=%v reason=%q err=%v, want tested=true protected=true reason=%q err=nil", tested, protected, reason, err, "object lock enabled")
	}
}

func TestCheckResult_ValidRejectsSkippedWithoutSkipReason(t *testing.T) {
	cr := CheckResult{Check: CheckDeletionProtection, Verdict: "SKIPPED", Simulated: true, Observer: "x"}
	if err := cr.Valid(); err == nil {
		t.Fatal("Valid() = nil, want an error -- SKIPPED must carry one of the 3 recognized SkipReasons")
	}
}

func TestCheckResult_ValidAcceptsPassWithNoSkipReason(t *testing.T) {
	cr := CheckResult{Check: CheckDeletionProtection, Verdict: "PASS", Simulated: true, Observer: "x"}
	if err := cr.Valid(); err != nil {
		t.Fatalf("Valid() = %v, want nil", err)
	}
}
