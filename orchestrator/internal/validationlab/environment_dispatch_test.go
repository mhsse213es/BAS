package validationlab

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
)

// An offline or busy lab agent says nothing about the content, so a dispatch refused for those reasons must not use
// up the validation attempt cap. Before this, 94 generated drafts reached the cap of 3 on staging without one of them
// ever running, and stayed DRAFT for a person to change.

func TestIsEnvironmentalDispatchFailure(t *testing.T) {
	cases := map[string]bool{
		"offline":           true,
		"agent busy":        true,
		"agent retired":     true,
		"agent quarantined": true,
		"build steps: ART: no windows steps found": false,
		"os mismatch": false,
		"":            false,
	}
	for reason, want := range cases {
		if got := isEnvironmentalDispatchFailure(reason); got != want {
			t.Errorf("isEnvironmentalDispatchFailure(%q) = %v, want %v", reason, got, want)
		}
	}
}

func TestRefundAttempt_EnvironmentalFailureKeepsCapForRealFailures(t *testing.T) {
	o := NewOrchestrator(nil, nil, nil, "lab", 0)
	o.retryBackoff = 0
	for i := 0; i < contentregistry.MaxValidationAttempts+2; i++ {
		if !o.mayAttempt("v1") {
			t.Fatalf("attempt %d refused although every earlier one was an environmental refusal", i)
		}
		o.noteAttempt("v1")
		o.refundAttempt("v1")
	}
	for i := 0; i < contentregistry.MaxValidationAttempts; i++ {
		o.noteAttempt("v1")
	}
	if o.mayAttempt("v1") {
		t.Fatal("after the cap of real attempts the version must not be attempted again")
	}
}

func TestMayAttempt_BackoffAppliesAfterRefund(t *testing.T) {
	o := NewOrchestrator(nil, nil, nil, "lab", 0)
	o.retryBackoff = time.Hour
	o.noteAttempt("v2")
	o.refundAttempt("v2")
	if o.mayAttempt("v2") {
		t.Fatal("a refused dispatch must still wait the backoff, or the queue stalls on one draft")
	}
}

func TestRunOnce_OfflineLabDoesNotExhaustAttemptCap(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := newTestRegistry(t, pool)
		ctx := context.Background()

		draft := mustCreateDraftVersion(t, reg, pool, contentregistry.ActorGenerator, "vl-offline-cap", nonDestructiveArtifact("vl-offline-cap"))

		o := NewOrchestrator(pool, reg, &fakeDispatcher{skipReason: "offline"}, "vl-lab-agent-offline-cap", 0)
		o.retryBackoff = 0
		for i := 0; i < contentregistry.MaxValidationAttempts+2; i++ {
			if err := o.runOnce(ctx); err != nil {
				t.Fatalf("runOnce %d: %v", i, err)
			}
		}

		assertLifecycle(t, reg, draft, contentregistry.LifecycleDraft)
		ids, err := o.selectEligible(ctx)
		if err != nil {
			t.Fatalf("selectEligible: %v", err)
		}
		found := false
		for _, id := range ids {
			if id == draft {
				found = true
			}
		}
		if !found {
			t.Fatal("an offline lab agent used up the attempt cap: the draft is no longer eligible once the lab is back")
		}
	})
}
