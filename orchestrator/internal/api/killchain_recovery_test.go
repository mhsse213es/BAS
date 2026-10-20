package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
	"github.com/audspect/bas/internal/pipelinecheck"
)

func historyOf(t *testing.T, store db.KillChainStore, id string) string {
	t.Helper()
	h, err := store.ApprovalHistory(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(h, ",")
}

// A completed write is recorded as executed in the approval history.
func TestInjectionGate_RecordsExecutedOutcome(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "rec-ok", scope, injectionapproval.Customer)
		res := runGatedInjection(context.Background(), store, "rec-ok", "runner", scope, injectionapproval.Customer,
			injT0.Add(2*time.Minute), &fakeInjector{supported: true}, injRequest("logs-bas"))
		if res.Status != "EXECUTED" {
			t.Fatalf("result = %+v", res)
		}
		if got := historyOf(t, store, "rec-ok"); got != "requested,approved,consumed,executed" {
			t.Fatalf("history = %s", got)
		}
	})
}

// A failed write is recorded as failed. The approval stays spent.
func TestInjectionGate_RecordsFailedOutcome(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "rec-fail", scope, injectionapproval.Customer)
		res := runGatedInjection(context.Background(), store, "rec-fail", "runner", scope, injectionapproval.Customer,
			injT0.Add(2*time.Minute), &fakeInjector{supported: true, err: errors.New("reset")}, injRequest("logs-bas"))
		if res.Status != "ERROR" {
			t.Fatalf("result = %+v", res)
		}
		if got := historyOf(t, store, "rec-fail"); got != "requested,approved,consumed,failed" {
			t.Fatalf("history = %s", got)
		}
	})
}

// Crash between consumption and execution: the approval is consumed with no outcome. The operator
// sees it as unknown. It is not reused, and an outcome cannot be written for it retroactively
// without a consumption.
func TestInjectionGate_InterruptedApprovalIsUnknownAndNotReused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "rec-crash", scope, injectionapproval.Customer)
		ctx := context.Background()
		now := injT0.Add(2 * time.Minute)
		// The process consumes the approval, then stops before writing or recording anything.
		if err := store.ConsumeApproval(ctx, "rec-crash", "runner", scope, injectionapproval.Customer, now); err != nil {
			t.Fatalf("consume: %v", err)
		}
		if got := historyOf(t, store, "rec-crash"); got != "requested,approved,consumed" {
			t.Fatalf("history = %s; an interrupted run must show no outcome", got)
		}
		// A restarted process cannot use it again. Recovery is a new request and approval.
		inj := &fakeInjector{supported: true}
		res := runGatedInjection(ctx, store, "rec-crash", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-bas"))
		if res.Status != "NOT_TESTED" || inj.calls != 0 {
			t.Fatalf("reuse after interruption: %+v calls=%d, want NOT_TESTED and no write", res, inj.calls)
		}
		if err := store.RecordExecutionOutcome(ctx, "rec-crash", "ops", "executed", now); err != nil {
			t.Fatalf("recording the outcome of the consumed approval: %v", err)
		}
	})
}

// An outcome cannot be recorded for an approval that was never consumed.
func TestRecordExecutionOutcome_RequiresConsumption(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestApproved(t, store, "rec-unconsumed", injScope(t, "logs-bas"), injectionapproval.Customer)
		if err := store.RecordExecutionOutcome(context.Background(), "rec-unconsumed", "ops", "executed", injT0); err == nil {
			t.Fatal("outcome recorded for an approval that was never consumed")
		}
	})
}

// The scope hash is stable across repeated computation of the same payload, so an approval made
// from one computation matches a later one.
func TestPayloadHash_StableAcrossCalls(t *testing.T) {
	doc := map[string]any{"b": 2, "a": map[string]any{"z": 1, "y": 2}, "c": []any{"x", "y"}}
	first := ""
	for i := 0; i < 50; i++ {
		tagged, err := pipelinecheck.TagDocument(doc, injRunID)
		if err != nil {
			t.Fatal(err)
		}
		h, err := pipelinecheck.PayloadHash(tagged)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = h
		} else if h != first {
			t.Fatalf("hash changed between calls: %s vs %s", first, h)
		}
	}
}
