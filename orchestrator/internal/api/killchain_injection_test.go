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

// fakeInjector writes nothing. It counts calls and remembers the last document it was given.
type fakeInjector struct {
	supported bool
	calls     int
	last      map[string]any
	err       error
}

func (f *fakeInjector) Supported() bool { return f.supported }

func (f *fakeInjector) Inject(_ context.Context, req pipelinecheck.InjectionRequest) (pipelinecheck.InjectionOutcome, error) {
	f.calls++
	f.last = req.Document
	if f.err != nil {
		return pipelinecheck.InjectionOutcome{}, f.err
	}
	return pipelinecheck.InjectionOutcome{Status: "EXECUTED", Reason: "written"}, nil
}

var injT0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const injRunID = "bas-0123456789abcdef0123456789abcdef"

func injDoc() map[string]any {
	return map[string]any{"event": map[string]any{"action": "bas-probe"}, "message": "bas probe"}
}

// injScope returns the scope an approver would see for this request: the tagged payload's hash.
func injScope(t *testing.T, index string) injectionapproval.Scope {
	t.Helper()
	tagged, err := pipelinecheck.TagDocument(injDoc(), injRunID)
	if err != nil {
		t.Fatal(err)
	}
	h, err := pipelinecheck.PayloadHash(tagged)
	if err != nil {
		t.Fatal(err)
	}
	return injectionapproval.Scope{Kind: injectionapproval.KindInjection, CampaignID: "c1", StageKey: "inject",
		ConnectorID: "dc-elastic", Target: index, PayloadHash: h, TestScope: "one record",
		ExpectedChange: "tagged record is searchable by run identifier"}
}

func injRequest(index string) pipelinecheck.InjectionRequest {
	return pipelinecheck.InjectionRequest{RunID: injRunID, Index: index, Document: injDoc()}
}

// requestApproved creates an approval for the scope, approved by a different user.
func requestApproved(t *testing.T, store db.KillChainStore, id string, scope injectionapproval.Scope, c injectionapproval.Classification) {
	t.Helper()
	ctx := context.Background()
	if err := store.RequestApproval(ctx, id, "alice", scope, injT0); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := store.ApproveRequest(ctx, id, "bob", c, injT0.Add(time.Minute)); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

// A valid, unexpired, unused approval for the exact scope: the record is tagged and written once.
func TestInjectionGate_ValidApprovalWritesTaggedRecordOnce(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-ok", scope, injectionapproval.Customer)
		inj := &fakeInjector{supported: true}
		res := runGatedInjection(context.Background(), store, "inj-ok", "runner", scope, injectionapproval.Customer,
			injT0.Add(2*time.Minute), inj, injRequest("logs-bas"))
		if res.Status != "EXECUTED" || inj.calls != 1 {
			t.Fatalf("result = %+v calls = %d, want EXECUTED once", res, inj.calls)
		}
		audspect, _ := inj.last["audspect"].(map[string]any)
		tags, _ := inj.last["tags"].([]string)
		if audspect["test_run"] != injRunID || len(tags) != 1 || tags[0] != pipelinecheck.MarkerTag {
			t.Fatalf("written document lacks the run identifier and marker: %v", inj.last)
		}
	})
}

// No approval ID is never a reason to write. A campaign launch supplies none.
func TestInjectionGate_NoApprovalNeverWrites(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		inj := &fakeInjector{supported: true}
		res := runGatedInjection(context.Background(), store, "", "runner", injScope(t, "logs-bas"),
			injectionapproval.Customer, injT0, inj, injRequest("logs-bas"))
		if res.Status != "NOT_TESTED" || inj.calls != 0 || !strings.Contains(res.Reason, "campaign launch") {
			t.Fatalf("result = %+v calls = %d, want NOT_TESTED with no write", res, inj.calls)
		}
	})
}

// A requested but never approved record is refused, and nothing is written.
func TestInjectionGate_UnapprovedRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		if err := store.RequestApproval(context.Background(), "inj-unapproved", "alice", scope, injT0); err != nil {
			t.Fatal(err)
		}
		inj := &fakeInjector{supported: true}
		res := runGatedInjection(context.Background(), store, "inj-unapproved", "runner", scope,
			injectionapproval.Customer, injT0.Add(time.Minute), inj, injRequest("logs-bas"))
		if res.Status != "NOT_TESTED" || inj.calls != 0 || !strings.Contains(res.Reason, "not approved") {
			t.Fatalf("result = %+v calls = %d, want NOT_TESTED, not approved, no write", res, inj.calls)
		}
	})
}

// An expired approval is refused and nothing is written.
func TestInjectionGate_ExpiredRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-expired", scope, injectionapproval.Customer)
		inj := &fakeInjector{supported: true}
		late := injT0.Add(time.Minute + injectionapproval.ApprovalTTL)
		res := runGatedInjection(context.Background(), store, "inj-expired", "runner", scope,
			injectionapproval.Customer, late, inj, injRequest("logs-bas"))
		if res.Status != "NOT_TESTED" || inj.calls != 0 || !strings.Contains(res.Reason, "expired") {
			t.Fatalf("result = %+v calls = %d, want NOT_TESTED, expired, no write", res, inj.calls)
		}
	})
}

// A reused approval is refused on the second use. The record is written once in total.
func TestInjectionGate_ReusedRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-reuse", scope, injectionapproval.Customer)
		inj := &fakeInjector{supported: true}
		ctx := context.Background()
		now := injT0.Add(2 * time.Minute)
		first := runGatedInjection(ctx, store, "inj-reuse", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-bas"))
		second := runGatedInjection(ctx, store, "inj-reuse", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-bas"))
		if first.Status != "EXECUTED" || second.Status != "NOT_TESTED" || inj.calls != 1 {
			t.Fatalf("first=%+v second=%+v calls=%d, want one write and one refusal", first, second, inj.calls)
		}
	})
}

// A modified scope is refused before the approval is spent, so the original can still be used.
func TestInjectionGate_ModifiedScopeRefusedAndNotSpent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-modified", scope, injectionapproval.Customer)
		inj := &fakeInjector{supported: true}
		ctx := context.Background()
		now := injT0.Add(2 * time.Minute)

		// A different target than the approved one.
		res := runGatedInjection(ctx, store, "inj-modified", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-prod"))
		if res.Status != "NOT_TESTED" || inj.calls != 0 {
			t.Fatalf("changed target: %+v calls=%d, want NOT_TESTED, no write", res, inj.calls)
		}
		// The approval was not spent by the mismatched attempt, so the matching one still works.
		res = runGatedInjection(ctx, store, "inj-modified", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-bas"))
		if res.Status != "EXECUTED" || inj.calls != 1 {
			t.Fatalf("matching attempt after a refused one: %+v calls=%d, want one write", res, inj.calls)
		}
	})
}

// A different payload than the approved one is refused: the payload hash is part of the scope.
func TestInjectionGate_ChangedPayloadRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-payload", scope, injectionapproval.Customer)
		inj := &fakeInjector{supported: true}
		req := injRequest("logs-bas")
		req.Document = map[string]any{"event": map[string]any{"action": "something-else"}}
		res := runGatedInjection(context.Background(), store, "inj-payload", "runner", scope,
			injectionapproval.Customer, injT0.Add(2*time.Minute), inj, req)
		if res.Status != "NOT_TESTED" || inj.calls != 0 {
			t.Fatalf("changed payload: %+v calls=%d, want NOT_TESTED, no write", res, inj.calls)
		}
	})
}

// Self-approval in a customer deployment never gets as far as a write: the approval cannot exist.
func TestInjectionGate_SelfApprovedCustomerNeverWrites(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		ctx := context.Background()
		if err := store.RequestApproval(ctx, "inj-self", "alice", scope, injT0); err != nil {
			t.Fatal(err)
		}
		if err := store.ApproveRequest(ctx, "inj-self", "alice", injectionapproval.Customer, injT0); !errors.Is(err, injectionapproval.ErrSelfApproval) {
			t.Fatalf("self-approval err = %v, want ErrSelfApproval", err)
		}
		inj := &fakeInjector{supported: true}
		res := runGatedInjection(ctx, store, "inj-self", "runner", scope, injectionapproval.Customer, injT0.Add(time.Minute), inj, injRequest("logs-bas"))
		if res.Status != "NOT_TESTED" || inj.calls != 0 {
			t.Fatalf("self-approved: %+v calls=%d, want NOT_TESTED, no write", res, inj.calls)
		}
	})
}

// A provider with no write adapter reports NOT_TESTED, and does not spend the approval.
func TestInjectionGate_UnsupportedProviderDoesNotSpendApproval(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-unsupported", scope, injectionapproval.Customer)
		ctx := context.Background()
		now := injT0.Add(2 * time.Minute)
		res := runGatedInjection(ctx, store, "inj-unsupported", "runner", scope, injectionapproval.Customer, now,
			pipelinecheck.UnsupportedInjector{Provider: "elastic"}, injRequest("logs-bas"))
		if res.Status != "NOT_TESTED" || !strings.Contains(res.Reason, "no injection adapter") {
			t.Fatalf("unsupported: %+v, want NOT_TESTED naming the missing adapter", res)
		}
		inj := &fakeInjector{supported: true}
		if res := runGatedInjection(ctx, store, "inj-unsupported", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-bas")); res.Status != "EXECUTED" {
			t.Fatalf("approval was spent by the unsupported attempt: %+v", res)
		}
	})
}

// A write that fails after the approval is used is an ERROR, not a silent NOT_TESTED, and the
// approval stays spent.
func TestInjectionGate_WriteFailureIsErrorAndApprovalStaysSpent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		scope := injScope(t, "logs-bas")
		requestApproved(t, store, "inj-fail", scope, injectionapproval.Customer)
		ctx := context.Background()
		now := injT0.Add(2 * time.Minute)
		inj := &fakeInjector{supported: true, err: errors.New("connection reset")}
		res := runGatedInjection(ctx, store, "inj-fail", "runner", scope, injectionapproval.Customer, now, inj, injRequest("logs-bas"))
		if res.Status != "ERROR" {
			t.Fatalf("write failure: %+v, want ERROR", res)
		}
		again := runGatedInjection(ctx, store, "inj-fail", "runner", scope, injectionapproval.Customer, now, &fakeInjector{supported: true}, injRequest("logs-bas"))
		if again.Status != "NOT_TESTED" || !strings.Contains(again.Reason, "already used") {
			t.Fatalf("approval after a failed write: %+v, want refused as already used", again)
		}
	})
}
