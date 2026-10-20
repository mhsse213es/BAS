package api

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
)

var approvalT0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func approvalScope() injectionapproval.Scope {
	return injectionapproval.Scope{Kind: injectionapproval.KindInjection, CampaignID: "c1", StageKey: "inject",
		ConnectorID: "dc-elastic", Target: "logs-bas-test", PayloadHash: "sha256:abc",
		TestScope: "one event", ExpectedChange: "marker event appears in index"}
}

// requestAndApprove creates a pending request and approves it as a different user.
func requestAndApprove(t *testing.T, store db.KillChainStore, id string, c injectionapproval.Classification) {
	t.Helper()
	ctx := context.Background()
	if err := store.RequestApproval(ctx, id, "alice", approvalScope(), approvalT0); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := store.ApproveRequest(ctx, id, "bob", c, approvalT0.Add(time.Minute)); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

// Happy path: request, approve by a different user, consume once with the same scope. The
// history records each step in order.
func TestApproval_HappyPathRecordsEachStep(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestAndApprove(t, store, "ap-happy", injectionapproval.Customer)
		if err := store.ConsumeApproval(context.Background(), "ap-happy", "runner", approvalScope(),
			injectionapproval.Customer, approvalT0.Add(2*time.Minute)); err != nil {
			t.Fatalf("consume: %v", err)
		}
		hist, err := store.ApprovalHistory(context.Background(), "ap-happy")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(hist, ",") != "requested,approved,consumed" {
			t.Fatalf("history = %v, want requested,approved,consumed", hist)
		}
	})
}

// Missing approval: a request nobody approved cannot be consumed, and the refusal is recorded.
func TestApproval_MissingApprovalRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		ctx := context.Background()
		if err := store.RequestApproval(ctx, "ap-missing", "alice", approvalScope(), approvalT0); err != nil {
			t.Fatal(err)
		}
		err := store.ConsumeApproval(ctx, "ap-missing", "runner", approvalScope(), injectionapproval.Customer, approvalT0)
		if !errors.Is(err, injectionapproval.ErrNotApproved) {
			t.Fatalf("err = %v, want ErrNotApproved", err)
		}
		hist, _ := store.ApprovalHistory(ctx, "ap-missing")
		if strings.Join(hist, ",") != "requested,refused" {
			t.Fatalf("history = %v, want requested,refused", hist)
		}
	})
}

// Expired: the approval cannot be used at or after its 15-minute window.
func TestApproval_ExpiredRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestAndApprove(t, store, "ap-expired", injectionapproval.Customer)
		late := approvalT0.Add(time.Minute + injectionapproval.ApprovalTTL)
		if err := store.ConsumeApproval(context.Background(), "ap-expired", "runner", approvalScope(), injectionapproval.Customer, late); !errors.Is(err, injectionapproval.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})
}

// Reuse: a second consume of the same approval is refused.
func TestApproval_ReuseRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestAndApprove(t, store, "ap-reuse", injectionapproval.Customer)
		ctx := context.Background()
		now := approvalT0.Add(2 * time.Minute)
		if err := store.ConsumeApproval(ctx, "ap-reuse", "runner", approvalScope(), injectionapproval.Customer, now); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if err := store.ConsumeApproval(ctx, "ap-reuse", "runner", approvalScope(), injectionapproval.Customer, now); !errors.Is(err, injectionapproval.ErrConsumed) {
			t.Fatalf("second consume err = %v, want ErrConsumed", err)
		}
	})
}

// Modified scope: a different target is refused, and the refusal does not spend the approval,
// so the original scope can still be consumed later.
func TestApproval_ModifiedScopeRefusedAndNotSpent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestAndApprove(t, store, "ap-scope", injectionapproval.Customer)
		ctx := context.Background()
		changed := approvalScope()
		changed.Target = "logs-prod"
		if err := store.ConsumeApproval(ctx, "ap-scope", "runner", changed, injectionapproval.Customer, approvalT0.Add(2*time.Minute)); !errors.Is(err, injectionapproval.ErrScopeChanged) {
			t.Fatalf("changed target err = %v, want ErrScopeChanged", err)
		}
		if err := store.ConsumeApproval(ctx, "ap-scope", "runner", approvalScope(), injectionapproval.Customer, approvalT0.Add(2*time.Minute)); err != nil {
			t.Fatalf("original scope refused after a changed-scope attempt: %v", err)
		}
	})
}

// Self-approval: a requester cannot approve their own request in a customer deployment.
func TestApproval_SelfApprovalRefusedInCustomer(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		ctx := context.Background()
		if err := store.RequestApproval(ctx, "ap-self", "alice", approvalScope(), approvalT0); err != nil {
			t.Fatal(err)
		}
		if err := store.ApproveRequest(ctx, "ap-self", "alice", injectionapproval.Customer, approvalT0); !errors.Is(err, injectionapproval.ErrSelfApproval) {
			t.Fatalf("err = %v, want ErrSelfApproval", err)
		}
		if err := store.ConsumeApproval(ctx, "ap-self", "runner", approvalScope(), injectionapproval.Customer, approvalT0); !errors.Is(err, injectionapproval.ErrNotApproved) {
			t.Fatalf("consume after refused self-approval err = %v, want ErrNotApproved", err)
		}
	})
}

// Lab self-approval is accepted only in a lab-classified deployment.
func TestApproval_SelfApprovalAllowedInLab(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		ctx := context.Background()
		if err := store.RequestApproval(ctx, "ap-lab", "alice", approvalScope(), approvalT0); err != nil {
			t.Fatal(err)
		}
		if err := store.ApproveRequest(ctx, "ap-lab", "alice", injectionapproval.Lab, approvalT0); err != nil {
			t.Fatalf("lab self-approval refused: %v", err)
		}
	})
}

// Concurrency: eight consumers race for one approval. Exactly one may succeed.
func TestApproval_ConcurrentConsumersOnlyOneWins(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestAndApprove(t, store, "ap-race", injectionapproval.Customer)
		ctx := context.Background()
		now := approvalT0.Add(2 * time.Minute)
		var wg sync.WaitGroup
		results := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- store.ConsumeApproval(ctx, "ap-race", "runner", approvalScope(), injectionapproval.Customer, now)
			}()
		}
		wg.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("%d consumers succeeded, want exactly 1", wins)
		}
	})
}

// The history is append-only: the database refuses UPDATE and DELETE on it.
func TestApprovalHistory_AppendOnly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := db.KillChainStore{Pool: pool}
		requestAndApprove(t, store, "ap-immutable", injectionapproval.Customer)
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `UPDATE pipeline_approval_events SET actor='someone-else' WHERE approval_id='ap-immutable'`); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("update err = %v, want append-only refusal", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM pipeline_approval_events WHERE approval_id='ap-immutable'`); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("delete err = %v, want append-only refusal", err)
		}
	})
}
