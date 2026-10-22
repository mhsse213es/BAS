package db

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/k8sscenario"
)

// TestK8sApprovalStore_MarkUsedIsSingleUseUnderConcurrency checks the database, not Go code, enforces single use:
// two concurrent consumers of one approval must produce exactly one success.
func TestK8sApprovalStore_MarkUsedIsSingleUseUnderConcurrency(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := EnsureK8sScenarioSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := NewK8sApprovalStore(pool)
	id := "appr-test-" + time.Now().Format("150405.000000")
	a := k8sscenario.Approval{ID: id, ApproverID: "operator-2", RequesterID: "operator-1", RunID: "run-x", Cluster: "kind-bas-lab",
		Namespace: "bas-sandbox", ActionID: "pod-create-unprivileged", ParamsHash: "h", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Put(a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM k8s_scenario_approvals WHERE id = $1`, id) })

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.MarkUsed(id) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("successful consumptions = %d, want exactly 1", ok)
	}
}

// TestK8sApprovalStore_RefusesSelfApprovalAtTheDatabase checks the CHECK constraint, independent of the Go gate.
func TestK8sApprovalStore_RefusesSelfApprovalAtTheDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := EnsureK8sScenarioSchema(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := NewK8sApprovalStore(pool)
	err = store.Put(k8sscenario.Approval{ID: "appr-self-" + time.Now().Format("150405.000000"), ApproverID: "op-1", RequesterID: "op-1",
		RunID: "r", Cluster: "c", Namespace: "n", ActionID: "a", ParamsHash: "h", ExpiresAt: time.Now().Add(time.Hour)})
	if err == nil {
		t.Fatal("the database must refuse an approval where approver equals requester")
	}
}
