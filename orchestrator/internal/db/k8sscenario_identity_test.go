package db_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
	"github.com/audspect/bas/internal/testutil"
)

// TestK8sRunIdentity_RoundTripsAndIsImmutable checks the execution identity (registry cluster ID, authorization,
// customer) survives insert and approval, and that the database refuses any later change to it. A status update must
// still succeed.
func TestK8sRunIdentity_RoundTripsAndIsImmutable(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureK8sScenarioSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Format("150405.000000")
		runID := "k8sr-id-" + stamp
		apprID := "appr-id-" + stamp
		runs := db.NewK8sRunStore(pool)
		approvals := db.NewK8sApprovalStore(pool)

		rec := db.K8sRunRecord{ID: runID, RequesterID: "op-1", Cluster: "kind-bas-lab", ClusterID: "k8sc-lab",
			AuthorizationID: "k8sa-1", CustomerRef: "cust-1", Namespace: "bas-sandbox",
			ActionID: "configmap-patch-labelled", Params: map[string]string{"name": "bas-fixture"},
			ParamsHash: "h", State: "PLANNED", Detail: "plan", CreatedAt: time.Now().UTC()}
		if err := runs.InsertRun(ctx, rec); err != nil {
			t.Fatal(err)
		}
		a := k8sscenario.Approval{ID: apprID, ApproverID: "op-2", RequesterID: "op-1", RunID: runID,
			ClusterID: "k8sc-lab", AuthorizationID: "k8sa-1", CustomerRef: "cust-1", Cluster: "kind-bas-lab",
			Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled", ParamsHash: "h",
			ApprovedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(15 * time.Minute).UTC()}
		if err := approvals.Put(a); err != nil {
			t.Fatal(err)
		}

		got, ok, err := runs.GetRun(ctx, runID)
		if err != nil || !ok {
			t.Fatalf("GetRun: ok=%v err=%v", ok, err)
		}
		if got.ClusterID != "k8sc-lab" || got.AuthorizationID != "k8sa-1" || got.CustomerRef != "cust-1" {
			t.Fatalf("run identity not persisted: %+v", got)
		}
		gotA, ok, err := approvals.Get(apprID)
		if err != nil || !ok {
			t.Fatalf("approval Get: ok=%v err=%v", ok, err)
		}
		if gotA.ClusterID != "k8sc-lab" || gotA.AuthorizationID != "k8sa-1" || gotA.CustomerRef != "cust-1" {
			t.Fatalf("approval identity not persisted: %+v", gotA)
		}

		// A status update that leaves the identity alone must succeed.
		got.ApprovalID = apprID
		got.State = "APPROVED"
		if err := runs.UpdateRun(ctx, got); err != nil {
			t.Fatalf("status update refused: %v", err)
		}

		// Any change to the identity is refused by the database.
		for _, q := range []string{
			`UPDATE k8s_scenario_runs SET cluster_id = 'k8sc-other' WHERE id = $1`,
			`UPDATE k8s_scenario_runs SET authorization_id = 'k8sa-other' WHERE id = $1`,
			`UPDATE k8s_scenario_runs SET customer_ref = 'cust-other' WHERE id = $1`,
			`UPDATE k8s_scenario_runs SET params_hash = 'changed' WHERE id = $1`,
		} {
			_, err := pool.Exec(ctx, q, runID)
			if err == nil || !strings.Contains(err.Error(), "execution identity is immutable") {
				t.Errorf("%s: want the identity to be refused, got %v", q, err)
			}
		}
		_, err = pool.Exec(ctx, `UPDATE k8s_scenario_approvals SET cluster_id = 'k8sc-other' WHERE id = $1`, apprID)
		if err == nil || !strings.Contains(err.Error(), "execution identity is immutable") {
			t.Errorf("approval cluster_id change: want refusal, got %v", err)
		}
	})
}
