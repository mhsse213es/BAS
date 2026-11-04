package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
	"github.com/audspect/bas/internal/testutil"
)

// A forced audit failure (a NUL byte cannot be stored in jsonb) leaves no approval and no switch change behind.
func TestK8sLifecycle_AuditFailureLeavesNothingChanged(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureK8sScenarioSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Format("150405.000000")
		apprID := "appr-atomic-" + stamp
		runID := "k8sr-atomic-" + stamp
		approvals := db.NewK8sApprovalStore(pool)
		switches := db.NewK8sControlledSwitchStore(pool)

		// The run must exist for the approval's foreign key to be meaningful in production; here only the
		// approval row is under test, so insert the run first.
		if err := db.NewK8sRunStore(pool).InsertRun(ctx, db.K8sRunRecord{ID: runID, RequesterID: "op-1",
			Cluster: "kind-bas-lab", ClusterID: "k8sc-lab", Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled",
			Params: map[string]string{}, ParamsHash: "h", State: "PLANNED", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM k8s_scenario_approvals WHERE id = $1`, apprID)
			_, _ = pool.Exec(ctx, `DELETE FROM k8s_scenario_runs WHERE id = $1`, runID)
		})

		a := k8sscenario.Approval{ID: apprID, ApproverID: "op-2", RequesterID: "op-1", RunID: runID,
			ClusterID: "k8sc-lab", AuthorizationID: "k8sa-1", CustomerRef: "cust-1", Cluster: "kind-bas-lab",
			Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled", ParamsHash: "h",
			ApprovedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(15 * time.Minute).UTC()}
		bad := k8sscenario.Event{Type: k8sscenario.EventApproved, RunID: runID,
			Fields: map[string]string{"params": "bad\x00value"}}
		if err := approvals.PutWithAudit(a, bad); err == nil {
			t.Fatal("an approval whose audit cannot be written must be refused")
		}
		if _, ok, _ := approvals.Get(apprID); ok {
			t.Fatal("no approval may exist without its audit record")
		}

		// The same approval with a valid audit record is stored.
		good := k8sscenario.ApprovalEvent(a, map[string]string{"name": "bas-fixture"})
		if err := approvals.PutWithAudit(a, good); err != nil {
			t.Fatalf("approval with audit: %v", err)
		}
		if _, ok, _ := approvals.Get(apprID); !ok {
			t.Fatal("approval with audit must be stored")
		}

		// The switch: a set that cannot be audited does not change the state.
		if err := switches.Set(ctx, true, "admin-1", time.Now(), k8sscenario.Event{Type: "k8s.controlled.switch",
			Fields: map[string]string{"x": "bad\x00"}}); err == nil {
			t.Fatal("a switch change whose audit cannot be written must be refused")
		}
		if on, _ := switches.Enabled(ctx); on {
			t.Fatal("the switch must stay off when its audit cannot be written")
		}
		// Default is off; a valid change is applied and read back.
		if err := switches.Set(ctx, true, "admin-1", time.Now(), k8sscenario.ControlledSwitchEvent(true, "admin-1", time.Now())); err != nil {
			t.Fatalf("switch on: %v", err)
		}
		if on, _ := switches.Enabled(ctx); !on {
			t.Fatal("switch on must read back on")
		}
		if err := switches.Set(ctx, false, "admin-1", time.Now(), k8sscenario.ControlledSwitchEvent(false, "admin-1", time.Now())); err != nil {
			t.Fatalf("switch off: %v", err)
		}
		if on, _ := switches.Enabled(ctx); on {
			t.Fatal("switch off must read back off")
		}
	})
}
