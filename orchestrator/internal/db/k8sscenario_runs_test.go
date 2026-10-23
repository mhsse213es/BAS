package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/k8sscenario"
)

// TestK8sRunStore_RoundTripsParamsAndApprovalLink checks a run survives insert, approval link and update.
func TestK8sRunStore_RoundTripsParamsAndApprovalLink(t *testing.T) {
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
	stamp := time.Now().Format("150405.000000")
	runID := "k8sr-rt-" + stamp
	apprID := "appr-rt-" + stamp
	runs := NewK8sRunStore(pool)
	approvals := NewK8sApprovalStore(pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM k8s_scenario_runs WHERE id = $1`, runID)
		_, _ = pool.Exec(ctx, `DELETE FROM k8s_scenario_approvals WHERE id = $1`, apprID)
	})

	rec := K8sRunRecord{ID: runID, RequesterID: "op-1", Cluster: "kind-bas-lab", Namespace: "bas-sandbox",
		ActionID: "configmap-patch-labelled", Params: map[string]string{"name": "bas-fixture", "value": "x"},
		ParamsHash: "h", State: "PLANNED", Detail: "plan", CreatedAt: time.Now().UTC()}
	if err := runs.InsertRun(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := approvals.Put(k8sApprovalFor(apprID, runID)); err != nil {
		t.Fatal(err)
	}
	rec.ApprovalID = apprID
	rec.State = "APPROVED"
	if err := runs.UpdateRun(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, ok, err := runs.GetRun(ctx, runID)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.State != "APPROVED" || got.ApprovalID != apprID || got.Params["value"] != "x" || got.Detail != "plan" {
		t.Fatalf("round trip = %+v", got)
	}
	list, err := runs.ListRuns(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range list {
		if r.ID == runID {
			found = true
		}
	}
	if !found {
		t.Fatal("the run is missing from the list")
	}
}

func k8sApprovalFor(id, runID string) k8sscenario.Approval {
	return k8sscenario.Approval{ID: id, ApproverID: "op-2", RequesterID: "op-1", RunID: runID, Cluster: "kind-bas-lab",
		Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled", ParamsHash: "h", ExpiresAt: time.Now().Add(time.Hour)}
}
