package k8sscenario

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLive_KindLab runs the engine against the real kind lab with the scenario credential. It is skipped unless
// the lab is configured:
//
//	KUBE_LAB_API          https URL of the kind API server
//	SCENARIO_TOKEN_FILE   token of the scenario ServiceAccount (bas-scenario/bas-scenario-runner), never printed
//	KUBE_LAB_CA_FILE      cluster CA (PEM)
//
// The lab must have namespace bas-sandbox labelled as a sandbox, and a fixture ConfigMap bas-fixture labelled
// as a sandbox fixture with data.state=original.
func TestLive_KindLab(t *testing.T) {
	api := os.Getenv("KUBE_LAB_API")
	tokenFile := os.Getenv("SCENARIO_TOKEN_FILE")
	caFile := os.Getenv("KUBE_LAB_CA_FILE")
	if api == "" || tokenFile == "" || caFile == "" {
		t.Skip("lab not configured")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewAPIClient(ClientConfig{APIServer: api, Token: strings.TrimSpace(string(tokenBytes)), CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const cluster = "kind-bas-lab"

	store := newMemApprovals()
	audit := &recordAudit{}
	cfg := Config{
		AllowedClusters:   map[string]string{cluster: api},
		AllowedNamespaces: []string{"bas-sandbox"},
		Client:            client,
		Audit:             audit,
		Alert:             &recordAlert{},
		Approvals:         store,
		ApproverPermitted: func(id string) bool { return id == "operator-2" },
		Now:               time.Now,
	}
	engine := NewEngine(cfg)
	approve := func(id, runID, action string, params map[string]string) string {
		_ = store.Put(Approval{ID: id, ApproverID: "operator-2", RequesterID: "operator-1", RunID: runID, Cluster: cluster,
			Namespace: "bas-sandbox", ActionID: action, ParamsHash: HashParams(params), ExpiresAt: time.Now().Add(15 * time.Minute)})
		return id
	}
	podRun := func(runID string, live bool) RunRequest {
		return RunRequest{RunID: runID, Requester: "operator-1", Cluster: ClusterRef{Name: cluster, Server: api},
			Namespace: "bas-sandbox", ActionID: "pod-create-unprivileged", Params: map[string]string{"name": "bas-sbx-lab-" + runID}, Live: live}
	}
	podGone := func(name string) bool {
		_, exists, err := client.Get(ctx, ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: name})
		return err == nil && !exists
	}

	t.Run("dry run plans and writes nothing", func(t *testing.T) {
		req := podRun("dry-1", false)
		res := engine.Run(ctx, req)
		if res.State != StateDryRunPlanned || len(res.Plan) == 0 {
			t.Fatalf("state=%s plan=%v", res.State, res.Plan)
		}
		if !podGone("bas-sbx-lab-dry-1") {
			t.Fatal("dry run created a pod")
		}
	})

	t.Run("live pod run with approval is verified and cleaned up", func(t *testing.T) {
		req := podRun("live-1", true)
		req.ApprovalID = approve("appr-live-1", req.RunID, req.ActionID, req.Params)
		res := engine.Run(ctx, req)
		if res.State != StateCleaned || !res.Verified {
			t.Fatalf("state=%s verified=%v err=%q", res.State, res.Verified, res.Error)
		}
		if !podGone("bas-sbx-lab-live-1") {
			t.Fatal("the pod was not removed after the run")
		}
	})

	t.Run("live pod run without approval is refused and creates nothing", func(t *testing.T) {
		req := podRun("noappr-1", true)
		res := engine.Run(ctx, req)
		if res.State != StateRefused {
			t.Fatalf("state=%s, want refused", res.State)
		}
		if !podGone("bas-sbx-lab-noappr-1") {
			t.Fatal("a refused run created a pod")
		}
	})

	t.Run("self-approval is refused and creates nothing", func(t *testing.T) {
		req := podRun("self-1", true)
		_ = store.Put(Approval{ID: "appr-self-1", ApproverID: "operator-1", RequesterID: "operator-1", RunID: req.RunID,
			Cluster: cluster, Namespace: "bas-sandbox", ActionID: req.ActionID, ParamsHash: HashParams(req.Params), ExpiresAt: time.Now().Add(time.Minute)})
		req.ApprovalID = "appr-self-1"
		if res := engine.Run(ctx, req); res.State != StateRefused {
			t.Fatalf("state=%s, want refused", res.State)
		}
		if !podGone("bas-sbx-lab-self-1") {
			t.Fatal("a self-approved run created a pod")
		}
	})

	t.Run("configmap patch is restored to the prior value", func(t *testing.T) {
		params := map[string]string{"name": "bas-fixture", "value": "lab-changed"}
		req := RunRequest{RunID: "cm-1", Requester: "operator-1", Cluster: ClusterRef{Name: cluster, Server: api},
			Namespace: "bas-sandbox", ActionID: "configmap-patch-labelled", Params: params, Live: true}
		req.ApprovalID = approve("appr-cm-1", req.RunID, req.ActionID, params)
		res := engine.Run(ctx, req)
		if res.State != StateCleaned || !res.Verified {
			t.Fatalf("state=%s verified=%v err=%q", res.State, res.Verified, res.Error)
		}
		obj, exists, err := client.Get(ctx, ObjectRef{Kind: "ConfigMap", Namespace: "bas-sandbox", Name: "bas-fixture"})
		if err != nil || !exists || obj.Data["state"] != "original" {
			t.Fatalf("fixture state=%q exists=%v err=%v, want original", obj.Data["state"], exists, err)
		}
	})

	if n := len(audit.events); n == 0 {
		t.Fatal("no audit events were written")
	}
}
