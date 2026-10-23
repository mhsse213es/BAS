package k8sscenario

import (
	"context"
	"errors"
	"os"
	"os/exec"
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

// revokeBeforeDelete is a Client wrapper. Just before the engine's rollback delete, it removes the delete verb
// from the scenario Role using the lab admin context. The delete is then sent for real and refused by the server.
type revokeBeforeDelete struct {
	Client
	revoke func() error
}

func (r revokeBeforeDelete) Delete(ctx context.Context, ref ObjectRef) error {
	if err := r.revoke(); err != nil {
		return err
	}
	return r.Client.Delete(ctx, ref)
}

// TestLive_RollbackFailure removes the scenario's delete permission during a run, so the real rollback is refused
// by the API server. The engine must end in CLEANUP_FAILED, alert, keep the evidence, and leave the pod in place
// until the operator removes it. The Role is restored and the pod removed afterwards.
func TestLive_RollbackFailure(t *testing.T) {
	api := os.Getenv("KUBE_LAB_API")
	tokenFile := os.Getenv("SCENARIO_TOKEN_FILE")
	caFile := os.Getenv("KUBE_LAB_CA_FILE")
	if api == "" || tokenFile == "" || caFile == "" {
		t.Skip("lab not configured")
	}
	adminCtx := os.Getenv("KUBE_LAB_KUBECTL_CONTEXT")
	if adminCtx == "" {
		adminCtx = "kind-bas-lab"
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
	const pod = "bas-sbx-lab-rbf-1"

	admin := func(args ...string) (string, error) {
		out, err := exec.Command("kubectl", append([]string{"--context", adminCtx}, args...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	setVerbs := func(verbs string) error {
		patch := `[{"op":"replace","path":"/rules/0/verbs","value":` + verbs + `}]`
		out, err := admin("patch", "role", "bas-scenario-sandbox", "-n", "bas-sandbox", "--type=json", "-p", patch)
		if err != nil {
			return errors.New("admin patch failed: " + out)
		}
		return nil
	}
	restoreRole := func() {
		if err := setVerbs(`["create","get","delete"]`); err != nil {
			t.Errorf("restoring the scenario Role failed: %v", err)
		}
	}
	// The Role's rules[0] holds pod verbs. Restore it regardless of outcome.
	if err := setVerbs(`["create","get","delete"]`); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	t.Cleanup(func() {
		restoreRole()
		_, _ = admin("delete", "pod", pod, "-n", "bas-sandbox", "--ignore-not-found")
	})

	store := newMemApprovals()
	alert := &recordAlert{}
	params := map[string]string{"name": pod}
	req := RunRequest{RunID: "rbf-1", Requester: "operator-1", Cluster: ClusterRef{Name: cluster, Server: api},
		Namespace: "bas-sandbox", ActionID: "pod-create-unprivileged", Params: params, Live: true, ApprovalID: "appr-rbf-1"}
	_ = store.Put(Approval{ID: "appr-rbf-1", ApproverID: "operator-2", RequesterID: "operator-1", RunID: req.RunID, Cluster: cluster,
		Namespace: "bas-sandbox", ActionID: req.ActionID, ParamsHash: HashParams(params), ExpiresAt: time.Now().Add(15 * time.Minute)})

	wrapped := revokeBeforeDelete{Client: client, revoke: func() error { return setVerbs(`["create","get"]`) }}
	cfg := Config{
		AllowedClusters:   map[string]string{cluster: api},
		AllowedNamespaces: []string{"bas-sandbox"},
		Client:            wrapped,
		Audit:             &recordAudit{},
		Alert:             alert,
		Approvals:         store,
		ApproverPermitted: func(id string) bool { return id == "operator-2" },
		Now:               time.Now,
	}
	res := NewEngine(cfg).Run(ctx, req)

	if res.State != StateCleanupFailed {
		t.Fatalf("state = %s (%q), want %s: a refused rollback must not be reported as cleaned up", res.State, res.Error, StateCleanupFailed)
	}
	if len(alert.msgs) == 0 {
		t.Fatal("the operator was not alerted")
	}
	// The pod must still exist: the rollback really was refused by the server, not skipped.
	obj, exists, err := client.Get(ctx, ObjectRef{Kind: "Pod", Namespace: "bas-sandbox", Name: pod})
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("pod is gone, but the rollback was refused; object=%+v", obj)
	}
	t.Logf("CLEANUP_FAILED as expected; pod %s left in place; alert: %s", pod, alert.msgs[0])
}

// TestLive_TokenProbe runs the token-request action on the lab. The scenario role may mint a token only for the
// probe ServiceAccount, so the run must end DISCARDED_NOT_REVOKED, and a token for any other account must be refused.
func TestLive_TokenProbe(t *testing.T) {
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

	// Minting for any other ServiceAccount must be refused by the server.
	if _, err := client.IssueToken(ctx, "bas-sandbox", "default", 600); err == nil {
		t.Fatal("the scenario role minted a token for the default ServiceAccount; it must be refused")
	}

	store := newMemApprovals()
	audit := &captureAudit{}
	params := map[string]string{}
	req := RunRequest{RunID: "tok-live-1", Requester: "operator-1", Cluster: ClusterRef{Name: cluster, Server: api},
		Namespace: "bas-sandbox", ActionID: "sa-token-probe", Params: params, Live: true, ApprovalID: "appr-tok-live-1"}
	_ = store.Put(Approval{ID: "appr-tok-live-1", ApproverID: "operator-2", RequesterID: "operator-1", RunID: req.RunID,
		Cluster: cluster, Namespace: "bas-sandbox", ActionID: req.ActionID, ParamsHash: HashParams(params), ExpiresAt: time.Now().Add(15 * time.Minute)})
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
	res := NewEngine(cfg).Run(ctx, req)
	if res.State != StateDiscardedNotRevoked || !res.Verified {
		t.Fatalf("state = %s verified=%v (%q), want %s verified", res.State, res.Verified, res.Error, StateDiscardedNotRevoked)
	}
	if strings.Contains(res.Error, "SECRET") || strings.Contains(res.Error, strings.TrimSpace(string(tokenBytes))) {
		t.Fatal("the run result contains credential text")
	}
	t.Logf("%s: %s", res.State, res.Error)
}
