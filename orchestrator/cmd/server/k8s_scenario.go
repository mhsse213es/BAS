package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/api"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
)

// buildK8sScenarioService enables Kubernetes state-changing scenarios only when explicitly configured:
//
//	KUBE_SCENARIO_API          https URL of the lab API server (required to enable)
//	KUBE_SCENARIO_CLUSTER      cluster name the allow-list uses (default kind-bas-lab)
//	KUBE_SCENARIO_NAMESPACE    the one namespace scenarios may write to (default bas-sandbox)
//	KUBE_SCENARIO_TOKEN_FILE   token of the scenario ServiceAccount, read from a file, never logged
//	KUBE_SCENARIO_CA_FILE      cluster CA (PEM)
//
// A partial configuration disables the feature and logs why. Returns nil when disabled.
func buildK8sScenarioService(pool *pgxpool.Pool) *api.K8sScenarioService {
	server := strings.TrimSpace(os.Getenv("KUBE_SCENARIO_API"))
	if server == "" {
		return nil
	}
	cluster := envOr("KUBE_SCENARIO_CLUSTER", "kind-bas-lab")
	namespace := envOr("KUBE_SCENARIO_NAMESPACE", "bas-sandbox")
	token, err := os.ReadFile(os.Getenv("KUBE_SCENARIO_TOKEN_FILE"))
	if err != nil {
		log.Printf("[k8s-scenario] disabled: cannot read KUBE_SCENARIO_TOKEN_FILE: %v", err)
		return nil
	}
	ca, err := os.ReadFile(os.Getenv("KUBE_SCENARIO_CA_FILE"))
	if err != nil {
		log.Printf("[k8s-scenario] disabled: cannot read KUBE_SCENARIO_CA_FILE: %v", err)
		return nil
	}
	client, err := k8sscenario.NewAPIClient(k8sscenario.ClientConfig{
		APIServer: server, Token: strings.TrimSpace(string(token)), CAPEM: ca,
	})
	if err != nil {
		log.Printf("[k8s-scenario] disabled: %v", err)
		return nil
	}
	clusters := map[string]string{cluster: server}
	engine := k8sscenario.NewEngine(k8sscenario.Config{
		AllowedClusters:   clusters,
		AllowedNamespaces: []string{namespace},
		Client:            client,
		Audit:             db.NewK8sScenarioAudit(pool),
		Alert:             logAlerter{},
		Approvals:         db.NewK8sApprovalStore(pool),
		// The route already requires the approve permission, so any non-empty approver id reaching the engine
		// has been authorised. The engine still refuses self-approval.
		ApproverPermitted: func(id string) bool { return id != "" },
		Now:               time.Now,
	})
	log.Printf("[k8s-scenario] enabled for cluster %q, namespace %q (lab only)", cluster, namespace)
	return &api.K8sScenarioService{
		Engine:     engine,
		Runs:       k8sRunAdapter{store: db.NewK8sRunStore(pool)},
		Approvals:  db.NewK8sApprovalStore(pool),
		Clusters:   clusters,
		Namespaces: []string{namespace},
	}
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// logAlerter writes operator alerts to the server log. CLEANUP_FAILED must not pass silently.
type logAlerter struct{}

func (logAlerter) Alert(_ context.Context, msg string) {
	log.Printf("[k8s-scenario] ALERT: %s", msg)
}

// k8sRunAdapter converts between the API run type and the database record.
type k8sRunAdapter struct {
	store *db.K8sRunStore
}

func toRecord(r api.K8sRun) db.K8sRunRecord {
	return db.K8sRunRecord{ID: r.ID, RequesterID: r.RequesterID, Cluster: r.Cluster, Namespace: r.Namespace,
		ActionID: r.ActionID, Params: r.Params, ParamsHash: r.ParamsHash, ApprovalID: r.ApprovalID,
		State: r.State, Detail: r.Detail, CreatedAt: r.CreatedAt}
}

func fromRecord(r db.K8sRunRecord) api.K8sRun {
	return api.K8sRun{ID: r.ID, RequesterID: r.RequesterID, Cluster: r.Cluster, Namespace: r.Namespace,
		ActionID: r.ActionID, Params: r.Params, ParamsHash: r.ParamsHash, ApprovalID: r.ApprovalID,
		State: r.State, Detail: r.Detail, CreatedAt: r.CreatedAt}
}

func (a k8sRunAdapter) InsertRun(ctx context.Context, r api.K8sRun) error {
	return a.store.InsertRun(ctx, toRecord(r))
}

func (a k8sRunAdapter) UpdateRun(ctx context.Context, r api.K8sRun) error {
	return a.store.UpdateRun(ctx, toRecord(r))
}

func (a k8sRunAdapter) GetRun(ctx context.Context, id string) (api.K8sRun, bool, error) {
	rec, ok, err := a.store.GetRun(ctx, id)
	if err != nil || !ok {
		return api.K8sRun{}, ok, err
	}
	return fromRecord(rec), true, nil
}

func (a k8sRunAdapter) ListRuns(ctx context.Context, limit int) ([]api.K8sRun, error) {
	recs, err := a.store.ListRuns(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]api.K8sRun, 0, len(recs))
	for _, r := range recs {
		out = append(out, fromRecord(r))
	}
	return out, nil
}
