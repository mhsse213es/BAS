package main

import (
	"context"
	"fmt"
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
	// The registry is the sole authority for the configured cluster. It must be registered as a lab-class cluster at
	// the same API server, or the server refuses to start.
	registered, err := db.NewK8sClusterStore(pool).List(context.Background())
	if err != nil {
		log.Fatalf("[FATAL] k8s scenario: reading the cluster registry: %v", err)
	}
	rec, err := resolveConfiguredCluster(registered, cluster, server)
	if err != nil {
		log.Fatalf("[FATAL] k8s scenario: %v", err)
	}
	clusters := map[string]string{rec.DisplayName: rec.ServerURL}
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
	log.Printf("[k8s-scenario] enabled for registered lab cluster %q (%s), namespace %q", rec.DisplayName, rec.ID, namespace)
	return &api.K8sScenarioService{
		Engine:     engine,
		Runs:       k8sRunAdapter{store: db.NewK8sRunStore(pool)},
		Registry:   db.NewK8sClusterStore(pool),
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

// resolveConfiguredCluster returns the registered cluster that KUBE_SCENARIO_CLUSTER names. It refuses a name that is
// not registered, a cluster that is not lab-class, and an API server address that differs from the configured one.
func resolveConfiguredCluster(registered []k8sscenario.ClusterRecord, name, apiServer string) (k8sscenario.ClusterRecord, error) {
	var rec k8sscenario.ClusterRecord
	found := false
	for _, c := range registered {
		if c.DisplayName == name {
			rec, found = c, true
			break
		}
	}
	if !found {
		return k8sscenario.ClusterRecord{}, fmt.Errorf("KUBE_SCENARIO_CLUSTER %q is not registered; register it as a lab cluster first", name)
	}
	if rec.Class != k8sscenario.ClassLab {
		return k8sscenario.ClusterRecord{}, fmt.Errorf("KUBE_SCENARIO_CLUSTER %q is registered as class %q; scenario execution needs class %q", name, rec.Class, k8sscenario.ClassLab)
	}
	canon, err := k8sscenario.CanonicalServerURL(apiServer)
	if err != nil {
		return k8sscenario.ClusterRecord{}, fmt.Errorf("KUBE_SCENARIO_API: %w", err)
	}
	if canon != rec.ServerURL {
		return k8sscenario.ClusterRecord{}, fmt.Errorf("KUBE_SCENARIO_API %q does not match the registered server %q for %q", canon, rec.ServerURL, name)
	}
	return rec, nil
}
