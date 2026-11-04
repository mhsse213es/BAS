package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/k8sscenario"
)

// K8sRun is one requested state-changing Kubernetes scenario run, as the console shows it.
type K8sRun struct {
	ID          string            `json:"id"`
	RequesterID string            `json:"requester"`
	Cluster     string            `json:"cluster"`
	Namespace   string            `json:"namespace"`
	ActionID    string            `json:"action"`
	Params      map[string]string `json:"params"`
	ParamsHash  string            `json:"paramsHash"`
	ApprovalID  string            `json:"approvalId,omitempty"`
	State       string            `json:"state"`
	Detail      string            `json:"detail,omitempty"`
	CreatedAt   time.Time         `json:"createdAt"`
}

// K8sRunStore persists runs. The database implementation lives in internal/db.
type K8sRunStore interface {
	InsertRun(ctx context.Context, r K8sRun) error
	UpdateRun(ctx context.Context, r K8sRun) error
	GetRun(ctx context.Context, id string) (K8sRun, bool, error)
	ListRuns(ctx context.Context, limit int) ([]K8sRun, error)
}

// K8sApprovals reads and writes approvals. The engine consumes them through ApprovalStore.
type K8sApprovals interface {
	k8sscenario.ApprovalStore
	Put(a k8sscenario.Approval) error
}

// K8sScenarioService wires the engine to the HTTP surface. Clusters and Namespaces are server configuration:
// a request cannot name a cluster or namespace that is not listed here.
type K8sScenarioService struct {
	Engine      *k8sscenario.Engine
	Runs        K8sRunStore
	Approvals   K8sApprovals
	Clusters    map[string]string     // cluster name -> API server URL
	Registry    K8sClusterRegistry    // registered clusters (Phase 2)
	Credentials K8sClusterCredentials // per-cluster read-only credential source (Phase 2)
	Audit       k8sscenario.Audit     // records refused execution profiles (Phase 4)
	Namespaces  []string
	ApprovalTTL time.Duration
	Now         func() time.Time
}

func (s *K8sScenarioService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// approvalTTL returns the configured approval lifetime, defaulting to fifteen minutes.
func (s *K8sScenarioService) approvalTTL() time.Duration {
	if s.ApprovalTTL > 0 {
		return s.ApprovalTTL
	}
	return 15 * time.Minute
}

func newK8sID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// k8sJSON writes a JSON body with an explicit status code.
func k8sJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type k8sRunRequest struct {
	ClusterID string            `json:"clusterId"`
	Cluster   string            `json:"cluster"`
	Namespace string            `json:"namespace"`
	Action    string            `json:"action"`
	Params    map[string]string `json:"params"`
}

// targetServer returns the configured API server for a cluster and namespace, or false if either is not listed.
func (s *K8sScenarioService) targetServer(cluster, namespace string) (string, bool) {
	server, ok := s.Clusters[cluster]
	if !ok {
		return "", false
	}
	for _, ns := range s.Namespaces {
		if ns == namespace {
			return server, true
		}
	}
	return "", false
}

// CreateK8sRun plans a run. It is a dry run: the engine validates the request and nothing is written to a cluster.
// POST /api/k8s-scenarios/runs
func (h *Handler) CreateK8sRun(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Engine == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	var body k8sRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.ClusterID != "" {
		// A registered cluster is named by its registration ID. Its display name must still be in the configured
		// engine map, so a registration alone never makes a cluster runnable.
		if svc.Registry == nil {
			jsonError(w, "cluster registry is not configured", http.StatusServiceUnavailable)
			return
		}
		c, found, err := svc.Registry.Get(r.Context(), body.ClusterID)
		if err != nil || !found {
			jsonError(w, "cluster not found", http.StatusBadRequest)
			return
		}
		if refuseProfile(w, r, svc, c, "lab", "run:"+body.Action) {
			return
		}
		body.Cluster = c.DisplayName
	}
	server, ok := svc.targetServer(body.Cluster, body.Namespace)
	if !ok {
		jsonError(w, "cluster or namespace is not configured for scenarios", http.StatusBadRequest)
		return
	}
	id := newK8sID("k8sr-")
	req := k8sscenario.RunRequest{RunID: id, Requester: actorID(r),
		Cluster: k8sscenario.ClusterRef{Name: body.Cluster, Server: server}, Namespace: body.Namespace,
		ActionID: body.Action, Params: body.Params, Live: false}
	res := svc.Engine.Run(r.Context(), req)
	if res.State != k8sscenario.StateDryRunPlanned {
		jsonError(w, res.Error, http.StatusBadRequest)
		return
	}
	run := K8sRun{ID: id, RequesterID: req.Requester, Cluster: body.Cluster, Namespace: body.Namespace, ActionID: body.Action,
		Params: body.Params, ParamsHash: k8sscenario.HashParams(body.Params), State: "PLANNED",
		Detail: strings.Join(res.Plan, "\n"), CreatedAt: svc.now()}
	if err := svc.Runs.InsertRun(r.Context(), run); err != nil {
		jsonError(w, "could not store the run", http.StatusInternalServerError)
		return
	}
	k8sJSON(w, http.StatusCreated, run)
}

// ApproveK8sRun approves a planned run. The approver must differ from the requester and hold the approve
// permission (enforced by the route). The approval is bound to the run's exact parameters.
// POST /api/k8s-scenarios/runs/{id}/approve
func (h *Handler) ApproveK8sRun(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Engine == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	run, ok, err := svc.Runs.GetRun(r.Context(), chi.URLParam(r, "id"))
	if err != nil || !ok {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	approver := actorID(r)
	if approver == "" {
		jsonError(w, "approver identity is required", http.StatusUnauthorized)
		return
	}
	if approver == run.RequesterID {
		jsonError(w, "self-approval is not allowed", http.StatusForbidden)
		return
	}
	if run.State != "PLANNED" {
		jsonError(w, "run is not awaiting approval", http.StatusConflict)
		return
	}
	approval := k8sscenario.Approval{
		ID:          newK8sID("appr-"),
		ApproverID:  approver,
		RequesterID: run.RequesterID,
		RunID:       run.ID,
		Cluster:     run.Cluster,
		Namespace:   run.Namespace,
		ActionID:    run.ActionID,
		ParamsHash:  run.ParamsHash,
		ExpiresAt:   svc.now().Add(svc.approvalTTL()),
	}
	if err := svc.Approvals.Put(approval); err != nil {
		jsonError(w, "could not record the approval", http.StatusInternalServerError)
		return
	}
	run.ApprovalID = approval.ID
	run.State = "APPROVED"
	if err := svc.Runs.UpdateRun(r.Context(), run); err != nil {
		jsonError(w, "could not update the run", http.StatusInternalServerError)
		return
	}
	respond(w, run)
}

// ExecuteK8sRun runs an approved run through the engine. Only the requester may execute, and the engine re-checks
// every gate, so approval alone is not enough. POST /api/k8s-scenarios/runs/{id}/execute
func (h *Handler) ExecuteK8sRun(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Engine == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	run, ok, err := svc.Runs.GetRun(r.Context(), chi.URLParam(r, "id"))
	if err != nil || !ok {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if actorID(r) != run.RequesterID {
		jsonError(w, "only the requester may execute a run", http.StatusForbidden)
		return
	}
	if run.ApprovalID == "" || run.State != "APPROVED" {
		jsonError(w, "run has no approval", http.StatusConflict)
		return
	}
	server, ok := svc.targetServer(run.Cluster, run.Namespace)
	if !ok {
		jsonError(w, "cluster or namespace is no longer configured for scenarios", http.StatusBadRequest)
		return
	}
	res := svc.Engine.Run(r.Context(), k8sscenario.RunRequest{RunID: run.ID, Requester: run.RequesterID,
		Cluster: k8sscenario.ClusterRef{Name: run.Cluster, Server: server}, Namespace: run.Namespace, ActionID: run.ActionID,
		Params: run.Params, Live: true, ApprovalID: run.ApprovalID})

	run.State = string(res.State)
	run.Detail = res.Error
	if res.Withheld {
		run.Detail = "result withheld: outcome could not be recorded"
	}
	if err := svc.Runs.UpdateRun(r.Context(), run); err != nil {
		jsonError(w, "run finished but could not be recorded", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"run": run, "verified": res.Verified, "withheld": res.Withheld})
}

// ListK8sRuns lists recent runs. GET /api/k8s-scenarios/runs
func (h *Handler) ListK8sRuns(w http.ResponseWriter, r *http.Request) {
	if h.k8sScenario == nil || h.k8sScenario.Runs == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	runs, err := h.k8sScenario.Runs.ListRuns(r.Context(), 100)
	if err != nil {
		jsonError(w, "could not list runs", http.StatusInternalServerError)
		return
	}
	respond(w, runs)
}

// WithK8sScenario attaches the scenario service. A nil service leaves the routes answering 503.
func (h *Handler) WithK8sScenario(s *K8sScenarioService) *Handler {
	h.k8sScenario = s
	return h
}
