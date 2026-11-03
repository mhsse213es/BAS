package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
)

// K8sClusterRegistry is the storage the cluster registry handlers need. The database store satisfies it.
type K8sClusterRegistry interface {
	Insert(ctx context.Context, c k8sscenario.ClusterRecord) error
	List(ctx context.Context) ([]k8sscenario.ClusterRecord, error)
	Get(ctx context.Context, id string) (k8sscenario.ClusterRecord, bool, error)
}

type k8sClusterRequest struct {
	DisplayName string `json:"displayName"`
	ServerURL   string `json:"serverUrl"`
	Class       string `json:"class"`
}

// k8sClusterView is what the API returns for a registered cluster, including its allowed profiles.
type k8sClusterView struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	ServerURL       string   `json:"serverUrl"`
	Class           string   `json:"class"`
	AllowedProfiles []string `json:"allowedProfiles"`
}

func toClusterView(c k8sscenario.ClusterRecord) k8sClusterView {
	return k8sClusterView{ID: c.ID, DisplayName: c.DisplayName, ServerURL: c.ServerURL, Class: c.Class,
		AllowedProfiles: k8sscenario.AllowedProfiles(c.Class)}
}

// ListK8sClusters lists registered clusters. GET /api/k8s-scenarios/clusters
func (h *Handler) ListK8sClusters(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Registry == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	clusters, err := svc.Registry.List(r.Context())
	if err != nil {
		jsonError(w, "could not list clusters", http.StatusInternalServerError)
		return
	}
	out := make([]k8sClusterView, 0, len(clusters))
	for _, c := range clusters {
		out = append(out, toClusterView(c))
	}
	k8sJSON(w, http.StatusOK, out)
}

// RegisterK8sCluster registers a cluster. Admin only (the route requires the approve permission).
// The class is set here by the administrator and is never taken from anyone else.
// POST /api/k8s-scenarios/clusters
func (h *Handler) RegisterK8sCluster(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Registry == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	var body k8sClusterRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	rec, err := k8sscenario.ValidateRegistration(body.DisplayName, body.ServerURL, strings.TrimSpace(body.Class), true)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec.ID = newK8sID("k8sc-")
	if err := svc.Registry.Insert(r.Context(), rec); err != nil {
		if errors.Is(err, db.ErrK8sClusterExists) {
			jsonError(w, err.Error(), http.StatusConflict)
			return
		}
		jsonError(w, "could not store the cluster", http.StatusInternalServerError)
		return
	}
	k8sJSON(w, http.StatusCreated, toClusterView(rec))
}
