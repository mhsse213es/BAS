package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/cloudgraph"
)

// K8sClusterCredentials returns the read-only token and optional CA for a registered cluster, looked up by its
// display name. The server supplies it from files outside the database; the handler never stores a credential.
// ErrK8sClusterNoCredential means none is configured for the cluster.
type K8sClusterCredentials func(displayName string) (token string, caPEM []byte, err error)

// ErrK8sClusterNoCredential is returned by a K8sClusterCredentials source when a cluster has no configured credential.
var ErrK8sClusterNoCredential = errors.New("no credential is configured for this cluster")

const k8sNamespaceTimeout = 30 * time.Second

// ListK8sClusterNamespaces lists a registered cluster's namespaces for the run form. Read-only.
// GET /api/k8s-scenarios/clusters/{id}/namespaces
func (h *Handler) ListK8sClusterNamespaces(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Registry == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	c, found, err := svc.Registry.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "could not read the cluster", http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "cluster not found", http.StatusNotFound)
		return
	}
	if svc.Credentials == nil {
		jsonError(w, ErrK8sClusterNoCredential.Error(), http.StatusConflict)
		return
	}
	token, ca, err := svc.Credentials(c.DisplayName)
	if errors.Is(err, ErrK8sClusterNoCredential) {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, "could not load the cluster credential", http.StatusInternalServerError)
		return
	}
	client, err := cloudgraph.NewK8sDiscoveryClient(cloudgraph.K8sDiscoveryConfig{
		ClusterName: c.DisplayName, APIServer: c.ServerURL, Token: token, CAPEM: ca,
	})
	if err != nil {
		jsonError(w, "cluster configuration is not usable", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), k8sNamespaceTimeout)
	defer cancel()
	names, err := client.ListNamespaces(ctx)
	if errors.Is(err, cloudgraph.ErrK8sUnauthorized) {
		jsonError(w, "the cluster rejected the credential", http.StatusBadGateway)
		return
	}
	if err != nil {
		jsonError(w, "could not list namespaces from the cluster", http.StatusBadGateway)
		return
	}
	k8sJSON(w, http.StatusOK, map[string]any{"clusterId": c.ID, "namespaces": names})
}
