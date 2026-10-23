package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// K8sAnalysisRunner runs one read-only discovery and analysis of the configured cluster. The server supplies it, so the
// handler never holds a cluster credential.
type K8sAnalysisRunner interface {
	Run(ctx context.Context) (cloudgraph.K8sAnalysis, error)
}

// k8sAnalysisTimeout bounds one discovery. Discovery pages through every list, so it can take a while on a large cluster.
const k8sAnalysisTimeout = 90 * time.Second

// WithK8sAnalysis attaches the discovery runner. A nil runner leaves the route answering 503.
func (h *Handler) WithK8sAnalysis(r K8sAnalysisRunner) *Handler {
	h.k8sAnalysis = r
	return h
}

// GetK8sAnalysis runs the read-only Kubernetes analysis and returns it. It writes nothing to the cluster.
// GET /api/k8s-discovery/analysis
func (h *Handler) GetK8sAnalysis(w http.ResponseWriter, r *http.Request) {
	if h.k8sAnalysis == nil {
		jsonError(w, "Kubernetes discovery is not configured", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), k8sAnalysisTimeout)
	defer cancel()
	res, err := h.k8sAnalysis.Run(ctx)
	if err != nil {
		// The error can carry request detail, so only the fact of failure is returned, not the error text.
		slog.Error("k8s analysis failed", "error", err)
		jsonError(w, "cluster discovery failed: see server log", http.StatusBadGateway)
		return
	}
	respond(w, res)
}
