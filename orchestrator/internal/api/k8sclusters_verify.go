package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/k8sscenario"
)

const k8sVerifyTimeout = 30 * time.Second

// VerifyK8sCluster contacts a registered cluster and records its identity: the Kubernetes version, the CA fingerprint
// and the server certificate's SPKI hash. The certificate must verify against the configured CA, or the system roots
// when no CA is set. The first successful verification pins the identity. A later verification that finds a different
// CA or server key is refused, so the cluster has to be registered again.
// POST /api/k8s-scenarios/clusters/{id}/verify  (admin only: it contacts the cluster)
func (h *Handler) VerifyK8sCluster(w http.ResponseWriter, r *http.Request) {
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
	ctx, cancel := context.WithTimeout(r.Context(), k8sVerifyTimeout)
	defer cancel()

	version, err := client.ServerVersion(ctx)
	if errors.Is(err, cloudgraph.ErrK8sUnauthorized) {
		jsonError(w, "the cluster rejected the credential", http.StatusBadGateway)
		return
	}
	if err != nil {
		jsonError(w, "could not read the cluster version", http.StatusBadGateway)
		return
	}
	spki, err := cloudgraph.TLSServerIdentity(ctx, c.ServerURL, ca)
	if err != nil {
		jsonError(w, "the cluster certificate could not be verified: "+err.Error(), http.StatusBadGateway)
		return
	}
	caFP := ""
	if len(ca) > 0 {
		caFP, err = cloudgraph.CAFingerprint(ca)
		if err != nil {
			jsonError(w, "the cluster CA could not be read", http.StatusConflict)
			return
		}
	}
	identity := k8sscenario.ClusterRecord{Version: version, CAFingerprint: caFP, SPKIHash: spki, VerifiedAt: time.Now().UTC()}
	if err := svc.Registry.UpdateIdentity(r.Context(), c.ID, identity); err != nil {
		if errors.Is(err, db.ErrK8sIdentityChanged) {
			jsonError(w, err.Error(), http.StatusConflict)
			return
		}
		jsonError(w, "could not store the verified identity", http.StatusInternalServerError)
		return
	}
	c.Version, c.CAFingerprint, c.SPKIHash, c.VerifiedAt = identity.Version, identity.CAFingerprint, identity.SPKIHash, identity.VerifiedAt
	k8sJSON(w, http.StatusOK, toClusterView(c))
}
