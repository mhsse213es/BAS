package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/k8sscenario"
)

const k8sAdmissionCheckTimeout = 60 * time.Second

// dnsLabelRE is the namespace name format the API server accepts.
var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type k8sAdmissionCheckRequest struct {
	ClusterID string `json:"clusterId"`
	CheckID   string `json:"checkId"`
	Namespace string `json:"namespace"`
}

// RunK8sAdmissionCheck runs one dry-run admission check against a registered cluster. Nothing is persisted. The
// namespace's Pod Security level decides whether the check applies, and a non-applicable namespace is SKIPPED.
// POST /api/k8s-scenarios/admission-checks/run
func (h *Handler) RunK8sAdmissionCheck(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Registry == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	var body k8sAdmissionCheckRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	check, ok := k8sscenario.AdmissionCheckByID(strings.TrimSpace(body.CheckID))
	if !ok {
		jsonError(w, "unknown admission check", http.StatusBadRequest)
		return
	}
	namespace := strings.TrimSpace(body.Namespace)
	if !dnsLabelRE.MatchString(namespace) {
		jsonError(w, "namespace must be a valid Kubernetes namespace name", http.StatusBadRequest)
		return
	}
	c, found, err := svc.Registry.Get(r.Context(), body.ClusterID)
	if err != nil {
		jsonError(w, "could not read the cluster", http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "cluster not found", http.StatusNotFound)
		return
	}
	if refuseProfile(w, r, svc, c, "safe", check.ID) {
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
	client, err := k8sscenario.NewDryRunClient(c.ServerURL, token, ca)
	if err != nil {
		jsonError(w, "cluster configuration is not usable", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), k8sAdmissionCheckTimeout)
	defer cancel()
	result := k8sscenario.RunAdmissionCheck(ctx, client, check, namespace, time.Now())
	result.Profile = "safe"
	status := http.StatusOK
	if result.Verdict == controlval.VerdictError {
		status = http.StatusBadGateway
	}
	k8sJSON(w, status, map[string]any{"clusterId": c.ID, "result": result})
}
