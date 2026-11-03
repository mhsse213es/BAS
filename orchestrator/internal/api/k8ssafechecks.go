package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/k8sscenario"
)

const k8sSafeCheckTimeout = 60 * time.Second

type k8sSafeCheckRequest struct {
	ClusterID string `json:"clusterId"`
	CheckID   string `json:"checkId"`
	Subject   string `json:"subject"`
	Namespace string `json:"namespace"`
}

// RunK8sSafeCheck runs one read-only check against a registered cluster: SubjectAccessReview only, nothing created.
// The cluster's class must allow the safe profile, which the backend checks before any review is sent.
// POST /api/k8s-scenarios/safe-checks/run
func (h *Handler) RunK8sSafeCheck(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Registry == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	var body k8sSafeCheckRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	check, ok := k8sscenario.SafeCheckByID(strings.TrimSpace(body.CheckID))
	if !ok {
		jsonError(w, "unknown safe check", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(body.Subject)
	if err := k8sscenario.ValidateSubject(subject); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
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
	if !profileAllowed(c.Class, "safe") {
		jsonError(w, "this cluster's class does not allow the safe profile", http.StatusForbidden)
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
	reviewer, err := k8sscenario.NewSARClient(c.ServerURL, token, ca)
	if err != nil {
		jsonError(w, "cluster configuration is not usable", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), k8sSafeCheckTimeout)
	defer cancel()
	result := k8sscenario.RunSafeCheck(ctx, reviewer, check, subject, strings.TrimSpace(body.Namespace), time.Now())
	result.Profile = "safe"
	// A check that could not be established is a failed request for the caller, not a passed one. The result is still
	// returned so the caller sees why.
	status := http.StatusOK
	if result.Verdict == controlval.VerdictError {
		status = http.StatusBadGateway
	}
	k8sJSON(w, status, map[string]any{"clusterId": c.ID, "result": result})
}

// profileAllowed reports whether a cluster class permits a profile.
func profileAllowed(class, profile string) bool {
	for _, p := range k8sscenario.AllowedProfiles(class) {
		if p == profile {
			return true
		}
	}
	return false
}
