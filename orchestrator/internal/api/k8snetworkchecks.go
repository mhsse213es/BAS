package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/k8sscenario"
)

// k8sNetworkCheckTimeout bounds a whole network check, including its probe pods and cleanup.
const k8sNetworkCheckTimeout = 10 * time.Minute

var dnsNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type k8sNetworkCheckRequest struct {
	ClusterID       string `json:"clusterId"`
	CheckID         string `json:"checkId"`
	Namespace       string `json:"namespace"`
	TargetNamespace string `json:"targetNamespace,omitempty"` // S9 only
	Service         string `json:"service,omitempty"`         // S9 only
}

// RunK8sNetworkCheck runs one Lab-profile network check (S9 or S10). These create and delete probe pods, so the
// cluster must be lab-class, and only an administrator who can execute may run one.
// POST /api/k8s-scenarios/network-checks/run
func (h *Handler) RunK8sNetworkCheck(w http.ResponseWriter, r *http.Request) {
	svc := h.k8sScenario
	if svc == nil || svc.Registry == nil {
		jsonError(w, "Kubernetes scenarios are not configured", http.StatusServiceUnavailable)
		return
	}
	var body k8sNetworkCheckRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	checkID := strings.TrimSpace(body.CheckID)
	if checkID != "cross-namespace-service-reachability" && checkID != "api-server-reachability-from-workload" {
		jsonError(w, "unknown network check", http.StatusBadRequest)
		return
	}
	namespace := strings.TrimSpace(body.Namespace)
	if !dnsNameRE.MatchString(namespace) {
		jsonError(w, "namespace must be a valid Kubernetes namespace name", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(body.TargetNamespace)
	service := strings.TrimSpace(body.Service)
	if checkID == "cross-namespace-service-reachability" {
		if target == "" {
			target = "np-db"
		}
		if service == "" {
			service = "db"
		}
		if !dnsNameRE.MatchString(target) || !dnsNameRE.MatchString(service) {
			jsonError(w, "targetNamespace and service must be valid Kubernetes names", http.StatusBadRequest)
			return
		}
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
	// Refused before any credential is read or any request is made: a non-lab cluster never sees a probe pod.
	if refuseProfile(w, r, svc, c, "lab", checkID) {
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
	client, err := k8sscenario.NewNetProbeKubeClient(c.ServerURL, token, ca)
	if err != nil {
		jsonError(w, "cluster configuration is not usable", http.StatusConflict)
		return
	}
	tag, err := newRunTag()
	if err != nil {
		jsonError(w, "could not create a run tag", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), k8sNetworkCheckTimeout)
	defer cancel()
	now := time.Now()
	var result k8sscenario.NetCheckResult
	if checkID == "cross-namespace-service-reachability" {
		result = k8sscenario.RunNetworkBoundary(ctx, client, tag, k8sscenario.NetworkBoundaryTarget{
			ProbeNamespace: namespace, TargetNamespace: target, Service: service, AllowedPort: 5432, BlockedPort: 3306,
		}, now)
	} else {
		result = k8sscenario.RunAPIReachability(ctx, client, tag, namespace, now)
	}
	result.Profile = "lab"
	status := http.StatusOK
	if result.Verdict == controlval.VerdictError {
		status = http.StatusBadGateway
	}
	k8sJSON(w, status, map[string]any{"clusterId": c.ID, "result": result})
}

// newRunTag returns a random lower-case hex tag for probe pod names.
func newRunTag() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
