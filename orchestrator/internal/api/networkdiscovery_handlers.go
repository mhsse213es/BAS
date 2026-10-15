package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/otsafety"
	"github.com/audspect/bas/internal/targetscope"
)

// maxNetworkDiscoveryRequestBytes bounds the raw request body before it is
// ever unmarshaled. 50 targets' worth of {host,port,label} JSON is well
// under 1MiB even generously; this ships from the start rather than as a
// follow-up fix, unlike cloud_campaign's own equivalent cap.
const maxNetworkDiscoveryRequestBytes = 1 << 20

// TriggerNetworkDiscoveryRun -- POST /api/network-discovery-runs. Probes
// every caller-declared target from the orchestrator's own configured
// vantage point and persists the result. "Authorized" in this phase means
// only that an authenticated caller holding auth.CanRunScenario submitted
// exactly this target list -- there is no separate scope-registration
// mechanism yet (deferred; see the Phase 1 spec).
func (h *Handler) TriggerNetworkDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	if !h.networkVantagePoint.Configured() {
		jsonError(w, "network discovery vantage point not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Targets                 []networkgraph.Target             `json:"targets"`
		TimeoutPerTargetMs      int                               `json:"timeoutPerTargetMs,omitempty"`
		TopologyImportID        string                            `json:"topologyImportId,omitempty"`
		OTSafetyImportID        string                            `json:"otSafetyImportId,omitempty"`
		ActiveTestAuthorization *otsafety.ActiveTestAuthorization `json:"activeTestAuthorization,omitempty"`
		TargetScopeImportID     string                            `json:"targetScopeImportId,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkDiscoveryRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Targets) == 0 {
		jsonError(w, "at least one target is required", http.StatusBadRequest)
		return
	}
	if len(req.Targets) > networkgraph.MaxTargetsPerRun {
		jsonError(w, fmt.Sprintf("too many targets — got %d, max %d", len(req.Targets), networkgraph.MaxTargetsPerRun), http.StatusBadRequest)
		return
	}
	for i, t := range req.Targets {
		if t.Host == "" {
			jsonError(w, fmt.Sprintf("targets[%d]: host required", i), http.StatusBadRequest)
			return
		}
		if t.Port < 1 || t.Port > 65535 {
			jsonError(w, fmt.Sprintf("targets[%d]: port must be between 1 and 65535", i), http.StatusBadRequest)
			return
		}
	}

	hosts := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		hosts = append(hosts, t.Host)
	}

	topo, safety, ok := h.resolveOTSafetyGatingContext(w, r, req.TopologyImportID, req.OTSafetyImportID)
	if !ok {
		return
	}
	if topo != nil && safety != nil {
		matchedZones, err := otsafety.CheckActiveTestAuthorization(hosts, topo, safety, req.ActiveTestAuthorization)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(matchedZones) > 0 {
			h.auditLog(r, "networkdiscovery.activeTestAuthorized", "", map[string]any{"sensitiveZones": matchedZones, "signOff": req.ActiveTestAuthorization.SignOff}, "ok")
		}
	}

	scope, ok := h.resolveTargetScopeImport(w, r, req.TargetScopeImportID)
	if !ok {
		return
	}
	if scope != nil {
		if unauthorized := targetscope.UnauthorizedTargets(hosts, scope); len(unauthorized) > 0 {
			jsonError(w, fmt.Sprintf("target(s) not in the declared authorized target scope: %v", unauthorized), http.StatusBadRequest)
			return
		}
	}

	opts := networkgraph.DiscoveryOptions{}
	if req.TimeoutPerTargetMs > 0 {
		timeout := time.Duration(req.TimeoutPerTargetMs) * time.Millisecond
		if timeout > networkgraph.MaxProbeTimeout {
			jsonError(w, fmt.Sprintf("timeoutPerTargetMs exceeds max %s", networkgraph.MaxProbeTimeout), http.StatusBadRequest)
			return
		}
		opts.TimeoutPerTarget = timeout
	}

	var requestedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		requestedBy = c.UserID
	}

	result, err := networkgraph.RunDiscovery(r.Context(), networkgraph.DialerProbe{}, h.networkVantagePoint, req.Targets, opts)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	run := &db.NetworkDiscoveryRun{
		ID:             newID(),
		VantagePointID: h.networkVantagePoint.ID,
		RequestedBy:    requestedBy,
		TargetCount:    len(req.Targets),
		Status:         string(result.Status),
	}
	if err := db.InsertNetworkDiscoveryRun(r.Context(), h.db, run); err != nil {
		h.auditLog(r, "networkdiscovery.run", "", map[string]any{"targetCount": len(req.Targets), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := db.InsertNetworkObservations(r.Context(), h.db, run.ID, result.Observations); err != nil {
		// The run row is already persisted claiming result.Status
		// ("completed"/"partial") -- without this, a reader would see a
		// run claiming success with zero backing observations. Best
		// effort: the original error is already what's reported below.
		_ = db.UpdateNetworkDiscoveryRunStatus(r.Context(), h.db, run.ID, "failed")
		h.auditLog(r, "networkdiscovery.run", run.ID, map[string]any{"targetCount": len(req.Targets), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkdiscovery.run", run.ID, map[string]any{
		"targetCount": len(req.Targets), "status": string(result.Status),
	}, "ok")
	respondStatus(w, map[string]any{
		"runId":        run.ID,
		"vantagePoint": h.networkVantagePoint,
		"status":       result.Status,
		"findings":     result.Findings,
	}, http.StatusCreated)
}

// ListNetworkDiscoveryRuns -- GET /api/network-discovery-runs. Any
// authenticated user may read this, matching ListCloudRuns' own
// precedent -- only the trigger endpoint is permission-gated.
func (h *Handler) ListNetworkDiscoveryRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListNetworkDiscoveryRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*db.NetworkDiscoveryRun{}
	}
	respond(w, runs)
}

// GetNetworkDiscoveryRun -- GET /api/network-discovery-runs/{id}. Same
// baseline-only gate as ListNetworkDiscoveryRuns.
func (h *Handler) GetNetworkDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network discovery run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	observations, err := db.ListNetworkObservationsByRun(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if observations == nil {
		observations = []networkgraph.NetworkObservation{}
	}
	respond(w, map[string]any{"run": run, "observations": observations})
}
