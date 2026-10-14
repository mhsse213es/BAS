package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktransport"
)

const maxTransportSecurityCheckRequestBytes = 1 << 20

// TriggerTransportSecurityCheckRun -- POST /api/transport-security-checks.
func (h *Handler) TriggerTransportSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	if !h.networkVantagePoint.Configured() {
		jsonError(w, "network discovery vantage point not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Checks []networktransport.TransportCheckRequest `json:"checks"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTransportSecurityCheckRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 {
		jsonError(w, "at least one check is required", http.StatusBadRequest)
		return
	}
	if len(req.Checks) > networktransport.MaxChecksPerRun {
		jsonError(w, fmt.Sprintf("too many checks — got %d, max %d", len(req.Checks), networktransport.MaxChecksPerRun), http.StatusBadRequest)
		return
	}
	for i, c := range req.Checks {
		if c.CheckType != networktransport.CheckCleartext && c.CheckType != networktransport.CheckCert {
			jsonError(w, fmt.Sprintf("checks[%d]: unrecognized checkType %q", i, c.CheckType), http.StatusBadRequest)
			return
		}
		if c.Target.Host == "" || c.Target.Port < 1 || c.Target.Port > 65535 {
			jsonError(w, fmt.Sprintf("checks[%d]: a valid target host/port is required", i), http.StatusBadRequest)
			return
		}
	}

	var requestedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		requestedBy = c.UserID
	}

	result, err := networktransport.RunChecks(r.Context(), networktransport.TCPCleartextProbe{}, networktransport.TLSCertProbe{}, h.networkVantagePoint, req.Checks)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	run := &db.TransportSecurityCheckRun{
		ID:             newID(),
		VantagePointID: h.networkVantagePoint.ID,
		RequestedBy:    requestedBy,
		CheckCount:     len(req.Checks),
		Status:         string(result.Status),
	}
	if err := db.InsertTransportSecurityCheckRun(r.Context(), h.db, run); err != nil {
		h.auditLog(r, "networktransport.run", "", map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	checkTypes := make([]networktransport.CheckType, len(req.Checks))
	for i, c := range req.Checks {
		checkTypes[i] = c.CheckType
	}
	if err := db.InsertTransportSecurityCheckResults(r.Context(), h.db, run.ID, checkTypes, result.Results); err != nil {
		_ = db.UpdateTransportSecurityCheckRunStatus(r.Context(), h.db, run.ID, "failed")
		h.auditLog(r, "networktransport.run", run.ID, map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networktransport.run", run.ID, map[string]any{"checkCount": len(req.Checks), "status": string(result.Status)}, "ok")
	respondStatus(w, map[string]any{"runId": run.ID, "status": result.Status}, http.StatusCreated)
}

// ListTransportSecurityCheckRuns -- GET /api/transport-security-checks.
func (h *Handler) ListTransportSecurityCheckRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListTransportSecurityCheckRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*db.TransportSecurityCheckRun{}
	}
	respond(w, runs)
}

// GetTransportSecurityCheckRun -- GET /api/transport-security-checks/{id}.
func (h *Handler) GetTransportSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetTransportSecurityCheckRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "transport security check run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	results, err := db.ListTransportSecurityCheckResultsByRun(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []db.TransportSecurityCheckResult{}
	}
	respond(w, map[string]any{"run": run, "results": results})
}
