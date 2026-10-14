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
	"github.com/audspect/bas/internal/networkdns"
)

const maxDNSSecurityCheckRequestBytes = 1 << 20

// TriggerDNSSecurityCheckRun -- POST /api/dns-security-checks.
func (h *Handler) TriggerDNSSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	if !h.networkVantagePoint.Configured() {
		jsonError(w, "network discovery vantage point not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Checks []networkdns.DNSCheckRequest `json:"checks"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDNSSecurityCheckRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Checks) == 0 {
		jsonError(w, "at least one check is required", http.StatusBadRequest)
		return
	}
	if len(req.Checks) > networkdns.MaxChecksPerRun {
		jsonError(w, fmt.Sprintf("too many checks — got %d, max %d", len(req.Checks), networkdns.MaxChecksPerRun), http.StatusBadRequest)
		return
	}
	for i, c := range req.Checks {
		if c.CheckType == networkdns.CheckOpenResolver && (c.Target.Host == "" || c.Target.Port < 1 || c.Target.Port > 65535) {
			jsonError(w, fmt.Sprintf("checks[%d]: a valid target host/port is required for an open-resolver check", i), http.StatusBadRequest)
			return
		}
		if c.QueryDomain == "" {
			jsonError(w, fmt.Sprintf("checks[%d]: queryDomain is required", i), http.StatusBadRequest)
			return
		}
	}

	var requestedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		requestedBy = c.UserID
	}

	result, err := networkdns.RunChecks(r.Context(), networkdns.DNSOpenResolverProbe{}, h.networkVantagePoint, req.Checks)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	run := &db.DNSSecurityCheckRun{
		ID:             newID(),
		VantagePointID: h.networkVantagePoint.ID,
		RequestedBy:    requestedBy,
		CheckCount:     len(req.Checks),
		Status:         string(result.Status),
	}
	if err := db.InsertDNSSecurityCheckRun(r.Context(), h.db, run); err != nil {
		h.auditLog(r, "networkdns.run", "", map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := db.InsertDNSSecurityCheckResults(r.Context(), h.db, run.ID, result.Results); err != nil {
		_ = db.UpdateDNSSecurityCheckRunStatus(r.Context(), h.db, run.ID, "failed")
		h.auditLog(r, "networkdns.run", run.ID, map[string]any{"checkCount": len(req.Checks), "error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkdns.run", run.ID, map[string]any{"checkCount": len(req.Checks), "status": string(result.Status)}, "ok")
	respondStatus(w, map[string]any{"runId": run.ID, "status": result.Status}, http.StatusCreated)
}

// ListDNSSecurityCheckRuns -- GET /api/dns-security-checks.
func (h *Handler) ListDNSSecurityCheckRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	runs, err := db.ListDNSSecurityCheckRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []*db.DNSSecurityCheckRun{}
	}
	respond(w, runs)
}

// GetDNSSecurityCheckRun -- GET /api/dns-security-checks/{id}.
func (h *Handler) GetDNSSecurityCheckRun(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	run, err := db.GetDNSSecurityCheckRun(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "dns security check run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	results, err := db.ListDNSSecurityCheckResultsByRun(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []networkdns.DNSCheckResult{}
	}
	respond(w, map[string]any{"run": run, "results": results})
}
