package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/audspect/bas/internal/auth"
)

// reportDownloadPath reconstructs the generator URL for a logged report from its
// type + parameters. Centralised so the URL is never persisted and route changes
// don't break history rows.
func reportDownloadPath(reportType, format, agentID, framework string) (string, error) {
	switch reportType {
	case "posture":
		if agentID == "" {
			return "", errors.New("agentId required")
		}
		f := "pdf"
		if format == "html" {
			f = "html"
		}
		return "/api/report/full/" + f + "?agentId=" + url.QueryEscape(agentID), nil
	case "audit":
		if agentID == "" {
			return "", errors.New("agentId required")
		}
		return "/api/report/audit-pack?agentId=" + url.QueryEscape(agentID), nil
	case "compliance":
		if framework == "" || agentID == "" {
			return "", errors.New("framework and agentId required")
		}
		f := format
		if f == "" {
			f = "html"
		}
		return "/api/compliance/report?framework=" + url.QueryEscape(framework) +
			"&agentId=" + url.QueryEscape(agentID) + "&format=" + url.QueryEscape(f), nil
	}
	return "", errors.New("invalid report type — use posture | audit | compliance")
}

// CreateReport logs a report generation (metadata only) and returns the
// reconstructed download path. The generator endpoint itself is invoked by the
// client opening downloadPath. POST /api/reports
func (h *Handler) CreateReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReportType string `json:"reportType"`
		Format     string `json:"format"`
		AgentID    string `json:"agentId"`
		Framework  string `json:"framework"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	path, err := reportDownloadPath(req.ReportType, req.Format, req.AgentID, req.Framework)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	by := "unknown"
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		by = c.UserID
	}
	scope := req.AgentID
	if req.ReportType == "compliance" {
		scope = req.Framework + " · " + req.AgentID
	}
	params, _ := json.Marshal(map[string]any{
		"agentId": req.AgentID, "framework": req.Framework, "format": req.Format, "campaignId": nil,
	})
	id := newID()
	if _, e := h.db.Exec(r.Context(),
		`INSERT INTO report_log (id, report_type, format, scope_label, parameters, source, status, generated_by)
		 VALUES ($1,$2,$3,$4,$5,'reports_hub','generated',$6)`,
		id, req.ReportType, req.Format, scope, params, by); e != nil {
		jsonError(w, e.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"id": id, "downloadPath": path})
}

// ListReports returns recent report-generation history, each with a freshly
// reconstructed downloadPath. GET /api/reports
func (h *Handler) ListReports(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, report_type, format, scope_label, parameters, source, status,
		        COALESCE(generated_by,''), generated_at
		   FROM report_log ORDER BY generated_at DESC LIMIT 100`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, rtype, format, scope, source, status, by string
		var paramsRaw []byte
		var at time.Time
		if rows.Scan(&id, &rtype, &format, &scope, &paramsRaw, &source, &status, &by, &at) != nil {
			continue
		}
		var p struct {
			AgentID   string `json:"agentId"`
			Framework string `json:"framework"`
			Format    string `json:"format"`
		}
		_ = json.Unmarshal(paramsRaw, &p)
		path, _ := reportDownloadPath(rtype, p.Format, p.AgentID, p.Framework)
		out = append(out, map[string]any{
			"id": id, "reportType": rtype, "format": format, "scopeLabel": scope,
			"source": source, "status": status, "generatedBy": by, "generatedAt": at,
			"downloadPath": path,
		})
	}
	respond(w, out)
}
