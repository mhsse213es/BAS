package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/reporting"
)

// GetNavigatorLayer exports a report's ATT&CK coverage as a MITRE ATT&CK
// Navigator layer JSON, loadable directly in the official Navigator.
//
// GET /api/report/navigator?agentId=X | runId=Y | campaignId=Z
func (h *Handler) GetNavigatorLayer(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		jsonError(w, "reporting engine not loaded", http.StatusServiceUnavailable)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	runID := r.URL.Query().Get("runId")
	campaignID := r.URL.Query().Get("campaignId")

	var report *reporting.FullReport
	var err error
	var scope string
	switch {
	case runID != "":
		report, err = h.reportingEngine.BuildFromRun(r.Context(), runID, "")
		scope = runID
	case campaignID != "":
		report, err = h.reportingEngine.BuildFromCampaign(r.Context(), campaignID, "")
		scope = campaignID
	case agentID != "":
		report, err = h.reportingEngine.Build(r.Context(), agentID, "")
		scope = agentID
	default:
		jsonError(w, "agentId, runId or campaignId required", http.StatusBadRequest)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	name := "Audspect BAS — " + scope
	if report.ScenarioName != "" {
		name = "Audspect BAS — " + report.ScenarioName
	}
	layer := reporting.BuildNavigatorLayer(report, name)

	b, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		jsonError(w, "encode layer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "report.export", scope, map[string]any{"format": "navigator", "type": "attack_layer"}, "ok")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`,
		buildReportFilename("ATTACK_Navigator", strings.ReplaceAll(scope, " ", "_"), "json")))
	w.Write(b)
}
