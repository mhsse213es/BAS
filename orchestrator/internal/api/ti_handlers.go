package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/reporting"
)

// GET /api/ti/readiness?agentId=&runId=
// Returns per-ATT&CK-group readiness scores derived from the most recent
// (or specified) run's TechniqueMatrix. No external API required — uses the
// bundled MITRE ATT&CK STIX enrichment. Groups with <3 tested techniques
// are excluded. Results sorted worst prevention readiness first.
func (h *Handler) GetTIReadiness(w http.ResponseWriter, r *http.Request) {
	if h.reportingEngine == nil {
		http.Error(w, "reporting engine not available", http.StatusServiceUnavailable)
		return
	}

	runID := r.URL.Query().Get("runId")
	agentID := r.URL.Query().Get("agentId")

	var matrix []reporting.TechniqueRow

	switch {
	case runID != "":
		rep, err := h.reportingEngine.BuildFromRun(r.Context(), runID, "")
		if err != nil {
			http.Error(w, "run not found", http.StatusNotFound)
			return
		}
		matrix = rep.TechniqueMatrix
	case agentID != "":
		rep, err := h.reportingEngine.Build(r.Context(), agentID, "")
		if err != nil {
			http.Error(w, "agent not found or no runs", http.StatusNotFound)
			return
		}
		matrix = rep.TechniqueMatrix
	default:
		http.Error(w, "agentId or runId required", http.StatusBadRequest)
		return
	}

	scores := reporting.BuildReadinessScores(matrix)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scores": scores,
		"total":  len(scores),
	})
}

// GET /api/ti/suggest-pack?type=kev
// Returns a validation pack built from CISA KEV CVE-to-technique mappings in the DB.
// Queries technique_cves+cves tables seeded from cisa-kev.json at startup.
// Includes a suggestedScenario body ready to POST to /api/scenarios.
func (h *Handler) GetSuggestPack(w http.ResponseWriter, r *http.Request) {
	packType := r.URL.Query().Get("type")
	if packType != "kev" {
		http.Error(w, `only type=kev is supported`, http.StatusBadRequest)
		return
	}

	type kevTech struct {
		TechniqueID      string `json:"techniqueId"`
		Name             string `json:"name"`
		Tactic           string `json:"tactic"`
		KEVCount         int    `json:"kevCount"`
		RansomwareLinked bool   `json:"ransomwareLinked"`
	}

	rows, err := h.db.Query(r.Context(), `
		SELECT t.technique_id, t.name, t.tactic,
		       COUNT(*) AS kev_count,
		       bool_or(c.known_ransomware) AS ransomware_linked
		FROM technique_cves tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		JOIN techniques t ON t.technique_id = tc.technique_id
		GROUP BY t.technique_id, t.name, t.tactic
		ORDER BY kev_count DESC, ransomware_linked DESC, t.technique_id`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var techs []kevTech
	totalCVEs := 0
	ransomwareCount := 0
	for rows.Next() {
		var t kevTech
		if err := rows.Scan(&t.TechniqueID, &t.Name, &t.Tactic, &t.KEVCount, &t.RansomwareLinked); err != nil {
			continue
		}
		totalCVEs += t.KEVCount
		if t.RansomwareLinked {
			ransomwareCount++
		}
		techs = append(techs, t)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	ids := make([]string, len(techs))
	for i, t := range techs {
		ids[i] = t.TechniqueID
	}

	now := time.Now().UTC()
	suggestedName := fmt.Sprintf("KEV Exposure Pack — %s", now.Format("2006-01-02"))
	suggestedID := fmt.Sprintf("kev-pack-%s", now.Format("20060102"))

	resp := map[string]interface{}{
		"packType":        "kev",
		"packName":        "CISA KEV Exposure Pack",
		"description":     "Validates your controls against ATT&CK techniques linked to active CISA Known Exploited Vulnerabilities.",
		"techniqueCount":  len(techs),
		"totalKevCves":    totalCVEs,
		"ransomwareCount": ransomwareCount,
		"techniques":      techs,
		"hasData":         len(techs) > 0,
		"suggestedName":   suggestedName,
		"suggestedId":     suggestedID,
		"suggestedScenario": map[string]interface{}{
			"id":            suggestedID,
			"name":          suggestedName,
			"description":   "Auto-generated KEV Exposure Pack: validates controls against techniques linked to active CISA Known Exploited Vulnerabilities.",
			"tags":          []string{"kev", "cisa", "threat-informed"},
			"artTechniques": ids,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
