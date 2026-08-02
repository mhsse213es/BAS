package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/exposure"
)

// profileForAgent finds the AssetExposureProfile for agentId within an
// already-built AssetGraph by matching AssetIdentity.AgentID -- exposure's
// own exported surface is hostKey-keyed (Profile(hostKey)), but
// AssetIdentity.HostKey is present on every Summaries() row, so this needs
// no change to internal/exposure itself.
func profileForAgent(ag *exposure.AssetGraph, agentID string) (exposure.AssetExposureProfile, bool) {
	for _, s := range ag.Summaries() {
		if s.Asset.AgentID == agentID {
			return ag.Profile(s.Asset.HostKey)
		}
	}
	return exposure.AssetExposureProfile{}, false
}

// GetAgentRisk returns one agent's computed Health Score, categorized
// findings, attack-path chain, and action plan. Read-only (Viewer+).
// GET /api/agents/{agentId}/risk
func (h *Handler) GetAgentRisk(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profile, ok := profileForAgent(ag, agentID)
	if !ok {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	allResults := h.aggregateAgentResults(r.Context(), agentID)
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)

	nowInputs := endpointrisk.HealthInputs{
		Compliance:     h.complianceInput(r.Context(), agentID, now, allResults),
		BAS:            h.basReadinessInput(now, allResults),
		SecurityConfig: h.securityConfigInput(r.Context(), agentID, now, allResults),
		Identity:       h.identityInput(r.Context(), agentID, now, allResults),
	}
	pastInputs := endpointrisk.HealthInputs{
		Compliance:     h.complianceInput(r.Context(), agentID, weekAgo, allResults),
		BAS:            h.basReadinessInput(weekAgo, allResults),
		SecurityConfig: h.securityConfigInput(r.Context(), agentID, weekAgo, allResults),
		Identity:       h.identityInput(r.Context(), agentID, weekAgo, allResults),
	}

	health := endpointrisk.ComputeHealth(agentID, profile, nowInputs, pastInputs)
	respond(w, health)
}

// AgentRiskRow is the fleet-list projection -- one row per managed agent,
// enough to sort/filter by before drilling into GetAgentRisk's full detail.
type AgentRiskRow struct {
	AgentID            string `json:"agentId"`
	Hostname           string `json:"hostname"`
	HealthScore        int    `json:"healthScore"`
	CriticalityRisk    int    `json:"criticalityRisk"`
	Trend              string `json:"trend"`
	TopDeficitCategory string `json:"topDeficitCategory,omitempty"`
	OpenFindingsCount  int    `json:"openFindingsCount"`
}

// GetAgentRiskSummary returns every managed agent's Health Score for the
// fleet-wide "Risk & Remediation" tab. Read-only (Viewer+).
// GET /api/agents/risk-summary
func (h *Handler) GetAgentRiskSummary(w http.ResponseWriter, r *http.Request) {
	ag, err := h.buildAssetGraph(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)

	var out []AgentRiskRow
	for _, s := range ag.Summaries() {
		if s.Asset.AgentID == "" {
			continue // exposure includes non-agent graph nodes too -- this tab is agent-scoped
		}
		profile, ok := ag.Profile(s.Asset.HostKey)
		if !ok {
			continue
		}
		allResults := h.aggregateAgentResults(r.Context(), s.Asset.AgentID)
		nowInputs := endpointrisk.HealthInputs{
			Compliance:     h.complianceInput(r.Context(), s.Asset.AgentID, now, allResults),
			BAS:            h.basReadinessInput(now, allResults),
			SecurityConfig: h.securityConfigInput(r.Context(), s.Asset.AgentID, now, allResults),
			Identity:       h.identityInput(r.Context(), s.Asset.AgentID, now, allResults),
		}
		pastInputs := endpointrisk.HealthInputs{
			Compliance:     h.complianceInput(r.Context(), s.Asset.AgentID, weekAgo, allResults),
			BAS:            h.basReadinessInput(weekAgo, allResults),
			SecurityConfig: h.securityConfigInput(r.Context(), s.Asset.AgentID, weekAgo, allResults),
			Identity:       h.identityInput(r.Context(), s.Asset.AgentID, weekAgo, allResults),
		}
		health := endpointrisk.ComputeHealth(s.Asset.AgentID, profile, nowInputs, pastInputs)

		row := AgentRiskRow{
			AgentID: s.Asset.AgentID, Hostname: s.Asset.Label,
			HealthScore: health.HealthScore, CriticalityRisk: health.CriticalityRisk, Trend: health.Trend.Direction,
		}
		if len(health.ActionPlan) > 0 {
			row.TopDeficitCategory = health.ActionPlan[0].CategoryName
		}
		for _, c := range health.Categories {
			row.OpenFindingsCount += len(c.Findings)
		}
		out = append(out, row)
	}
	respond(w, map[string]any{"agents": out})
}
