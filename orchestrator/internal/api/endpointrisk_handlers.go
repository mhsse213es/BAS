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

	compliance := h.complianceInput(r.Context(), agentID, now, allResults)
	bas := h.basReadinessInput(now, allResults)
	pastCompliance := h.complianceInput(r.Context(), agentID, weekAgo, allResults)
	pastBAS := h.basReadinessInput(weekAgo, allResults)

	health := endpointrisk.ComputeHealth(agentID, profile, compliance, bas, pastCompliance, pastBAS)
	respond(w, health)
}
