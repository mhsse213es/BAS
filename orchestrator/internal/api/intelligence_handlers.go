package api

import (
	"net/http"

	"github.com/audspect/bas/internal/intelligence"
)

// GET /api/intelligence/campaigns
func (h *Handler) IntelligenceCampaigns(w http.ResponseWriter, r *http.Request) {
	campaigns, err := intelligence.ListCampaigns(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, campaigns)
}

// GET /api/intelligence/malware
func (h *Handler) IntelligenceMalware(w http.ResponseWriter, r *http.Request) {
	malware, err := intelligence.ListMalware(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, malware)
}

// GET /api/intelligence/tools
func (h *Handler) IntelligenceTools(w http.ResponseWriter, r *http.Request) {
	tools, err := intelligence.ListTools(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, tools)
}
