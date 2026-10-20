package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

// killChainStore returns the store for this handler, or nil when no database is
// configured. Handlers answer 503 in that case rather than pretending to work.
func (h *Handler) killChainStore() *db.KillChainStore {
	if h.db == nil {
		return nil
	}
	return &db.KillChainStore{Pool: h.db}
}

// CreateKillChainCampaign stores a validated campaign definition.
// POST /api/killchain/campaigns (scenarios:run)
func (h *Handler) CreateKillChainCampaign(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var def killchain.CampaignDef
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&def); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		jsonError(w, "invalid JSON body: unexpected data after the object", http.StatusBadRequest)
		return
	}
	order, err := def.Validate()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	createdBy := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		createdBy = c.UserID
	}
	if err := store.CreateCampaign(r.Context(), def, createdBy); err != nil {
		jsonError(w, "could not store campaign: "+err.Error(), http.StatusConflict)
		return
	}
	h.auditLog(r, "killchain.campaign.create", def.ID, map[string]any{"stages": len(def.Stages)}, "success")
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"id": def.ID, "version": def.Version, "order": order})
}

// ListKillChainCampaigns returns stored campaigns, newest first.
// GET /api/killchain/campaigns
func (h *Handler) ListKillChainCampaigns(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	list, err := store.ListCampaigns(r.Context())
	if err != nil {
		jsonError(w, "could not list campaigns", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"campaigns": list})
}

// GetKillChainCampaign returns one campaign: its stages in topological order,
// each with its verdict and reasons, plus the derived rollup.
// GET /api/killchain/campaigns/{id}
func (h *Handler) GetKillChainCampaign(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	rec, err := store.Campaign(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeKillChainError(w, err)
		return
	}
	jsonOK(w, killChainView(rec))
}

// AdvanceKillChainCampaign moves a campaign as far as the wired executor allows.
// With no scenario adapter wired, stages end in ERROR; nothing is faked.
// POST /api/killchain/campaigns/{id}/advance (scenarios:run)
func (h *Handler) AdvanceKillChainCampaign(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	orch := killchain.Orchestrator{Store: store, Executor: killchain.UnwiredExecutor{}}
	if _, err := orch.Advance(r.Context(), id); err != nil {
		writeKillChainError(w, err)
		return
	}
	rec, err := store.Campaign(r.Context(), id)
	if err != nil {
		writeKillChainError(w, err)
		return
	}
	h.auditLog(r, "killchain.campaign.advance", id, nil, "success")
	jsonOK(w, killChainView(rec))
}

func writeKillChainError(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrKillChainNotFound) {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}
	jsonError(w, "campaign error: "+err.Error(), http.StatusBadRequest)
}

type killChainStageView struct {
	Key         string                   `json:"key"`
	ScenarioID  string                   `json:"scenarioId"`
	State       killchain.StageState     `json:"state"`
	Verdict     killchain.Verdict        `json:"verdict,omitempty"`
	Reasons     []string                 `json:"reasons,omitempty"`
	ExecutionID string                   `json:"executionId,omitempty"`
	Evidence    *killchain.StageEvidence `json:"evidence,omitempty"`
}

// killChainView builds the response. Stages are listed in the definition's
// topological order, so the output is stable across reads.
func killChainView(rec killchain.CampaignRecord) map[string]any {
	order, _ := rec.Def.Validate()
	stages := make([]killChainStageView, 0, len(order))
	results := make([]killchain.StageResult, 0, len(order))
	for _, key := range order {
		def, _ := rec.Def.Stage(key)
		sr, ok := rec.Stages[key]
		if !ok {
			sr = killchain.StageRecord{Key: key, State: killchain.StatePending}
		}
		stages = append(stages, killChainStageView{
			Key: key, ScenarioID: def.ScenarioID, State: sr.State, Verdict: sr.Verdict,
			Reasons: sr.Reasons, ExecutionID: sr.ExecutionID, Evidence: sr.Evidence,
		})
		results = append(results, killchain.StageResult{Key: key, State: sr.State, Verdict: sr.Verdict})
	}
	return map[string]any{
		"id":      rec.ID,
		"name":    rec.Def.Name,
		"version": rec.Def.Version,
		"stages":  stages,
		"rollup":  killchain.Roll(results),
	}
}
