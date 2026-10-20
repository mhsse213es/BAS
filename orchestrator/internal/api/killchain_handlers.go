package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// killChainVerifier verifies campaign definition signatures. Tests may replace
// it with a key they control. Production uses the same trust root as scenarios.
var killChainVerifier integrity.Verifier = integrity.CompiledVerifier{}

// killChainStore returns the store for this handler, or nil when no database is
// configured. Handlers answer 503 in that case rather than pretending to work.
func (h *Handler) killChainStore() *db.KillChainStore {
	if h.db == nil {
		return nil
	}
	return &db.KillChainStore{Pool: h.db}
}

// handlerStageDispatcher sends campaign stages through the same run path that
// single scenario runs use, so every existing guard applies.
type handlerStageDispatcher struct {
	h *Handler
}

// DispatchStage starts one posture run and returns its run ID.
func (d handlerStageDispatcher) DispatchStage(ctx context.Context, sc *scenario.Scenario, agentID string, o stageDispatchOptions) (string, string, error) {
	return d.h.dispatchRun(ctx, sc, agentID, dispatchOpts{
		Mode:        o.Mode,
		Reason:      o.Reason,
		InitiatedBy: o.InitiatedBy,
		ConfirmLive: o.ConfirmLive,
		ConfirmLab:  o.ConfirmLab,
	})
}

// CreateKillChainCampaign stores a campaign definition that carries a valid
// signature. Unsigned or tampered definitions are refused.
// POST /api/killchain/campaigns (scenarios:run)
//
// Body: {"definition": <campaign JSON>, "signature": "<base64 .sig>", "agentId": "<optional>"}.
// The signature covers the exact definition bytes sent.
func (h *Handler) CreateKillChainCampaign(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Definition json.RawMessage `json:"definition"`
		Signature  string          `json:"signature"`
		AgentID    string          `json:"agentId,omitempty"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		jsonError(w, "invalid JSON body: unexpected data after the object", http.StatusBadRequest)
		return
	}
	if len(req.Definition) == 0 {
		jsonError(w, "definition is required", http.StatusBadRequest)
		return
	}
	def, err := killchain.LoadSignedCampaign(req.Definition, []byte(req.Signature), killChainVerifier)
	if errors.Is(err, killchain.ErrUnsignedCampaign) {
		jsonError(w, "campaign definition is not signed by an accepted key", http.StatusForbidden)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	order, err := def.Validate()
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	createdBy := ""
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		createdBy = c.UserID
	}
	if err := store.CreateCampaign(r.Context(), def, createdBy, req.AgentID); err != nil {
		jsonError(w, "could not store campaign: "+err.Error(), http.StatusConflict)
		return
	}
	h.auditLog(r, "killchain.campaign.create", def.ID, map[string]any{"stages": len(def.Stages), "agentBound": req.AgentID != ""}, "success")
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

// AdvanceKillChainCampaign moves a campaign as far as it can. Each stage is
// dispatched as a posture run on the campaign's bound agent. The request names
// who approved it, and that is audited.
// POST /api/killchain/campaigns/{id}/advance (scenarios:run)
func (h *Handler) AdvanceKillChainCampaign(w http.ResponseWriter, r *http.Request) {
	store := h.killChainStore()
	if store == nil {
		jsonError(w, "database not configured", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	bound, err := store.Campaign(r.Context(), id)
	if err != nil {
		writeKillChainError(w, err)
		return
	}
	approval, err := readAdvanceApproval(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var approver string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		approver = c.UserID
	}
	if err := checkCampaignApproval(bound.Def, approval, approver); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var initiatedBy *string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil && c.UserID != "" {
		uid := c.UserID
		initiatedBy = &uid
	}
	if live, lab := bound.Def.LiveAndLabStages(); len(live) > 0 {
		h.auditLog(r, "killchain.campaign.approve", id, map[string]any{
			"liveStages": live, "labStages": lab, "reason": approval.Reason,
			"approver": approver, "createdBy": bound.CreatedBy,
		}, "success")
	}
	exec := EngineStageExecutor{
		AgentID:     bound.AgentID,
		Runs:        poolRunReader{pool: h.db},
		GroundTruth: store,
		Options: stageDispatchOptions{InitiatedBy: initiatedBy,
			ConfirmLive: approval.ConfirmLive, ConfirmLab: approval.ConfirmLab, Reason: approval.Reason},
	}
	if h.verification != nil {
		exec.Attestations = h.verification
	}
	if h.engine != nil {
		exec.Resolver = h.engine
	}
	exec.HostEvents = store
	exec.Hosts = poolRunReader{pool: h.db}
	if h.engine != nil {
		exec.Scenarios = h.engine
	}
	exec.Dispatcher = handlerStageDispatcher{h: h}
	exec.OSes = poolRunReader{pool: h.db}
	exec.Audit = func(ctx context.Context, action, resource string, detail map[string]any, outcome string) {
		h.auditLog(r, action, resource, detail, outcome)
	}
	orch := killchain.Orchestrator{Store: store, Executor: exec}
	if _, err := orch.Advance(r.Context(), id); err != nil {
		writeKillChainError(w, err)
		return
	}
	rec, err := store.Campaign(r.Context(), id)
	if err != nil {
		writeKillChainError(w, err)
		return
	}
	h.auditLog(r, "killchain.campaign.advance", id, map[string]any{"agentBound": bound.AgentID != ""}, "success")
	jsonOK(w, killChainView(rec))
}

// RecoverKillChainCampaigns resolves stages dispatched before a restart. It
// collects finished runs and marks unfinished ones interrupted. It never starts
// a stage. Call it once at boot.
func RecoverKillChainCampaigns(ctx context.Context, pool *pgxpool.Pool, engine *scenario.Engine) error {
	store := &db.KillChainStore{Pool: pool}
	// A nil engine is passed as a nil interface, so host evidence is skipped rather
	// than calling into a nil pointer.
	var scenarios scenarioLookup
	if engine != nil {
		scenarios = engine
	}
	list, err := store.ListCampaigns(ctx)
	if err != nil {
		return err
	}
	exec := EngineStageExecutor{Runs: poolRunReader{pool: pool}, Attestations: verification.NewStore(pool), GroundTruth: store,
		HostEvents: store, Hosts: poolRunReader{pool: pool}, Scenarios: scenarios}
	orch := killchain.Orchestrator{Store: store, Executor: exec}
	for _, c := range list {
		if _, err := orch.Recover(ctx, c.ID); err != nil {
			return err
		}
	}
	return nil
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
		"agentId": rec.AgentID,
		"stages":  stages,
		"rollup":  killchain.Roll(results),
	}
}
