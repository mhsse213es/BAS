package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)

// postureFindingAgg is the run-level aggregate outcome for one check_id,
// carried from upsertPostureFindingsForRun into applyPostureFinding. Unlike
// findingAgg (BAS findings), there is no technique/tactic/control metadata --
// a posture check_id is self-describing via postureCheckFindingText.
type postureFindingAgg struct {
	checkID, category string
}

// upsertPostureFindingsForRun (re)derives posture findings from a run's
// persisted results and applies findings.Apply per (agent, check_id), scoped
// to Security Configuration + Identity categories only. Idempotent, safe to
// call from partial submissions -- mirrors upsertFindingsForRun's contract
// exactly (see handlers.go's SubmitScenarioResult call site comment).
func (h *Handler) upsertPostureFindingsForRun(ctx context.Context, runID string) {
	if h.endpointRiskTaxonomy == nil {
		return
	}
	var agentID string
	var resultsRaw []byte
	var observedAt time.Time
	err := h.db.QueryRow(ctx,
		`SELECT agent_id, results, COALESCE(completed_at, started_at) FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &resultsRaw, &observedAt)
	if err != nil {
		return
	}
	var results []models.SimulationResult
	_ = json.Unmarshal(resultsRaw, &results)
	if len(results) == 0 {
		return
	}

	// Aggregate to one outcome per check_id within this run: any failing
	// result for a check_id makes that check_id "missed" for this run; only
	// if every contributing result for that check_id passed does it count as
	// "prevented". Matches upsertFindingsForRun's own precedent exactly:
	// Pass/Blocked contribute as non-fail, Fail contributes as fail, and
	// Error/Skipped are excluded from consideration entirely (a check_id
	// whose only results this run are error/skipped never gets a byCheck
	// entry at all, so no Observation is generated for it this run --
	// same as the `default: continue // error | skipped` branch in
	// upsertFindingsForRun, finding_handlers.go:85-86).
	type agg struct {
		category string
		anyFail  bool
	}
	byCheck := map[string]*agg{}
	for _, r := range results {
		if r.CheckID == "" {
			continue
		}
		category, _, ok := h.endpointRiskTaxonomy.CategoryForCheck(r.CheckID)
		if !ok || (category != endpointrisk.CategorySecurityConfig && category != endpointrisk.CategoryIdentity) {
			continue
		}
		var isFail bool
		switch r.Result {
		case models.ResultPass, models.ResultBlocked:
			isFail = false
		case models.ResultFail:
			isFail = true
		default: // error | skipped -- excluded from this run's contribution
			continue
		}
		a := byCheck[r.CheckID]
		if a == nil {
			a = &agg{category: category}
			byCheck[r.CheckID] = a
		}
		if isFail {
			a.anyFail = true
		}
	}

	for checkID, a := range byCheck {
		outcome := "prevented"
		if a.anyFail {
			outcome = "missed"
		}
		h.applyPostureFinding(ctx, agentID, &postureFindingAgg{checkID: checkID, category: a.category},
			findings.Observation{Outcome: outcome, RunID: runID, ObservedAt: observedAt})
	}
}

// applyPostureFinding loads the current posture finding for (agentID,
// a.checkID), runs findings.Apply unchanged, and writes the result back
// (insert on create, update otherwise) -- structurally identical to
// applyFinding (finding_handlers.go) minus the BAS-specific columns and the
// dispatchTicketing call (no ticketing integration for posture findings in
// this sub-project).
func (h *Handler) applyPostureFinding(ctx context.Context, agentID string, a *postureFindingAgg, o findings.Observation) {
	var s findings.State
	var resolvedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT status, exposure_state, occurrence_count, reopened_count,
		        COALESCE(last_run_id,''), last_observed_at, resolved_at
		   FROM posture_findings WHERE agent_id=$1 AND check_id=$2`,
		agentID, a.checkID).
		Scan(&s.Status, &s.ExposureState, &s.OccurrenceCount, &s.ReopenedCount, &s.LastRunID, &s.LastObservedAt, &resolvedAt)
	if err == nil {
		s.Exists = true
		s.Resolved = resolvedAt != nil
	}

	next, tr := findings.Apply(s, o)
	if tr == findings.Noop || tr == findings.Stale {
		return
	}
	if tr == findings.Created {
		text := postureCheckFindingText[a.checkID]
		_, _ = h.db.Exec(ctx,
			`INSERT INTO posture_findings (agent_id, check_id, category, title, exposure_state, status,
			        occurrence_count, last_run_id, first_seen, last_seen, last_observed_at)
			 VALUES ($1,$2,$3,$4,$5,'open',1,$6,NOW(),NOW(),$7)
			 ON CONFLICT (agent_id, check_id) DO NOTHING`,
			agentID, a.checkID, a.category, text.Title, next.ExposureState, o.RunID, o.ObservedAt)
		return
	}

	// recurred | healed | reopened -> update. (Refined never occurs here --
	// that transition only fires when a later observation shares the exact
	// same RunID as the stored state, which upsertPostureFindingsForRun never
	// produces since it aggregates each check_id to one Observation per run.)
	var resolvedAtSet *time.Time
	var resolvedReason *string
	clearResolved := tr == findings.Reopened
	if tr == findings.Healed {
		now := time.Now()
		reason := "re-validated pass"
		resolvedAtSet, resolvedReason = &now, &reason
	}
	_, _ = h.db.Exec(ctx,
		`UPDATE posture_findings SET status=$1, exposure_state=$2, occurrence_count=$3, reopened_count=$4,
		        last_run_id=$5, last_seen=NOW(), last_observed_at=$6,
		        resolved_at = CASE WHEN $7 THEN NULL ELSE COALESCE($8, resolved_at) END,
		        resolved_reason = COALESCE($9, resolved_reason)
		   WHERE agent_id=$10 AND check_id=$11`,
		next.Status, next.ExposureState, next.OccurrenceCount, next.ReopenedCount,
		o.RunID, o.ObservedAt,
		clearResolved, resolvedAtSet, resolvedReason,
		agentID, a.checkID)
}

const postureFindingCols = `id, agent_id, check_id, category, title, severity, status,
	occurrence_count, reopened_count, first_seen, last_seen, last_observed_at,
	COALESCE(last_run_id,''), resolved_at, resolved_reason`

func scanPostureFindings(rows findingScanner) []map[string]any {
	out := []map[string]any{}
	for rows.Next() {
		var id, agentID, checkID, category, title, severity, status, lastRunID string
		var occ, reopened int
		var firstSeen, lastSeen, lastObserved time.Time
		var resolvedAt *time.Time
		var resolvedReason *string
		if rows.Scan(&id, &agentID, &checkID, &category, &title, &severity, &status,
			&occ, &reopened, &firstSeen, &lastSeen, &lastObserved, &lastRunID, &resolvedAt, &resolvedReason) != nil {
			continue
		}
		m := map[string]any{
			"id": id, "agentId": agentID, "checkId": checkID, "category": category,
			"title": title, "severity": severity, "status": status,
			"occurrenceCount": occ, "reopenedCount": reopened,
			"firstSeen": firstSeen, "lastSeen": lastSeen, "lastObservedAt": lastObserved,
			"lastRunId": lastRunID,
		}
		if resolvedAt != nil {
			m["resolvedAt"] = *resolvedAt
		}
		if resolvedReason != nil {
			m["resolvedReason"] = *resolvedReason
		}
		out = append(out, m)
	}
	return out
}

// ListAgentPostureFindings returns one agent's posture findings, open-only by
// default (?status=all includes remediated). GET /api/agents/{agentId}/posture-findings
func (h *Handler) ListAgentPostureFindings(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	statusFilter := "open"
	if r.URL.Query().Get("status") == "all" {
		statusFilter = ""
	}
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` FROM posture_findings
		  WHERE agent_id=$1 AND ($2='' OR status=$2)
		  ORDER BY last_seen DESC`,
		agentID, statusFilter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	respond(w, scanPostureFindings(rows))
}

// GetPostureFinding returns one posture finding by ID. GET /api/posture-findings/{id}
func (h *Handler) GetPostureFinding(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT `+postureFindingCols+` FROM posture_findings WHERE id=$1`, chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list := scanPostureFindings(rows)
	rows.Close()
	if len(list) == 0 {
		jsonError(w, "posture finding not found", http.StatusNotFound)
		return
	}
	respond(w, list[0])
}
