package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/go-chi/chi/v5"
)

// findingAgg is the worst per-run outcome for one (technique, control) key,
// carried from upsertFindingsForRun into applyFinding.
type findingAgg struct {
	techID, name, tactic, severity, control, source, outcome string
	dataSrc                                                  []string
}

// upsertFindingsForRun (re)derives findings from a run's persisted results +
// detection_summary and applies the state machine per (agent,technique,control).
// Idempotent and safe to call from both the result and detection ingest hooks;
// out-of-order older runs are ignored by findings.Apply.
func (h *Handler) upsertFindingsForRun(ctx context.Context, runID string) {
	var agentID string
	var resultsRaw, detRaw, metaRaw []byte
	var observedAt time.Time
	var campaignID *string
	err := h.db.QueryRow(ctx,
		`SELECT agent_id, results, detection_summary, step_meta,
		        COALESCE(completed_at, started_at), campaign_id
		   FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &resultsRaw, &detRaw, &metaRaw, &observedAt, &campaignID)
	if err != nil {
		return
	}
	var results []models.SimulationResult
	_ = json.Unmarshal(resultsRaw, &results)
	if len(results) == 0 {
		return
	}
	detected := detectedTechs(detRaw, results) // technique ids caught by EDR/SIEM

	// step framework per technique → source_type
	frameworkByTech := map[string]string{}
	var meta map[string]scenario.StepMeta
	if json.Unmarshal(metaRaw, &meta) == nil {
		for _, m := range meta {
			if m.TechniqueID != "" {
				frameworkByTech[m.TechniqueID] = m.Framework
			}
		}
	}

	// agent's installed products snapshot (jsonb passed through verbatim)
	var prodRaw []byte
	h.db.QueryRow(ctx, `SELECT security_products FROM agents WHERE agent_id = $1`, agentID).Scan(&prodRaw)
	if len(prodRaw) == 0 {
		prodRaw = []byte("[]")
	}

	// Aggregate to the worst outcome per (technique, control) within this run.
	worstRank := map[string]int{"prevented": 0, "detected_only": 1, "missed": 2}
	byKey := map[string]*findingAgg{}
	for _, res := range results {
		id := res.Technique.ID
		if id == "" {
			continue
		}
		var outcome string
		switch res.Result {
		case models.ResultPass, models.ResultBlocked:
			outcome = "prevented"
		case models.ResultFail:
			if detected[id] {
				outcome = "detected_only"
			} else {
				outcome = "missed"
			}
		default:
			continue // error | skipped
		}
		var ds []string
		if e := attackdata.Lookup(id); e != nil {
			ds = e.DataSources
		}
		control := findings.ControlClass(ds)
		key := id + "|" + control
		a := byKey[key]
		if a == nil {
			src := frameworkByTech[id]
			if src == "art" {
				src = "atomic"
			} else if src != "caldera" {
				src = "custom"
			}
			byKey[key] = &findingAgg{techID: id, name: res.Technique.Name, tactic: res.Technique.Tactic,
				severity: res.Severity, control: control, source: src, outcome: outcome, dataSrc: ds}
		} else if worstRank[outcome] > worstRank[a.outcome] {
			a.outcome = outcome
		}
	}

	for _, a := range byKey {
		h.applyFinding(ctx, agentID, a, prodRaw,
			findings.Observation{Outcome: a.outcome, RunID: runID, ObservedAt: observedAt}, campaignID)
	}
}

// applyFinding loads the current finding for the key, runs the state machine,
// and writes the result back (insert on create, update otherwise).
func (h *Handler) applyFinding(ctx context.Context, agentID string, a *findingAgg, prodRaw []byte, o findings.Observation, campaignID *string) {
	var s findings.State
	var resolvedAt *time.Time
	err := h.db.QueryRow(ctx,
		`SELECT status, exposure_state, occurrence_count, reopened_count,
		        COALESCE(last_run_id,''), last_observed_at, resolved_at
		   FROM findings WHERE agent_id=$1 AND technique_id=$2 AND control_class=$3`,
		agentID, a.techID, a.control).
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
		dsJSON, _ := json.Marshal(a.dataSrc)
		_, _ = h.db.Exec(ctx,
			`INSERT INTO findings (agent_id, technique_id, control_class, technique_name, tactic, severity,
			        exposure_state, status, source_type, attack_data_source, security_product_snapshot,
			        occurrence_count, last_run_id, last_campaign_id, first_seen, last_seen, last_observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,'open',$8,$9,$10,1,$11,$12,NOW(),NOW(),$13)
			 ON CONFLICT (agent_id, technique_id, control_class) DO NOTHING`,
			agentID, a.techID, a.control, a.name, a.tactic, a.severity, next.ExposureState, a.source, dsJSON, prodRaw,
			o.RunID, campaignID, o.ObservedAt)
		return
	}

	// recurred | refined | healed | reopened → update
	var resolvedAtSet *time.Time
	var resolvedBy, resolvedReason *string
	clearResolved := tr == findings.Reopened
	if tr == findings.Healed {
		now := time.Now()
		sys, reason := "system", "re-validated prevented"
		resolvedAtSet, resolvedBy, resolvedReason = &now, &sys, &reason
	}
	_, _ = h.db.Exec(ctx,
		`UPDATE findings SET status=$1, exposure_state=$2, occurrence_count=$3, reopened_count=$4,
		        last_run_id=$5, last_campaign_id=$6, last_seen=NOW(), last_observed_at=$7,
		        resolved_at = CASE WHEN $8 THEN NULL ELSE COALESCE($9, resolved_at) END,
		        resolved_by = COALESCE($10, resolved_by),
		        resolved_reason = COALESCE($11, resolved_reason)
		   WHERE agent_id=$12 AND technique_id=$13 AND control_class=$14`,
		next.Status, next.ExposureState, next.OccurrenceCount, next.ReopenedCount,
		o.RunID, campaignID, o.ObservedAt,
		clearResolved, resolvedAtSet, resolvedBy, resolvedReason,
		agentID, a.techID, a.control)
}

// findingScanner is satisfied by pgx.Rows — lets scanFindings stay storage-agnostic.
type findingScanner interface {
	Next() bool
	Scan(dest ...any) error
}

const findingCols = `id, agent_id, technique_id, control_class, technique_name, tactic,
	severity, exposure_state, status, source_type, occurrence_count, reopened_count,
	last_campaign_id, first_seen, last_seen, resolved_reason`

func scanFindings(rows findingScanner) []map[string]any {
	out := []map[string]any{}
	for rows.Next() {
		var id, agentID, techID, control, name, tactic, severity, exposure, status, source string
		var occ, reopened int
		var firstSeen, lastSeen time.Time
		var lastCampaign, resolvedReason *string
		if rows.Scan(&id, &agentID, &techID, &control, &name, &tactic, &severity, &exposure, &status, &source,
			&occ, &reopened, &lastCampaign, &firstSeen, &lastSeen, &resolvedReason) != nil {
			continue
		}
		m := map[string]any{
			"id": id, "agentId": agentID, "techniqueId": techID, "controlClass": control,
			"techniqueName": name, "tactic": tactic, "severity": severity, "exposureState": exposure,
			"status": status, "sourceType": source, "occurrenceCount": occ, "reopenedCount": reopened,
			"firstSeen": firstSeen, "lastSeen": lastSeen,
		}
		if lastCampaign != nil {
			m["lastCampaignId"] = *lastCampaign
		}
		if resolvedReason != nil {
			m["resolvedReason"] = *resolvedReason
		}
		out = append(out, m)
	}
	return out
}

// ListFindings returns findings, filterable by status/severity/agentId, ordered
// by severity then recency. GET /api/findings
func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := h.db.Query(r.Context(),
		`SELECT `+findingCols+` FROM findings
		  WHERE ($1='' OR status=$1) AND ($2='' OR severity=$2) AND ($3='' OR agent_id=$3)
		  ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
		           last_seen DESC`,
		q.Get("status"), q.Get("severity"), q.Get("agentId"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	respond(w, scanFindings(rows))
}

// GetFinding returns one finding plus authoritative enrichment, the agent's
// product snapshot, and the raw ATT&CK data sources. GET /api/findings/{id}
func (h *Handler) GetFinding(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT `+findingCols+` FROM findings WHERE id=$1`, chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	list := scanFindings(rows)
	rows.Close()
	if len(list) == 0 {
		jsonError(w, "finding not found", http.StatusNotFound)
		return
	}
	f := list[0]
	if e := attackdata.Lookup(f["techniqueId"].(string)); e != nil {
		f["enrichment"] = e
	}
	var prodRaw, dsRaw []byte
	h.db.QueryRow(r.Context(), `SELECT security_product_snapshot, attack_data_source FROM findings WHERE id=$1`,
		f["id"]).Scan(&prodRaw, &dsRaw)
	var prod, ds []any
	_ = json.Unmarshal(prodRaw, &prod)
	_ = json.Unmarshal(dsRaw, &ds)
	f["productSnapshot"] = prod
	f["dataSources"] = ds
	respond(w, f)
}

// SetFindingStatus sets an analyst-chosen status. POST /api/findings/{id}/status
// body {status, reason?}. Analyst+.
func (h *Handler) SetFindingStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	valid := map[string]bool{"open": true, "triaged": true, "remediated": true, "risk_accepted": true}
	if !valid[req.Status] {
		jsonError(w, "invalid status — use open | triaged | remediated | risk_accepted", http.StatusBadRequest)
		return
	}
	by := "unknown"
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		by = c.UserID
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE findings SET status=$1, resolved_by=$2, resolved_reason=$3,
		        resolved_at = CASE WHEN $1='remediated' THEN NOW() ELSE NULL END
		   WHERE id=$4`,
		req.Status, by, req.Reason, chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "finding not found", http.StatusNotFound)
		return
	}
	respond(w, map[string]any{"status": req.Status})
}
