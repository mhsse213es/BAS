package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)

// SubmitRunEvents ingests a batch of run lifecycle events from an agent. Each
// event is inserted idempotently by (run_id, seq); the run's denormalized
// progress summary is updated ONLY for events that were actually inserted, so a
// network retry of the same seq can never double-count. Best-effort overlay: the
// authoritative results still arrive via /api/scenarios/result.
func (h *Handler) SubmitRunEvents(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch []models.RunEvent
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		jsonError(w, "invalid events payload — expected a JSON array of events", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	for _, e := range batch {
		if e.RunID == "" || e.Type == "" {
			continue
		}
		payload := []byte("{}")
		if e.Payload != nil {
			payload, _ = json.Marshal(e.Payload)
		}
		if _, err := h.db.Exec(ctx, `
			WITH ins AS (
				INSERT INTO run_events (run_id, seq, type, task_id, technique_id, ts, payload)
				VALUES ($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (run_id, seq) DO NOTHING
				RETURNING type, payload
			)
			UPDATE scenario_runs s SET
				steps_total   = CASE WHEN ins.type='run_started'
				                     THEN COALESCE((ins.payload->>'stepsTotal')::int, s.steps_total)
				                     ELSE s.steps_total END,
				steps_running = s.steps_running
				                + CASE WHEN ins.type='started' THEN 1 ELSE 0 END
				                - CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
				steps_done    = s.steps_done    + CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
				steps_passed  = s.steps_passed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict'='pass' THEN 1 ELSE 0 END,
				steps_failed  = s.steps_failed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict' IN ('fail','blocked') THEN 1 ELSE 0 END,
				steps_timeout = s.steps_timeout + CASE WHEN ins.type='timeout' THEN 1 ELSE 0 END
			FROM ins
			WHERE s.id = $1`,
			e.RunID, e.Seq, e.Type, e.TaskID, e.TechniqueID, e.Ts, payload); err != nil {
			log.Printf("[events] ingest run %s seq %d: %v", e.RunID, e.Seq, err)
		}
	}

	h.relayRunEvents(batch)

	w.WriteHeader(http.StatusOK)
}

// relayRunEvents is a stub until Task 4 wires the browser broadcast.
func (h *Handler) relayRunEvents(_ []models.RunEvent) {}

// ListRunEvents returns a run's events ordered by seq (for browser reconnect /
// timeline reconstruction). JWT-protected (registered under the auth group).
func (h *Handler) ListRunEvents(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	rows, err := h.db.Query(r.Context(),
		`SELECT seq, type, task_id, technique_id, ts, payload
		 FROM run_events WHERE run_id = $1 ORDER BY seq ASC`, runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := make([]models.RunEvent, 0)
	for rows.Next() {
		var e models.RunEvent
		var payload []byte
		if err := rows.Scan(&e.Seq, &e.Type, &e.TaskID, &e.TechniqueID, &e.Ts, &payload); err != nil {
			continue
		}
		_ = json.Unmarshal(payload, &e.Payload)
		e.RunID = runID
		out = append(out, e)
	}
	respond(w, out)
}
