package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Agent Logging ─────────────────────────────────────────────────────────────

// POST /api/agents/events — batch log ingest from agents.
// Accepts {"events": [...LogEvent...]}. Protected by agent secret.
// Routes each event to the correct table by event_type.
func (h *Handler) ReceiveEvents(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Events []struct {
			SchemaVersion int                    `json:"schema_version"`
			EventType     string                 `json:"event_type"`
			AgentID       string                 `json:"agent_id"`
			Seq           int64                  `json:"seq"`
			Ts            time.Time              `json:"ts"`
			Payload       map[string]interface{} `json:"payload"`
		} `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Events) == 0 {
		jsonError(w, "invalid events payload — expected {events:[...]}", http.StatusBadRequest)
		return
	}

	accepted := 0
	for _, e := range body.Events {
		if e.AgentID == "" || e.EventType == "" {
			continue
		}
		ts := e.Ts
		if ts.IsZero() {
			ts = time.Now()
		}
		switch e.EventType {
		case "op_log":
			level, _ := e.Payload["level"].(string)
			category, _ := e.Payload["category"].(string)
			message, _ := e.Payload["message"].(string)
			h.db.Exec(r.Context(),
				`INSERT INTO agent_op_logs
				    (agent_id, level, category, message, seq, schema_ver, created_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				e.AgentID, level, category, message, e.Seq, e.SchemaVersion, ts)
			accepted++
		case "sec_log":
			level, _ := e.Payload["level"].(string)
			scenID, _ := e.Payload["scenario_id"].(string)
			runID, _ := e.Payload["run_id"].(string)
			stepID, _ := e.Payload["step_id"].(string)
			techID, _ := e.Payload["technique_id"].(string)
			category, _ := e.Payload["category"].(string)
			message, _ := e.Payload["message"].(string)
			h.db.Exec(r.Context(),
				`INSERT INTO agent_sec_logs
				    (agent_id, level, scenario_id, run_id, step_id, technique_id,
				     category, message, seq, schema_ver, created_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				e.AgentID, level, scenID, runID, stepID, techID,
				category, message, e.Seq, e.SchemaVersion, ts)
			accepted++
		case "telemetry":
			metric, _ := e.Payload["metric"].(string)
			value, _ := e.Payload["value"].(float64)
			unit, _ := e.Payload["unit"].(string)
			h.db.Exec(r.Context(),
				`INSERT INTO agent_telemetry
				    (agent_id, metric, value, unit, seq, schema_ver, created_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				e.AgentID, metric, value, unit, e.Seq, e.SchemaVersion, ts)
			accepted++
		}
	}
	respond(w, map[string]int{"accepted": accepted})
}

// GET /api/agents/{agentId}/logs/operational?limit=100&before=<RFC3339>
func (h *Handler) GetOpLogs(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	limit, before := logQueryParams(r)

	rows, err := h.db.Query(r.Context(),
		`SELECT id, level, category, message, seq, schema_ver, created_at
		 FROM agent_op_logs
		 WHERE agent_id = $1 AND created_at < $2
		 ORDER BY created_at DESC LIMIT $3`,
		agentID, before, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type opRow struct {
		ID        int64     `json:"id"`
		Level     string    `json:"level"`
		Category  string    `json:"category"`
		Message   string    `json:"message"`
		Seq       int64     `json:"seq"`
		SchemaVer int       `json:"schemaVersion"`
		CreatedAt time.Time `json:"createdAt"`
	}
	var out []opRow
	for rows.Next() {
		var r opRow
		if err := rows.Scan(&r.ID, &r.Level, &r.Category, &r.Message,
			&r.Seq, &r.SchemaVer, &r.CreatedAt); err == nil {
			out = append(out, r)
		}
	}
	if out == nil {
		out = []opRow{}
	}
	respond(w, out)
}

// GET /api/agents/{agentId}/logs/security?limit=100&before=<RFC3339>&run_id=<id>
func (h *Handler) GetSecLogs(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	limit, before := logQueryParams(r)
	runID := r.URL.Query().Get("run_id")

	type secRow struct {
		ID          int64     `json:"id"`
		Level       string    `json:"level"`
		ScenarioID  string    `json:"scenarioId"`
		RunID       string    `json:"runId"`
		StepID      string    `json:"stepId"`
		TechniqueID string    `json:"techniqueId"`
		Category    string    `json:"category"`
		Message     string    `json:"message"`
		Seq         int64     `json:"seq"`
		SchemaVer   int       `json:"schemaVersion"`
		CreatedAt   time.Time `json:"createdAt"`
	}

	var (
		pgRows interface {
			Next() bool
			Close()
			Scan(dest ...interface{}) error
		}
		qErr error
	)
	if runID != "" {
		pgRows, qErr = h.db.Query(r.Context(),
			`SELECT id, level, scenario_id, run_id, step_id, technique_id,
			        category, message, seq, schema_ver, created_at
			 FROM agent_sec_logs
			 WHERE agent_id = $1 AND run_id = $2 AND created_at < $3
			 ORDER BY created_at DESC LIMIT $4`,
			agentID, runID, before, limit)
	} else {
		pgRows, qErr = h.db.Query(r.Context(),
			`SELECT id, level, scenario_id, run_id, step_id, technique_id,
			        category, message, seq, schema_ver, created_at
			 FROM agent_sec_logs
			 WHERE agent_id = $1 AND created_at < $2
			 ORDER BY created_at DESC LIMIT $3`,
			agentID, before, limit)
	}
	if qErr != nil {
		jsonError(w, qErr.Error(), http.StatusInternalServerError)
		return
	}
	defer pgRows.Close()

	var out []secRow
	for pgRows.Next() {
		var r secRow
		if err := pgRows.Scan(&r.ID, &r.Level, &r.ScenarioID, &r.RunID, &r.StepID,
			&r.TechniqueID, &r.Category, &r.Message, &r.Seq, &r.SchemaVer, &r.CreatedAt); err == nil {
			out = append(out, r)
		}
	}
	if out == nil {
		out = []secRow{}
	}
	respond(w, out)
}

// GET /api/agents/{agentId}/telemetry?limit=100&before=<RFC3339>&metric=<name>
func (h *Handler) GetTelemetry(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	limit, before := logQueryParams(r)
	metric := r.URL.Query().Get("metric")

	type telRow struct {
		ID        int64     `json:"id"`
		Metric    string    `json:"metric"`
		Value     float64   `json:"value"`
		Unit      string    `json:"unit"`
		Seq       int64     `json:"seq"`
		SchemaVer int       `json:"schemaVersion"`
		CreatedAt time.Time `json:"createdAt"`
	}

	var (
		pgRows interface {
			Next() bool
			Close()
			Scan(dest ...interface{}) error
		}
		qErr error
	)
	if metric != "" {
		pgRows, qErr = h.db.Query(r.Context(),
			`SELECT id, metric, value, unit, seq, schema_ver, created_at
			 FROM agent_telemetry
			 WHERE agent_id = $1 AND metric = $2 AND created_at < $3
			 ORDER BY created_at DESC LIMIT $4`,
			agentID, metric, before, limit)
	} else {
		pgRows, qErr = h.db.Query(r.Context(),
			`SELECT id, metric, value, unit, seq, schema_ver, created_at
			 FROM agent_telemetry
			 WHERE agent_id = $1 AND created_at < $2
			 ORDER BY created_at DESC LIMIT $3`,
			agentID, before, limit)
	}
	if qErr != nil {
		jsonError(w, qErr.Error(), http.StatusInternalServerError)
		return
	}
	defer pgRows.Close()

	var out []telRow
	for pgRows.Next() {
		var r telRow
		if err := pgRows.Scan(&r.ID, &r.Metric, &r.Value, &r.Unit,
			&r.Seq, &r.SchemaVer, &r.CreatedAt); err == nil {
			out = append(out, r)
		}
	}
	if out == nil {
		out = []telRow{}
	}
	respond(w, out)
}

// logQueryParams extracts shared pagination params from the query string.
// limit: default 100, max 500. before: RFC3339 timestamp, default = now+1s.
func logQueryParams(r *http.Request) (limit int, before time.Time) {
	limit = 100
	before = time.Now().Add(time.Second)
	if s := r.URL.Query().Get("limit"); s != "" {
		var v int
		if _, err := fmt.Sscanf(s, "%d", &v); err == nil && v > 0 {
			limit = v
		}
		if limit > 500 {
			limit = 500
		}
	}
	if s := r.URL.Query().Get("before"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			before = t
		}
	}
	return
}
