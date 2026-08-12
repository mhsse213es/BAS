package api

import (
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/openaev"
	"github.com/go-chi/chi/v5"
)

// GET /api/openaev/config — Admin. bearer_token is never included in the response.
func (h *Handler) GetOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var baseURL, status, lastError string
	var pollHours int
	var enabled bool
	err := h.db.QueryRow(r.Context(),
		`SELECT base_url, poll_interval_hours, enabled, last_sync_status, last_error
		   FROM openaev_config WHERE id = 1`,
	).Scan(&baseURL, &pollHours, &enabled, &status, &lastError)
	if err != nil {
		// No row yet — defaults.
		respond(w, map[string]any{"baseUrl": "", "pollIntervalHours": 24, "enabled": false, "lastSyncStatus": "never", "lastError": ""})
		return
	}
	respond(w, map[string]any{
		"baseUrl":           baseURL,
		"pollIntervalHours": pollHours,
		"enabled":           enabled,
		"lastSyncStatus":    status,
		"lastError":         lastError,
	})
}

// PUT /api/openaev/config — Admin.
func (h *Handler) PutOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL           string `json:"baseUrl"`
		BearerToken       string `json:"bearerToken"`
		PollIntervalHours int    `json:"pollIntervalHours"`
		Enabled           bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO openaev_config (id, base_url, bearer_token, poll_interval_hours, enabled, updated_at)
		 VALUES (1, $1, $2, $3, $4, NOW())
		 ON CONFLICT (id) DO UPDATE SET
		   base_url = EXCLUDED.base_url,
		   bearer_token = CASE WHEN EXCLUDED.bearer_token = '' THEN openaev_config.bearer_token ELSE EXCLUDED.bearer_token END,
		   poll_interval_hours = EXCLUDED.poll_interval_hours,
		   enabled = EXCLUDED.enabled,
		   updated_at = NOW()`,
		body.BaseURL, body.BearerToken, body.PollIntervalHours, body.Enabled,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "openaev.config.update", "", map[string]any{"baseUrl": body.BaseURL, "enabled": body.Enabled}, "ok")
	respond(w, map[string]string{"status": "ok"})
}

// POST /api/openaev/config/test — Admin. Validates connectivity/credentials
// before the operator flips enabled=true.
func (h *Handler) TestOpenAEVConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BaseURL     string `json:"baseUrl"`
		BearerToken string `json:"bearerToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	provider := openaev.NewRESTProvider(body.BaseURL, body.BearerToken)
	refs, err := provider.List(r.Context())
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true, "scenarioCount": len(refs)})
}

// POST /api/openaev/sync — Admin. Manual sync trigger.
func (h *Handler) SyncOpenAEV(w http.ResponseWriter, r *http.Request) {
	var baseURL, token string
	var enabled bool
	err := h.db.QueryRow(r.Context(), `SELECT base_url, bearer_token, enabled FROM openaev_config WHERE id = 1`).
		Scan(&baseURL, &token, &enabled)
	if err != nil || !enabled {
		jsonError(w, "openaev is not configured/enabled", http.StatusConflict)
		return
	}

	store := openaev.NewSQLStore(h.db)
	importer := openaev.NewImporter(store)
	provider := openaev.NewRESTProvider(baseURL, token)

	result, syncErr := importer.SyncAll(r.Context(), provider)
	status := "ok"
	lastErr := ""
	if syncErr != nil {
		status = "error"
		lastErr = syncErr.Error()
	}
	h.db.Exec(r.Context(),
		`UPDATE openaev_config SET last_sync_at = NOW(), last_sync_status = $1, last_error = $2 WHERE id = 1`,
		status, lastErr)

	h.auditLog(r, "openaev.sync", "", map[string]any{"result": result}, "ok")
	if syncErr != nil {
		jsonError(w, syncErr.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}

// GET /api/openaev/status — Viewer+.
func (h *Handler) GetOpenAEVStatus(w http.ResponseWriter, r *http.Request) {
	var lastSyncAt any
	var status, lastError string
	h.db.QueryRow(r.Context(),
		`SELECT last_sync_at, last_sync_status, last_error FROM openaev_config WHERE id = 1`,
	).Scan(&lastSyncAt, &status, &lastError)

	var scenarioCount int
	h.db.QueryRow(r.Context(), `SELECT count(*) FROM openaev_scenarios`).Scan(&scenarioCount)

	respond(w, map[string]any{
		"lastSyncAt":     lastSyncAt,
		"lastSyncStatus": status,
		"lastError":      lastError,
		"scenarioCount":  scenarioCount,
	})
}

// GET /api/openaev/scenarios — Viewer+.
func (h *Handler) ListOpenAEVScenarios(w http.ResponseWriter, r *http.Request) {
	store := openaev.NewSQLStore(h.db)
	scenarios, err := store.List(r.Context(), "scenario")
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scenarios == nil {
		scenarios = []openaev.Scenario{}
	}
	respond(w, scenarios)
}

// GET /api/openaev/scenarios/{id} — Viewer+.
func (h *Handler) GetOpenAEVScenario(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	store := openaev.NewSQLStore(h.db)
	sc, detail, found, err := store.Get(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	respond(w, map[string]any{"scenario": sc, "detail": detail})
}

// POST /api/openaev/import — Admin. Air-gapped manual bundle upload.
func (h *Handler) ImportOpenAEVBundle(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	buf := make([]byte, 0)
	chunk := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if readErr != nil {
			break
		}
	}

	store := openaev.NewSQLStore(h.db)
	importer := openaev.NewImporter(store)
	result, err := importer.ImportOne(r.Context(), buf)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "openaev.import", "", map[string]any{"result": result}, "ok")
	respond(w, result)
}

// POST /api/openaev/scenarios/{id}/create-plan — Admin.
// Builds an editable exercise plan from a synced OpenAEV scenario
// (structure-preserving skeleton — see openaev.BuildPlan).
func (h *Handler) CreateExercisePlanFromOpenAEV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	store := openaev.NewSQLStore(h.db)
	sc, detail, found, err := store.Get(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		jsonError(w, "scenario not found", http.StatusNotFound)
		return
	}
	plan := openaev.BuildPlan(sc, detail)
	if err := h.exerciseStore.CreatePlan(r.Context(), &plan); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "openaev.create_plan", plan.ID, map[string]any{"scenario_id": id, "name": plan.Name}, "success")
	respond(w, map[string]string{"plan_id": plan.ID})
}
