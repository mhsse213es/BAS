package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/connector"
	"github.com/audspect/bas/internal/ioc"
)

var validConnectors = map[string]bool{"misp": true, "opencti": true, "otx": true}

// GET /api/threat-intel/{connector}/config — Admin. api_key is never
// included in the response, matching GetOpenAEVConfig's existing precedent.
func (h *Handler) GetThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	var baseURL, status, lastError string
	var enabled, insecureTLS bool
	err := h.db.QueryRow(r.Context(),
		`SELECT base_url, enabled, insecure_tls, last_sync_status, last_error FROM threat_intel_config WHERE connector = $1`, conn,
	).Scan(&baseURL, &enabled, &insecureTLS, &status, &lastError)
	if err != nil {
		// No row has ever been saved for this connector -- "configured: false"
		// tells the frontend this is a genuine first-time setup, so its
		// save-confirmation "you're about to overwrite an existing value"
		// modal (which only makes sense once real values are already in
		// place) can stay hidden until an actual update happens.
		respond(w, map[string]any{"baseUrl": "", "enabled": false, "insecureTls": false, "lastSyncStatus": "never", "lastError": "", "configured": false})
		return
	}
	respond(w, map[string]any{
		"baseUrl":        baseURL,
		"enabled":        enabled,
		"insecureTls":    insecureTLS,
		"lastSyncStatus": status,
		"lastError":      lastError,
		"configured":     true,
	})
}

// PUT /api/threat-intel/{connector}/config — Admin. Empty submitted apiKey
// keeps the existing stored key, matching PutOpenAEVConfig's existing
// precedent. On success, rebuilds the full 3-connector source list from the
// DB and calls Scheduler.Reconfigure so the change takes effect immediately
// -- no restart. For 'otx', also swaps h.iocProvider the same way, since
// OTX has a second, independent consumer beyond the Scheduler.
func (h *Handler) PutThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	var body struct {
		BaseURL     string `json:"baseUrl"`
		APIKey      string `json:"apiKey"`
		Enabled     bool   `json:"enabled"`
		InsecureTLS bool   `json:"insecureTls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO threat_intel_config (connector, base_url, api_key, enabled, insecure_tls, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (connector) DO UPDATE SET
		   base_url = EXCLUDED.base_url,
		   api_key = CASE WHEN EXCLUDED.api_key = '' THEN threat_intel_config.api_key ELSE EXCLUDED.api_key END,
		   enabled = EXCLUDED.enabled,
		   insecure_tls = EXCLUDED.insecure_tls,
		   updated_at = NOW()`,
		conn, body.BaseURL, body.APIKey, body.Enabled, body.InsecureTLS,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]any{"status": "ok"}
	if h.scheduler != nil {
		sources, lerr := connector.LoadSourcesFromDB(r.Context(), h.db, nil, nil)
		if lerr == nil {
			h.scheduler.Reconfigure(sources)
			// Reconfigure only auto-syncs the very first time it starts the
			// scheduler from cold (0 -> N sources); every later save just
			// updates the source list silently otherwise. Without this, a
			// second/third connector saved after the first one is already
			// running would never get its first fetch until the next
			// periodic poll (default 24h) or a manual Sync Now click --
			// TriggerSync is idempotent/non-blocking, so this is always
			// safe to call.
			h.scheduler.TriggerSync()
		} else {
			// Previously silent: the config save above still succeeded, but
			// the live scheduler never picked up the change, with no signal
			// to the operator that anything was wrong. Log it and surface a
			// warning so a config save that "succeeds" but doesn't actually
			// take effect isn't invisible.
			log.Printf("[threat-intel] reconfigure %s: load sources from db failed: %v", conn, lerr)
			resp["warning"] = "config saved, but the live connector could not be reloaded — it may not take effect until the next scheduled sync or a server restart"
		}
		if activitySources, aerr := connector.LoadActivitySourcesFromDB(r.Context(), h.db); aerr == nil {
			h.scheduler.ReconfigureActivitySources(activitySources)
		} else {
			log.Printf("[threat-intel] reconfigure %s: load activity sources from db failed: %v", conn, aerr)
		}
	}
	if conn == "otx" {
		var otxKey string
		var otxEnabled bool
		if qerr := h.db.QueryRow(r.Context(),
			`SELECT api_key, enabled FROM threat_intel_config WHERE connector='otx'`,
		).Scan(&otxKey, &otxEnabled); qerr == nil && otxEnabled && otxKey != "" {
			if provider, perr := ioc.NewProvider(ioc.Config{Provider: "otx", APIKey: otxKey}); perr == nil {
				h.setIOCProvider(provider)
			}
		} else {
			h.setIOCProvider(nil)
		}
	}

	h.auditLog(r, "connector.config.update", conn, map[string]any{"baseUrl": body.BaseURL, "enabled": body.Enabled}, "ok")
	respond(w, resp)
}

// DELETE /api/threat-intel/{connector}/config — Admin. Removes the stored
// config entirely (base URL + API key), returning the connector to
// "configured: false" -- unlike Enabled=false via PUT, which stops syncing
// but leaves the credentials in place. Reconfigures the live scheduler
// immediately, same as PutThreatIntelConfig, so removal takes effect
// without a restart.
func (h *Handler) DeleteThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(), `DELETE FROM threat_intel_config WHERE connector = $1`, conn); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]any{"status": "ok"}
	if h.scheduler != nil {
		sources, lerr := connector.LoadSourcesFromDB(r.Context(), h.db, nil, nil)
		if lerr == nil {
			h.scheduler.Reconfigure(sources)
		} else {
			log.Printf("[threat-intel] reconfigure after delete %s: load sources from db failed: %v", conn, lerr)
			resp["warning"] = "config removed, but the live connector could not be reloaded — it may keep syncing until the next scheduled sync or a server restart"
		}
		if activitySources, aerr := connector.LoadActivitySourcesFromDB(r.Context(), h.db); aerr == nil {
			h.scheduler.ReconfigureActivitySources(activitySources)
		} else {
			log.Printf("[threat-intel] reconfigure after delete %s: load activity sources from db failed: %v", conn, aerr)
		}
	}
	if conn == "otx" {
		h.setIOCProvider(nil)
	}

	h.auditLog(r, "connector.config.delete", conn, nil, "ok")
	respond(w, resp)
}

// POST /api/threat-intel/{connector}/config/test — Admin. Validates
// connectivity/credentials before the operator flips enabled=true,
// mirroring TestOpenAEVConfig's existing precedent.
func (h *Handler) TestThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	conn := chi.URLParam(r, "connector")
	if !validConnectors[conn] {
		jsonError(w, "unknown connector — must be misp, opencti, or otx", http.StatusBadRequest)
		return
	}
	var body struct {
		BaseURL     string `json:"baseUrl"`
		APIKey      string `json:"apiKey"`
		InsecureTLS bool   `json:"insecureTls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if conn == "otx" {
		// OTX is an ActivitySource, not a Source -- FetchActivity reports
		// activity signals, not curated actors. actorCount here means
		// "distinct actors this connectivity check found activity for",
		// same rough meaning as the misp/opencti branch below.
		signals, err := connector.NewOTXSource(body.APIKey).FetchActivity()
		if err != nil {
			respond(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		respond(w, map[string]any{"ok": true, "actorCount": len(signals)})
		return
	}
	var src connector.Source
	switch conn {
	case "misp":
		src = connector.NewMISPClient(body.BaseURL, body.APIKey, nil, nil, body.InsecureTLS)
	case "opencti":
		src = connector.NewOpenCTIClient(body.BaseURL, body.APIKey, nil)
	}
	actors, err := src.Fetch()
	if err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true, "actorCount": len(actors)})
}
