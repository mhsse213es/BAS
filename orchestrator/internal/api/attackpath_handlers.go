package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)

// SubmitAttackPathCollection ingests one agent's attack-path recon payload
// (observed nodes + relationship/reachability edges) and stores it as the
// agent's latest collection. The server rebuilds and analyzes the fleet graph
// at report time — the agent never computes anything.
//
// Agent-authed. Idempotent: UPSERT on agent_id, so re-delivery replaces the
// agent's prior collection (matching the at-least-once pipeline elsewhere).
// POST /api/attackpath/collect
func (h *Handler) SubmitAttackPathCollection(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	// Decode into a raw map first so we can extract jobId without touching
	// the Collection struct (which is shared with the attackpath package).
	var raw map[string]json.RawMessage
	body := json.NewDecoder(r.Body)
	if err := body.Decode(&raw); err != nil {
		jsonError(w, "invalid attack-path collection payload", http.StatusBadRequest)
		return
	}
	var c attackpath.Collection
	// Re-encode and decode into typed struct for existing logic.
	if fullRaw, err := json.Marshal(raw); err == nil {
		json.Unmarshal(fullRaw, &c)
	}
	var jobID string
	if jb, ok := raw["jobId"]; ok {
		json.Unmarshal(jb, &jobID)
	}

	if c.AgentID == "" {
		jsonError(w, "agentId is required", http.StatusBadRequest)
		return
	}
	if c.Source == "" {
		c.Source = "agent"
	}
	if c.CollectedAt.IsZero() {
		c.CollectedAt = time.Now().UTC()
	}

	payload, err := json.Marshal(c)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.storeAttackPathCollection(r, c, payload); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Duration is measured from started_at (first execution heartbeat), not ack_at,
	// so we capture execution time rather than delivery+queue+execution time.
	var durationMs int64
	if jobID != "" {
		var startedAt *time.Time
		h.db.QueryRow(r.Context(),
			`SELECT started_at FROM attackpath_jobs WHERE id=$1`, jobID).Scan(&startedAt)
		if startedAt != nil {
			durationMs = time.Since(*startedAt).Milliseconds()
		}
	}

	// Record lightweight metadata in history (never overwrites the live graph).
	sharpHound := c.Source == "sharphound"
	h.db.Exec(r.Context(),
		`INSERT INTO attackpath_collection_history
		 (agent_id, hostname, source, collected_at, node_count, edge_count, sharphound, duration_ms, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'completed')`,
		c.AgentID, c.Hostname, c.Source, c.CollectedAt,
		len(c.Nodes), len(c.Edges), sharpHound, durationMs)

	// Mark the job completed with execution metrics.
	metrics := APJobMetrics{
		DurationMs:  durationMs,
		NodeCount:   len(c.Nodes),
		EdgeCount:   len(c.Edges),
		TargetCount: len(c.Nodes), // approximation; actual target list is in job payload
	}
	h.CompleteAPJob(r.Context(), c.AgentID, jobID, metrics)

	// Notify all browser sessions so the UI can advance its status timeline.
	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgAttackPathCollected,
		AgentID: c.AgentID,
		Data: mustMarshal(map[string]any{
			"hostname":    c.Hostname,
			"nodes":       len(c.Nodes),
			"edges":       len(c.Edges),
			"source":      c.Source,
			"collectedAt": c.CollectedAt,
			"durationMs":  durationMs,
			"jobId":       jobID,
		}),
	})
	respond(w, map[string]any{
		"agentId": c.AgentID, "nodes": len(c.Nodes), "edges": len(c.Edges), "source": c.Source,
	})
}

// storeAttackPathCollection upserts a collection keyed by (agent_id, source) so
// an agent's reachability payload (source=agent) and its SharpHound payload
// (source=sharphound) coexist instead of overwriting each other.
func (h *Handler) storeAttackPathCollection(r *http.Request, c attackpath.Collection, payload []byte) error {
	_, err := h.db.Exec(r.Context(),
		`INSERT INTO attackpath_collections (agent_id, hostname, source, collected_at, payload, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (agent_id, source) DO UPDATE
		   SET hostname=EXCLUDED.hostname,
		       collected_at=EXCLUDED.collected_at, payload=EXCLUDED.payload, updated_at=NOW()`,
		c.AgentID, c.Hostname, c.Source, c.CollectedAt, payload)
	return err
}

// loadAttackPathCollections reads every stored agent collection.
func (h *Handler) loadAttackPathCollections(r *http.Request) []attackpath.Collection {
	rows, err := h.db.Query(r.Context(), `SELECT payload FROM attackpath_collections`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var cols []attackpath.Collection
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c attackpath.Collection
		if json.Unmarshal(raw, &c) == nil {
			cols = append(cols, c)
		}
	}
	return cols
}

// loadAssetTags reads every operator asset tag.
func (h *Handler) loadAssetTags(r *http.Request) []attackpath.AssetTag {
	rows, err := h.db.Query(r.Context(),
		`SELECT host_key, label, crown_jewel, segment, high_value FROM attackpath_asset_tags`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue) == nil {
			tags = append(tags, t)
		}
	}
	return tags
}

// GetAttackPathSummary builds the fleet attack-path graph from every stored
// collection (with operator asset tags overlaid) and returns the analyzed
// Summary for the dashboard. Read-only (Viewer+). Returns {collected:false}
// when nothing has been collected yet.
// GET /api/attackpath/summary
func (h *Handler) GetAttackPathSummary(w http.ResponseWriter, r *http.Request) {
	cols := h.loadAttackPathCollections(r)
	if len(cols) == 0 {
		respond(w, map[string]any{"collected": false})
		return
	}
	s := attackpath.BuildAndAnalyze(cols, h.loadAssetTags(r))

	// Build per-agent metadata from the live collections table so the UI can
	// show "Current Graph" details (hostname, counts, timestamp) without a
	// separate API call.
	type agentMeta struct {
		AgentID     string    `json:"agentId"`
		Hostname    string    `json:"hostname"`
		CollectedAt time.Time `json:"collectedAt"`
		NodeCount   int       `json:"nodeCount"`
		EdgeCount   int       `json:"edgeCount"`
	}
	var agentMetas []agentMeta
	rows, _ := h.db.Query(r.Context(),
		`SELECT agent_id, hostname, collected_at
		   FROM attackpath_collections WHERE source='agent'
		  ORDER BY collected_at DESC`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var m agentMeta
			rows.Scan(&m.AgentID, &m.Hostname, &m.CollectedAt)
			agentMetas = append(agentMetas, m)
		}
	}
	// Annotate with node/edge counts from parsed collections.
	for i, m := range agentMetas {
		for _, c := range cols {
			if c.AgentID == m.AgentID {
				agentMetas[i].NodeCount = len(c.Nodes)
				agentMetas[i].EdgeCount = len(c.Edges)
				break
			}
		}
	}

	var latest time.Time
	for _, c := range cols {
		if c.CollectedAt.After(latest) {
			latest = c.CollectedAt
		}
	}
	respond(w, map[string]any{
		"collected":        true,
		"agents":           len(cols),
		"summary":          s,
		"latestCollectedAt": latest,
		"agentMeta":        agentMetas,
	})
}

// GetAttackPathHistory returns recent collection run metadata (no graph payloads).
// GET /api/attackpath/history?agentId=X&limit=N  (Viewer+)
func (h *Handler) GetAttackPathHistory(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	limit := 20

	type historyRow struct {
		ID          string    `json:"id"`
		AgentID     string    `json:"agentId"`
		Hostname    string    `json:"hostname"`
		CollectedAt time.Time `json:"collectedAt"`
		NodeCount   int       `json:"nodeCount"`
		EdgeCount   int       `json:"edgeCount"`
		SharpHound  bool      `json:"sharpHound"`
		DurationMs  int64     `json:"durationMs"`
		Status      string    `json:"status"`
		ErrorMsg    string    `json:"errorMsg,omitempty"`
	}

	var dbRows interface {
		Next() bool
		Scan(...any) error
		Close()
	}
	var err error
	if agentID != "" {
		dbRows, err = h.db.Query(r.Context(),
			`SELECT id, agent_id, hostname, collected_at, node_count, edge_count,
			        sharphound, duration_ms, status, error_msg
			   FROM attackpath_collection_history WHERE agent_id=$1
			  ORDER BY collected_at DESC LIMIT $2`, agentID, limit)
	} else {
		dbRows, err = h.db.Query(r.Context(),
			`SELECT id, agent_id, hostname, collected_at, node_count, edge_count,
			        sharphound, duration_ms, status, error_msg
			   FROM attackpath_collection_history
			  ORDER BY collected_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dbRows.Close()

	var out []historyRow
	for dbRows.Next() {
		var row historyRow
		if dbRows.Scan(&row.ID, &row.AgentID, &row.Hostname, &row.CollectedAt,
			&row.NodeCount, &row.EdgeCount, &row.SharpHound, &row.DurationMs,
			&row.Status, &row.ErrorMsg) != nil {
			continue
		}
		out = append(out, row)
	}
	if out == nil {
		out = []historyRow{}
	}
	respond(w, out)
}

// GetAttackPathAssets returns the host inventory — every host in the current
// fleet graph with its effective tags — so the operator can assign crown-jewel,
// segment, and tier-0 metadata. Read-only (Viewer+).
// GET /api/attackpath/assets
func (h *Handler) GetAttackPathAssets(w http.ResponseWriter, r *http.Request) {
	cols := h.loadAttackPathCollections(r)
	g := attackpath.BuildGraph(cols...)
	// Apply tags so the inventory reflects current assignments, including tags
	// for hosts not (yet) present in any collection.
	tags := h.loadAssetTags(r)
	inv := g.HostInventory()
	// Merge in tags whose host has not been collected yet so the operator still
	// sees and can edit them.
	seen := map[string]bool{}
	for _, a := range inv {
		seen[attackpath.NormalizeHostKey(a.HostKey)] = true
	}
	for _, t := range tags {
		k := attackpath.NormalizeHostKey(t.HostKey)
		if !seen[k] {
			inv = append(inv, t)
		}
	}
	// Overlay stored tag values onto the inventory rows (HostInventory reflects
	// graph state; stored tags are authoritative for the editable fields).
	idx := map[string]attackpath.AssetTag{}
	for _, t := range tags {
		idx[attackpath.NormalizeHostKey(t.HostKey)] = t
	}
	for i := range inv {
		if t, ok := idx[attackpath.NormalizeHostKey(inv[i].HostKey)]; ok {
			inv[i].CrownJewel = t.CrownJewel
			inv[i].Segment = t.Segment
			inv[i].HighValue = t.HighValue
		}
	}
	respond(w, map[string]any{"assets": inv})
}

// SetAttackPathAsset upserts (or clears) one host's operator tag. Sending all
// fields empty/false deletes the tag. Analyst+.
// POST /api/attackpath/assets   {hostKey, label, crownJewel, segment, highValue}
func (h *Handler) SetAttackPathAsset(w http.ResponseWriter, r *http.Request) {
	var t attackpath.AssetTag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		jsonError(w, "invalid asset tag payload", http.StatusBadRequest)
		return
	}
	key := attackpath.NormalizeHostKey(t.HostKey)
	if key == "" {
		jsonError(w, "hostKey is required", http.StatusBadRequest)
		return
	}
	// An empty tag clears the assignment.
	if t.CrownJewel == "" && t.Segment == "" && !t.HighValue {
		if _, err := h.db.Exec(r.Context(), `DELETE FROM attackpath_asset_tags WHERE host_key=$1`, key); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.auditLog(r, "attackpath.asset_tag", key, map[string]any{"action": "clear"}, "ok")
		respond(w, map[string]any{"hostKey": key, "cleared": true})
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO attackpath_asset_tags (host_key, label, crown_jewel, segment, high_value, updated_at)
		 VALUES ($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT (host_key) DO UPDATE
		   SET label=EXCLUDED.label, crown_jewel=EXCLUDED.crown_jewel,
		       segment=EXCLUDED.segment, high_value=EXCLUDED.high_value, updated_at=NOW()`,
		key, t.Label, t.CrownJewel, t.Segment, t.HighValue); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "attackpath.asset_tag", key, map[string]any{"crownJewel": t.CrownJewel, "segment": t.Segment, "highValue": t.HighValue, "label": t.Label}, "ok")
	respond(w, map[string]any{"hostKey": key, "crownJewel": t.CrownJewel, "segment": t.Segment, "highValue": t.HighValue})
}

// buildCollectCmd assembles the command_attackpath_collect WS payload, loading
// the SharpHound binary from BAS_SHARPHOUND_PATH when a SharpHound run is
// requested. Returns the payload and whether the binary was delivered. Shared by
// the operator dispatch handler and the periodic scheduler.
func buildCollectCmd(targets []string, segment string, runSharpHound bool, sharpHoundArgs string) (map[string]any, bool) {
	cmd := map[string]any{
		"collectId":      fmt.Sprintf("ap-%d", time.Now().UnixMilli()),
		"targets":        targets,
		"segment":        segment,
		"runSharpHound":  runSharpHound,
		"sharpHoundArgs": sharpHoundArgs,
	}
	loaded := false
	if runSharpHound {
		if p := os.Getenv("BAS_SHARPHOUND_PATH"); p != "" {
			if raw, err := os.ReadFile(p); err == nil {
				cmd["sharpHoundPayload"] = map[string]string{
					"name":    "SharpHound.exe",
					"content": base64.StdEncoding.EncodeToString(raw),
				}
				loaded = true
			}
		}
	}
	return cmd, loaded
}

// DispatchAttackPathCollect tells a connected agent to run an attack-path
// collection: probe an explicit target allowlist and (optionally, where domain-
// joined) run SharpHound. Operator-authed (Analyst+). Recon only — never
// scanning beyond the provided targets.
//
// The SharpHound binary is delivered in the command when BAS_SHARPHOUND_PATH
// points at a readable file; otherwise the agent runs reachability + local
// identity only and skips SharpHound.
// POST /api/attackpath/collect/{agentId}
func (h *Handler) DispatchAttackPathCollect(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Targets       []string `json:"targets"`
		Segment       string   `json:"segment"`
		RunSharpHound bool     `json:"runSharpHound"`
		SharpHoundArgs string  `json:"sharpHoundArgs"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	cmd, sharpHoundLoaded := buildCollectCmd(body.Targets, body.Segment, body.RunSharpHound, body.SharpHoundArgs)

	// Check whether a previous collection exists for this agent so the UI can
	// inform the operator it will be replaced — not lost, just superseded.
	var prevCollectedAt *time.Time
	h.db.QueryRow(r.Context(),
		`SELECT collected_at FROM attackpath_collections WHERE agent_id=$1 AND source='agent'`,
		agentID).Scan(&prevCollectedAt)

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type: models.MsgCommandAttackPathCollect, AgentID: agentID, Data: cmd,
	})
	if !sent {
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}
	h.auditLog(r, "attackpath.collect", agentID, map[string]any{"targets": len(body.Targets), "sharpHound": body.RunSharpHound}, "ok")
	respond(w, map[string]any{
		"agentId": agentID, "targets": len(body.Targets),
		"sharpHound": body.RunSharpHound, "sharpHoundDelivered": sharpHoundLoaded,
		"previousCollectionAt": prevCollectedAt,
	})
}

// attackPathSchedule is the wire type for the schedule singleton.
type attackPathSchedule struct {
	Enabled         bool      `json:"enabled"`
	IntervalMinutes int       `json:"intervalMinutes"`
	Targets         []string  `json:"targets"`
	Segment         string    `json:"segment"`
	RunSharpHound   bool      `json:"runSharpHound"`
	LastRunAt       *time.Time `json:"lastRunAt,omitempty"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

// GetAttackPathSchedule returns the current periodic-collection config.
// Viewer+. Returns defaults when not yet configured.
// GET /api/attackpath/schedule
func (h *Handler) GetAttackPathSchedule(w http.ResponseWriter, r *http.Request) {
	var s attackPathSchedule
	var targetsRaw []byte
	err := h.db.QueryRow(r.Context(),
		`SELECT enabled, interval_minutes, targets, segment, run_sharphound, last_run_at, updated_at
		 FROM attackpath_schedule WHERE id = 1`).
		Scan(&s.Enabled, &s.IntervalMinutes, &targetsRaw, &s.Segment, &s.RunSharpHound, &s.LastRunAt, &s.UpdatedAt)
	if err != nil {
		// Not yet configured — return safe defaults.
		respond(w, attackPathSchedule{Enabled: false, IntervalMinutes: 1440, Targets: []string{}})
		return
	}
	if err := json.Unmarshal(targetsRaw, &s.Targets); err != nil {
		s.Targets = []string{}
	}
	respond(w, s)
}

// SetAttackPathSchedule upserts the periodic-collection singleton config.
// Admin only.
// POST /api/attackpath/schedule
func (h *Handler) SetAttackPathSchedule(w http.ResponseWriter, r *http.Request) {
	var s attackPathSchedule
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		jsonError(w, "invalid schedule payload", http.StatusBadRequest)
		return
	}
	if s.IntervalMinutes <= 0 {
		s.IntervalMinutes = 1440
	}
	targetsRaw, err := json.Marshal(s.Targets)
	if err != nil {
		targetsRaw = []byte("[]")
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO attackpath_schedule (id, enabled, interval_minutes, targets, segment, run_sharphound, updated_at)
		 VALUES (1, $1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (id) DO UPDATE
		   SET enabled=$1, interval_minutes=$2, targets=$3, segment=$4, run_sharphound=$5, updated_at=NOW()`,
		s.Enabled, s.IntervalMinutes, targetsRaw, s.Segment, s.RunSharpHound); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "attackpath.schedule_update", "", map[string]any{"enabled": s.Enabled, "intervalMinutes": s.IntervalMinutes}, "ok")
	respond(w, map[string]any{"ok": true, "enabled": s.Enabled, "intervalMinutes": s.IntervalMinutes})
}

// SubmitAttackPathSharpHound ingests a RAW SharpHound collection zip from a
// domain-joined agent, parses it server-side into a normalized Collection, and
// stores it. The agent never parses SharpHound output — it only runs the
// collector and uploads the bytes. Agent-authed; idempotent (upsert on
// agent_id + sharphound source).
// POST /api/attackpath/sharphound?agentId=...&hostname=...   (body: zip bytes)
func (h *Handler) SubmitAttackPathSharpHound(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	agentID := r.URL.Query().Get("agentId")
	if agentID == "" {
		jsonError(w, "agentId query param is required", http.StatusBadRequest)
		return
	}
	hostname := r.URL.Query().Get("hostname")
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<20)) // 64 MiB cap
	if err != nil || len(raw) == 0 {
		jsonError(w, "empty or unreadable SharpHound upload", http.StatusBadRequest)
		return
	}
	c, err := attackpath.ParseSharpHoundZip(agentID, hostname, raw)
	if err != nil {
		jsonError(w, "invalid SharpHound zip: "+err.Error(), http.StatusBadRequest)
		return
	}
	payload, err := json.Marshal(c)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.storeAttackPathCollection(r, c, payload); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"agentId": agentID, "nodes": len(c.Nodes), "edges": len(c.Edges), "source": "sharphound",
	})
}

// GetAttackPathSubnet derives the /24 subnet from the selected agent's known IP
// and returns the full list of addresses as suggested probe targets. The UI
// pre-fills the targets textarea with this list; the operator reviews and edits
// before dispatching — nothing is dispatched automatically.
func (h *Handler) GetAttackPathSubnet(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}

	var ipStr string
	h.db.QueryRow(r.Context(),
		`SELECT ip_address FROM agents WHERE agent_id = $1`, agentID).Scan(&ipStr)

	ipStr = strings.TrimSpace(ipStr)
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		// No IP recorded for this agent yet (unlikely but possible before first heartbeat).
		respond(w, map[string]any{"agentIp": ipStr, "subnet": "", "targets": []string{}})
		return
	}

	subnet := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
	targets := make([]string, 0, 253)
	for i := 1; i <= 254; i++ {
		candidate := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], i)
		if candidate != ipStr {
			targets = append(targets, candidate)
		}
	}

	respond(w, map[string]any{
		"agentIp": ipStr,
		"subnet":  subnet,
		"targets": targets,
	})
}
