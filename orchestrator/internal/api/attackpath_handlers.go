package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/attackpath"
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
	var c attackpath.Collection
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		jsonError(w, "invalid attack-path collection payload", http.StatusBadRequest)
		return
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
