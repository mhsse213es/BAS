package api

import (
	"encoding/json"
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
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO attackpath_collections (agent_id, hostname, source, collected_at, payload, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (agent_id) DO UPDATE
		   SET hostname=EXCLUDED.hostname, source=EXCLUDED.source,
		       collected_at=EXCLUDED.collected_at, payload=EXCLUDED.payload, updated_at=NOW()`,
		c.AgentID, c.Hostname, c.Source, c.CollectedAt, payload); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{
		"agentId": c.AgentID, "nodes": len(c.Nodes), "edges": len(c.Edges), "source": c.Source,
	})
}
