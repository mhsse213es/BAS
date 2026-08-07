package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// AgentGroupNode is one node in the tree returned by GET /api/agent-groups.
type AgentGroupNode struct {
	ID               int64            `json:"id"`
	Name             string           `json:"name"`
	ParentID         *int64           `json:"parentId,omitempty"`
	DirectAgentCount int              `json:"directAgentCount"`
	TotalAgentCount  int              `json:"totalAgentCount"` // direct + all descendants
	Children         []AgentGroupNode `json:"children,omitempty"`
}

// GET /api/agent-groups — the full tree, nested, with per-node agent counts.
// Admin-only (CanManageAgentGroups, enforced by the route).
func (h *Handler) GetAgentGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT id, name, parent_id FROM agent_groups ORDER BY name`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type flat struct {
		ID       int64
		Name     string
		ParentID *int64
	}
	var flats []flat
	for rows.Next() {
		var f flat
		if err := rows.Scan(&f.ID, &f.Name, &f.ParentID); err != nil {
			rows.Close()
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		flats = append(flats, f)
	}
	rows.Close()

	directCounts := map[int64]int{}
	countRows, err := h.db.Query(r.Context(),
		`SELECT group_id, COUNT(*) FROM agents WHERE group_id IS NOT NULL GROUP BY group_id`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for countRows.Next() {
		var gid int64
		var cnt int
		if err := countRows.Scan(&gid, &cnt); err != nil {
			countRows.Close()
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		directCounts[gid] = cnt
	}
	countRows.Close()

	childrenOf := map[int64][]flat{}
	var roots []flat
	for _, f := range flats {
		if f.ParentID == nil {
			roots = append(roots, f)
		} else {
			childrenOf[*f.ParentID] = append(childrenOf[*f.ParentID], f)
		}
	}

	var build func(f flat) AgentGroupNode
	build = func(f flat) AgentGroupNode {
		node := AgentGroupNode{ID: f.ID, Name: f.Name, ParentID: f.ParentID, DirectAgentCount: directCounts[f.ID]}
		total := node.DirectAgentCount
		for _, c := range childrenOf[f.ID] {
			child := build(c)
			total += child.TotalAgentCount
			node.Children = append(node.Children, child)
		}
		node.TotalAgentCount = total
		return node
	}

	out := make([]AgentGroupNode, 0, len(roots))
	for _, root := range roots {
		out = append(out, build(root))
	}
	respond(w, out)
}

// POST /api/agent-groups — create. Body: {name, parentId?}.
func (h *Handler) CreateAgentGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		ParentID *int64 `json:"parentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	var id int64
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO agent_groups (name, parent_id) VALUES ($1, $2) RETURNING id`,
		body.Name, body.ParentID).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondStatus(w, map[string]any{"id": id, "name": body.Name, "parentId": body.ParentID}, http.StatusCreated)
}

// PATCH /api/agent-groups/{id} — rename and/or move. Body: {name?, parentId?}.
func (h *Handler) UpdateAgentGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var body struct {
		Name     *string `json:"name"`
		ParentID *int64  `json:"parentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if body.ParentID != nil {
		if *body.ParentID == id {
			jsonError(w, "a group cannot be its own parent", http.StatusBadRequest)
			return
		}
		// Walk upward from the proposed new parent; if we reach id, this move
		// would create a cycle (id would become an ancestor of itself).
		cur := *body.ParentID
		for {
			var next *int64
			err := h.db.QueryRow(r.Context(), `SELECT parent_id FROM agent_groups WHERE id = $1`, cur).Scan(&next)
			if err != nil {
				jsonError(w, "parent group not found", http.StatusBadRequest)
				return
			}
			if next == nil {
				break
			}
			if *next == id {
				jsonError(w, "cannot move a group under its own descendant", http.StatusBadRequest)
				return
			}
			cur = *next
		}
	}

	if body.Name != nil {
		if _, err := h.db.Exec(r.Context(), `UPDATE agent_groups SET name = $1 WHERE id = $2`, *body.Name, id); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if body.ParentID != nil {
		if _, err := h.db.Exec(r.Context(), `UPDATE agent_groups SET parent_id = $1 WHERE id = $2`, *body.ParentID, id); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	respond(w, map[string]any{"id": id})
}

// DELETE /api/agent-groups/{id} — blocked (409) unless empty of both direct
// agents and subgroups.
func (h *Handler) DeleteAgentGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var agentCount, subgroupCount int
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM agents WHERE group_id = $1`, id).Scan(&agentCount); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM agent_groups WHERE parent_id = $1`, id).Scan(&subgroupCount); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if agentCount > 0 || subgroupCount > 0 {
		jsonError(w, "group has "+strconv.Itoa(agentCount)+" agent(s) and "+strconv.Itoa(subgroupCount)+" subgroup(s) — move or remove them first", http.StatusConflict)
		return
	}
	if _, err := h.db.Exec(r.Context(), `DELETE FROM agent_groups WHERE id = $1`, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /api/agents/{agentId}/group — assign/move a single agent. Body: {groupId: number|null}.
func (h *Handler) SetAgentGroup(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		GroupID *int64 `json:"groupId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(), `UPDATE agents SET group_id = $1 WHERE agent_id = $2`, body.GroupID, agentID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"agentId": agentID, "groupId": body.GroupID})
}
