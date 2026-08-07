package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// createAgentGroup POSTs a new group and returns its id, for use as seed
// data by the tests below.
func createAgentGroup(t *testing.T, h *Handler, name string, parentID *int64) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "parentId": parentID})
	rec := httptest.NewRecorder()
	h.CreateAgentGroup(rec, httptest.NewRequest(http.MethodPost, "/api/agent-groups", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group %q: status = %d, body = %s", name, rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return created.ID
}

// seedBareAgent inserts a minimal agent row directly, matching the pattern
// used by TestGetAgents_EmptyOrderingAndNullableFields in agent_lifecycle_test.go.
func seedBareAgent(t *testing.T, pool *pgxpool.Pool, agentID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, last_update) VALUES ($1, $2, NOW())`, agentID, "host-"+agentID); err != nil {
		t.Fatalf("seed agent %s: %v", agentID, err)
	}
}

// A group with no agents and no subgroups deletes cleanly.
func TestDeleteAgentGroup_EmptyGroupSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		groupID := createAgentGroup(t, h, "Temp Group", nil)

		delReq := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/agent-groups/x", nil), "id", itoa(groupID))
		delRec := httptest.NewRecorder()
		h.DeleteAgentGroup(delRec, delReq)
		if delRec.Code != http.StatusNoContent {
			t.Errorf("delete empty group: status = %d, want 204, body = %s", delRec.Code, delRec.Body.String())
		}
	})
}

// A group with agents in it cannot be deleted -- 409, not a silent cascade.
func TestDeleteAgentGroup_NonEmptyGroupBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		groupID := createAgentGroup(t, h, "Finance", nil)

		agentID := "agent-groups-nonempty-1"
		seedBareAgent(t, pool, agentID)

		assignBody, _ := json.Marshal(map[string]*int64{"groupId": &groupID})
		assignReq := withURLParam(httptest.NewRequest(http.MethodPatch, "/api/agents/x/group", bytes.NewReader(assignBody)), "agentId", agentID)
		assignRec := httptest.NewRecorder()
		h.SetAgentGroup(assignRec, assignReq)
		if assignRec.Code != http.StatusOK {
			t.Fatalf("assign agent to group: status = %d, body = %s", assignRec.Code, assignRec.Body.String())
		}

		delReq := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/agent-groups/x", nil), "id", itoa(groupID))
		delRec := httptest.NewRecorder()
		h.DeleteAgentGroup(delRec, delReq)
		if delRec.Code != http.StatusConflict {
			t.Errorf("delete non-empty group: status = %d, want 409", delRec.Code)
		}
	})
}

// Moving a group under its own descendant must be rejected, not silently applied.
func TestPatchAgentGroup_CircularMoveRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		parentID := createAgentGroup(t, h, "Parent", nil)
		childID := createAgentGroup(t, h, "Child", &parentID)

		moveBody, _ := json.Marshal(map[string]int64{"parentId": childID})
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/api/agent-groups/x", bytes.NewReader(moveBody)), "id", itoa(parentID))
		rec := httptest.NewRecorder()
		h.UpdateAgentGroup(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("circular move: status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// GET /api/agents?groupId=X must include agents in X's subgroups, not just
// direct members.
func TestGetAgents_GroupIDFilterIncludesDescendants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		parentID := createAgentGroup(t, h, "Finance", nil)
		childID := createAgentGroup(t, h, "Servers", &parentID)

		agentID := "agent-groups-descendant-1"
		seedBareAgent(t, pool, agentID)
		assignBody, _ := json.Marshal(map[string]*int64{"groupId": &childID})
		assignReq := withURLParam(httptest.NewRequest(http.MethodPatch, "/api/agents/x/group", bytes.NewReader(assignBody)), "agentId", agentID)
		h.SetAgentGroup(httptest.NewRecorder(), assignReq)

		req := httptest.NewRequest(http.MethodGet, "/api/agents?groupId="+itoa(parentID), nil)
		rec := httptest.NewRecorder()
		h.GetAgents(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("get agents by group: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte(agentID)) {
			t.Errorf("agent %s (in child group Servers) missing from parent group Finance's filtered list: %s", agentID, rec.Body.String())
		}

		// A sibling agent with no group assignment must not leak into the filter.
		otherID := "agent-groups-descendant-unrelated"
		seedBareAgent(t, pool, otherID)
		rec2 := httptest.NewRecorder()
		h.GetAgents(rec2, httptest.NewRequest(http.MethodGet, "/api/agents?groupId="+itoa(parentID), nil))
		if bytes.Contains(rec2.Body.Bytes(), []byte(otherID)) {
			t.Errorf("ungrouped agent %s leaked into group filter: %s", otherID, rec2.Body.String())
		}
	})
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
