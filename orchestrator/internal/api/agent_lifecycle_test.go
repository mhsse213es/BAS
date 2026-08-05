package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func enrollBody(agentID string, extra map[string]any) []byte {
	m := map[string]any{"agentId": agentID, "hostname": "host-" + agentID}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func heartbeatBody(agentID string) []byte {
	b, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "host-" + agentID, "status": "idle"})
	return b
}

func TestEnrollAgent_MalformedAndMissingID(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	malformed := httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	h.EnrollAgent(rec, malformed)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: status = %d, want 400", rec.Code)
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody("", nil)))
	rec2 := httptest.NewRecorder()
	h.EnrollAgent(rec2, missing)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing agentId: status = %d, want 400", rec2.Code)
	}
}

func TestEnrollAgent_ReEnrollPreservesEnrolledAtAndResetsPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-reenroll-1"

		rec1 := httptest.NewRecorder()
		h.EnrollAgent(rec1, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first enroll: status = %d, body = %s", rec1.Code, rec1.Body.String())
		}
		var firstEnrolledAt time.Time
		if err := pool.QueryRow(context.Background(), `SELECT enrolled_at FROM agents WHERE agent_id=$1`, agentID).Scan(&firstEnrolledAt); err != nil {
			t.Fatalf("read enrolled_at: %v", err)
		}

		// Manually diverge policy_json to prove re-enroll resets it.
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET policy_json = '{"logLevel":"debug","maxConcurrentRuns":99,"heartbeatIntervalS":5}' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("diverge policy: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
		rec2 := httptest.NewRecorder()
		h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second enroll: status = %d, body = %s", rec2.Code, rec2.Body.String())
		}

		var secondEnrolledAt time.Time
		var policyRaw string
		if err := pool.QueryRow(context.Background(), `SELECT enrolled_at, policy_json::text FROM agents WHERE agent_id=$1`, agentID).Scan(&secondEnrolledAt, &policyRaw); err != nil {
			t.Fatalf("read after re-enroll: %v", err)
		}
		if !firstEnrolledAt.Equal(secondEnrolledAt) {
			t.Fatalf("enrolled_at changed on re-enroll: %v -> %v (must stay stable)", firstEnrolledAt, secondEnrolledAt)
		}
		var policy models.PolicyBundle
		if err := json.Unmarshal([]byte(policyRaw), &policy); err != nil {
			t.Fatalf("decode policy: %v", err)
		}
		if policy.LogLevel != "info" || policy.MaxConcurrentRuns != 1 || policy.HeartbeatInterval != 30 {
			t.Fatalf("policy after re-enroll = %+v, want the hardcoded default (re-enroll resets it, characterized behavior)", policy)
		}
	})
}

func TestEnrollAgent_PreservesQuarantinedAndRetiredState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		for _, state := range []string{"quarantined", "retired"} {
			agentID := "agent-preserve-" + state
			rec := httptest.NewRecorder()
			h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
			if rec.Code != http.StatusOK {
				t.Fatalf("initial enroll (%s): status = %d", state, rec.Code)
			}
			if _, err := pool.Exec(context.Background(), `UPDATE agents SET state=$1 WHERE agent_id=$2`, state, agentID); err != nil {
				t.Fatalf("set state: %v", err)
			}

			rec2 := httptest.NewRecorder()
			h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
			if rec2.Code != http.StatusOK {
				t.Fatalf("re-enroll (%s): status = %d", state, rec2.Code)
			}
			var got string
			if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&got); err != nil {
				t.Fatalf("read state: %v", err)
			}
			if got != state {
				t.Fatalf("state after re-enroll = %q, want %q preserved", got, state)
			}
		}
	})
}

func TestEnrollAgent_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-idempotent-enroll"
		for i := 0; i < 3; i++ {
			rec := httptest.NewRecorder()
			h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
			if rec.Code != http.StatusOK {
				t.Fatalf("enroll #%d: status = %d", i, rec.Code)
			}
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id=$1`, agentID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after 3 enrolls = %d, want 1", count)
		}
	})
}

func TestHeartbeat_MalformedAndMissingID(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	malformed := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	h.Heartbeat(rec, malformed)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: status = %d, want 400", rec.Code)
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody("")))
	rec2 := httptest.NewRecorder()
	h.Heartbeat(rec2, missing)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing agentId: status = %d, want 400", rec2.Code)
	}
}

func TestHeartbeat_IdempotentAndTimestampAdvances(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-idempotent-hb"

		rec1 := httptest.NewRecorder()
		h.Heartbeat(rec1, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first heartbeat: status = %d, body = %s", rec1.Code, rec1.Body.String())
		}
		var first time.Time
		if err := pool.QueryRow(context.Background(), `SELECT last_update FROM agents WHERE agent_id=$1`, agentID).Scan(&first); err != nil {
			t.Fatalf("read first last_update: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
			if rec.Code != http.StatusOK {
				t.Fatalf("heartbeat #%d: status = %d", i, rec.Code)
			}
		}

		var count int
		var second time.Time
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*), MAX(last_update) FROM agents WHERE agent_id=$1 GROUP BY agent_id`, agentID).Scan(&count, &second); err != nil {
			t.Fatalf("read after repeats: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after 3 heartbeats = %d, want 1", count)
		}
		if !second.After(first) {
			t.Fatalf("last_update did not advance: first=%v second=%v", first, second)
		}
	})
}

func TestHeartbeat_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-concurrent-hb"

		const n = 20
		var wg sync.WaitGroup
		statuses := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rec := httptest.NewRecorder()
				h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
				statuses[i] = rec.Code
			}(i)
		}
		wg.Wait()

		for i, s := range statuses {
			if s != http.StatusOK {
				t.Errorf("goroutine %d: status = %d, want 200 (no panics/deadlocks/errors under concurrency)", i, s)
			}
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id=$1`, agentID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after concurrent heartbeats = %d, want 1", count)
		}
	})
}

func TestSetAgentState_ValidationAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-setstate-1"
		enrollRec := httptest.NewRecorder()
		h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if enrollRec.Code != http.StatusOK {
			t.Fatalf("seed enroll: status = %d", enrollRec.Code)
		}

		invalidBody, _ := json.Marshal(map[string]string{"state": "not-a-state"})
		invalidReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(invalidBody)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.SetAgentState(rec, invalidReq)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid state: status = %d, want 400", rec.Code)
		}

		unknownBody, _ := json.Marshal(map[string]string{"state": "restricted"})
		unknownReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/does-not-exist/state", bytes.NewReader(unknownBody)), "agentId", "does-not-exist")
		rec2 := httptest.NewRecorder()
		h.SetAgentState(rec2, unknownReq)
		if rec2.Code != http.StatusNotFound {
			t.Fatalf("unknown agent: status = %d, want 404", rec2.Code)
		}

		for i := 0; i < 2; i++ {
			validBody, _ := json.Marshal(map[string]string{"state": "restricted"})
			validReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(validBody)), "agentId", agentID)
			rec3 := httptest.NewRecorder()
			h.SetAgentState(rec3, validReq)
			if rec3.Code != http.StatusOK {
				t.Fatalf("valid state set #%d: status = %d", i, rec3.Code)
			}
		}
		var got string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&got); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if got != "restricted" {
			t.Fatalf("state = %q, want restricted", got)
		}
	})
}

func TestGetAgents_EmptyOrderingAndNullableFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")

		recEmpty := httptest.NewRecorder()
		h.GetAgents(recEmpty, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var empty []map[string]any
		_ = json.Unmarshal(recEmpty.Body.Bytes(), &empty)
		if empty == nil {
			t.Fatal("expected [], got null for zero agents")
		}

		// Heartbeat-only agent: never enrolled, so enrolled_at must be null.
		hbRec := httptest.NewRecorder()
		h.Heartbeat(hbRec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody("agent-hb-only"))))
		if hbRec.Code != http.StatusOK {
			t.Fatalf("seed heartbeat: status = %d", hbRec.Code)
		}

		// Two more agents with distinct, explicit last_update values to prove ordering.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update) VALUES ('agent-old','h', NOW() - interval '2 hours')`); err != nil {
			t.Fatalf("seed old: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update) VALUES ('agent-newest','h', NOW() + interval '1 hour')`); err != nil {
			t.Fatalf("seed newest: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var agents []models.Agent
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(agents) != 3 {
			t.Fatalf("got %d agents, want 3", len(agents))
		}
		if agents[0].AgentID != "agent-newest" || agents[len(agents)-1].AgentID != "agent-old" {
			t.Fatalf("ordering not descending by last_update: %v", []string{agents[0].AgentID, agents[1].AgentID, agents[2].AgentID})
		}

		var hbOnly *models.Agent
		for i := range agents {
			if agents[i].AgentID == "agent-hb-only" {
				hbOnly = &agents[i]
			}
		}
		if hbOnly == nil {
			t.Fatal("agent-hb-only missing from response")
		}
		if hbOnly.EnrolledAt != nil {
			t.Fatalf("EnrolledAt = %v, want nil for a heartbeat-only agent", hbOnly.EnrolledAt)
		}
	})
}

func TestPingAgent_DoesNotTouchDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		rec := httptest.NewRecorder()
		h.PingAgent(rec, httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatal("PingAgent must not create any agent row")
		}
	})
}

func TestAgentIdentity_EdgeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")

		whitespace := "   "
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(whitespace, nil))))
		if rec.Code != http.StatusOK {
			t.Fatalf("whitespace-only agentId: status = %d (current validation only checks == \"\")", rec.Code)
		}

		longID := strings.Repeat("x", 500)
		rec2 := httptest.NewRecorder()
		h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(longID, nil))))
		if rec2.Code != http.StatusOK {
			t.Fatalf("500-char agentId: status = %d, want 200 (no length constraint in schema)", rec2.Code)
		}

		unicodeID := "エージェント-🤖-агент"
		rec3 := httptest.NewRecorder()
		h.EnrollAgent(rec3, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(unicodeID, nil))))
		if rec3.Code != http.StatusOK {
			t.Fatalf("unicode agentId: status = %d, want 200", rec3.Code)
		}
		var gotID string
		if err := pool.QueryRow(context.Background(), `SELECT agent_id FROM agents WHERE agent_id=$1`, unicodeID).Scan(&gotID); err != nil {
			t.Fatalf("unicode agentId did not round-trip through Postgres: %v", err)
		}
		if gotID != unicodeID {
			t.Fatalf("round-tripped agentId = %q, want %q", gotID, unicodeID)
		}
	})
}

func TestAgentLifecycle_EndToEndChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-e2e-chain"

		pingRec := httptest.NewRecorder()
		h.PingAgent(pingRec, httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil))
		if pingRec.Code != http.StatusOK {
			t.Fatalf("ping: status = %d", pingRec.Code)
		}

		enrollRec := httptest.NewRecorder()
		h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if enrollRec.Code != http.StatusOK {
			t.Fatalf("enroll: status = %d, body = %s", enrollRec.Code, enrollRec.Body.String())
		}

		hbRec := httptest.NewRecorder()
		h.Heartbeat(hbRec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
		if hbRec.Code != http.StatusOK {
			t.Fatalf("heartbeat: status = %d", hbRec.Code)
		}

		listRec1 := httptest.NewRecorder()
		h.GetAgents(listRec1, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var agents1 []models.Agent
		_ = json.Unmarshal(listRec1.Body.Bytes(), &agents1)
		found := false
		for _, a := range agents1 {
			if a.AgentID == agentID {
				found = true
				if a.State != models.AgentStateActive {
					t.Fatalf("state after enroll+heartbeat = %q, want active", a.State)
				}
			}
		}
		if !found {
			t.Fatal("agent not visible in GetAgents after enroll+heartbeat")
		}

		stateBody, _ := json.Marshal(map[string]string{"state": "quarantined"})
		stateReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(stateBody)), "agentId", agentID)
		stateRec := httptest.NewRecorder()
		h.SetAgentState(stateRec, stateReq)
		if stateRec.Code != http.StatusOK {
			t.Fatalf("set state: status = %d", stateRec.Code)
		}

		hbRec2 := httptest.NewRecorder()
		h.Heartbeat(hbRec2, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
		if hbRec2.Code != http.StatusOK {
			t.Fatalf("second heartbeat: status = %d", hbRec2.Code)
		}
		var resp models.HeartbeatResponse
		if err := json.Unmarshal(hbRec2.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode heartbeat response: %v", err)
		}
		if resp.State != models.AgentStateQuarantined {
			t.Fatalf("heartbeat response state = %q, want quarantined (heartbeat's upsert never touches state on conflict)", resp.State)
		}

		listRec2 := httptest.NewRecorder()
		h.GetAgents(listRec2, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var agents2 []models.Agent
		_ = json.Unmarshal(listRec2.Body.Bytes(), &agents2)
		for _, a := range agents2 {
			if a.AgentID == agentID && a.State != models.AgentStateQuarantined {
				t.Fatalf("final GetAgents state = %q, want quarantined", a.State)
			}
		}
	})
}

func TestStopAgent_RequiresReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		body, _ := json.Marshal(map[string]string{"reason": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/agent-x/stop", bytes.NewReader(body)), "agentId", "agent-x")
		rec := httptest.NewRecorder()
		h.StopAgent(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty reason: status = %d, want 400", rec.Code)
		}
	})
}

func TestStopAgent_NotConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-stop-notconn"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/stop", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.StopAgent(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("agent not connected: status = %d, want 503", rec.Code)
		}
	})
}

func TestStopAgent_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		hub := ws.NewHub()
		h := New(pool, hub, nil, "")
		agentID := "agent-stop-ok"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))

		fake := startFakeAgent(t, hub, agentID)

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning host"})
		req := authedRequest(t, http.MethodPost, "/api/agents/"+agentID+"/stop", bytes.NewReader(body), auth.RoleAdmin, "admin-1")
		req = withURLParam(req, "agentId", agentID)
		rec := callAuthed(h.StopAgent, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("stop dispatch: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandStopAgent {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandStopAgent)
		}
		var payload struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(env.Data, &payload); err != nil || payload.Reason != "decommissioning host" {
			t.Fatalf("WS payload = %+v, err = %v, want reason=decommissioning host", payload, err)
		}

		var stoppedBy, stopReason string
		if err := pool.QueryRow(context.Background(),
			`SELECT stopped_by, stop_reason FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&stoppedBy, &stopReason); err != nil {
			t.Fatalf("read stop columns: %v", err)
		}
		if stoppedBy != "admin-1" || stopReason != "decommissioning host" {
			t.Fatalf("stopped_by=%q stop_reason=%q, want admin-1/decommissioning host", stoppedBy, stopReason)
		}
	})
}

func TestRemoveAgent_RequiresReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		body, _ := json.Marshal(map[string]string{"reason": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/agent-x/remove", bytes.NewReader(body)), "agentId", "agent-x")
		rec := httptest.NewRecorder()
		h.RemoveAgent(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty reason: status = %d, want 400", rec.Code)
		}
	})
}

func TestRemoveAgent_UnknownAgent_Returns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		body, _ := json.Marshal(map[string]string{"reason": "cleanup"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/no-such-agent/remove", bytes.NewReader(body)), "agentId", "no-such-agent")
		rec := httptest.NewRecorder()
		h.RemoveAgent(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown agent: status = %d, want 404", rec.Code)
		}
	})
}

// TestRemoveAgent_SetsStateToRetired_WithoutRequiringConnection is the key
// behavioral difference from StopAgent: it must succeed for an agent with
// no live WS connection at all -- the common case for something an admin
// wants removed from the dashboard (e.g. a decommissioned or already-dead
// endpoint), unlike StopAgent which requires reaching the live agent.
func TestRemoveAgent_SetsStateToRetired_WithoutRequiringConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-remove-offline"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		// Deliberately no startFakeAgent(...) -- the agent is not connected.

		body, _ := json.Marshal(map[string]string{"reason": "decommissioned host"})
		req := authedRequest(t, http.MethodPost, "/api/agents/"+agentID+"/remove", bytes.NewReader(body), auth.RoleAdmin, "admin-1")
		req = withURLParam(req, "agentId", agentID)
		rec := callAuthed(h.RemoveAgent, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("remove: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var state string
		if err := pool.QueryRow(context.Background(),
			`SELECT state FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if state != "retired" {
			t.Fatalf("state = %q, want retired", state)
		}
	})
}
