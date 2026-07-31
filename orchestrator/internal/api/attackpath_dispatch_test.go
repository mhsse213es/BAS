package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBuildCollectCmd_NoSharpHound(t *testing.T) {
	cmd, loaded := buildCollectCmd([]string{"10.0.0.1"}, "prod", false, "")
	if loaded {
		t.Fatal("loaded = true, want false when runSharpHound is false")
	}
	if _, ok := cmd["sharpHoundPayload"]; ok {
		t.Fatal("cmd should not carry a sharpHoundPayload when runSharpHound is false")
	}
	if cmd["segment"] != "prod" {
		t.Errorf("segment = %v, want prod", cmd["segment"])
	}
}

func TestBuildCollectCmd_SharpHoundRequestedButPathUnset(t *testing.T) {
	t.Setenv("BAS_SHARPHOUND_PATH", "")
	cmd, loaded := buildCollectCmd(nil, "", true, "")
	if loaded {
		t.Fatal("loaded = true, want false when BAS_SHARPHOUND_PATH is unset")
	}
	if _, ok := cmd["sharpHoundPayload"]; ok {
		t.Fatal("cmd should not carry a sharpHoundPayload when the binary path is unset")
	}
}

// TestBuildCollectCmd_SharpHoundLoadedFromPath pins that a readable
// BAS_SHARPHOUND_PATH gets base64-embedded into the command payload.
func TestBuildCollectCmd_SharpHoundLoadedFromPath(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "SharpHound.exe")
	content := []byte("fake-binary-content")
	if err := os.WriteFile(binPath, content, 0o644); err != nil {
		t.Fatalf("write fixture binary: %v", err)
	}
	t.Setenv("BAS_SHARPHOUND_PATH", binPath)

	cmd, loaded := buildCollectCmd([]string{"10.0.0.1"}, "", true, "--stealth")
	if !loaded {
		t.Fatal("loaded = false, want true when BAS_SHARPHOUND_PATH points at a readable file")
	}
	payload, ok := cmd["sharpHoundPayload"].(map[string]string)
	if !ok {
		t.Fatalf("sharpHoundPayload type = %T, want map[string]string", cmd["sharpHoundPayload"])
	}
	decoded, err := base64.StdEncoding.DecodeString(payload["content"])
	if err != nil || string(decoded) != string(content) {
		t.Fatalf("decoded payload = %q, want %q (err=%v)", decoded, content, err)
	}
	if cmd["sharpHoundArgs"] != "--stealth" {
		t.Errorf("sharpHoundArgs = %v, want --stealth", cmd["sharpHoundArgs"])
	}
}

func dispatchCollectReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/attackpath/collect/x", bytes.NewReader(b))
}

func TestDispatchAttackPathCollect_AgentNotConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		req := withURLParam(dispatchCollectReq(map[string]any{"targets": []string{"10.0.0.1"}}), "agentId", "offline-agent")
		h.DispatchAttackPathCollect(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

// TestDispatchAttackPathCollect_Success drives the real WS delivery path
// through a connected fake agent and confirms the actual command received,
// not just the DB/response side effects.
func TestDispatchAttackPathCollect_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		agent := startFakeAgent(t, h.hub, "dispatch-collect-agent")
		defer agent.Disconnect(t)

		rec := httptest.NewRecorder()
		req := withURLParam(dispatchCollectReq(map[string]any{
			"targets": []string{"10.0.0.1", "10.0.0.2"}, "segment": "prod",
		}), "agentId", "dispatch-collect-agent")
		h.DispatchAttackPathCollect(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := agent.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandAttackPathCollect {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgCommandAttackPathCollect)
		}
		var data map[string]any
		json.Unmarshal(env.Data, &data)
		targets, _ := data["targets"].([]any)
		if len(targets) != 2 {
			t.Fatalf("dispatched targets = %+v, want 2", data["targets"])
		}
	})
}

func TestGetAttackPathSchedule_Defaults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAttackPathSchedule(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out attackPathSchedule
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Enabled || out.IntervalMinutes != 1440 {
			t.Fatalf("out = %+v, want disabled default with 1440min interval", out)
		}
	})
}

// TestSetAttackPathSchedule_UpsertAndIntervalFloor pins that a non-positive
// interval is floored to the 1440-minute (daily) default, and that a
// follow-up GET reflects the stored config.
func TestSetAttackPathSchedule_UpsertAndIntervalFloor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		body, _ := json.Marshal(attackPathSchedule{Enabled: true, IntervalMinutes: 0, Targets: []string{"10.0.0.1"}, Segment: "dmz"})
		setRec := httptest.NewRecorder()
		h.SetAttackPathSchedule(setRec, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
		if setRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", setRec.Code, setRec.Body.String())
		}
		var setOut map[string]any
		json.Unmarshal(setRec.Body.Bytes(), &setOut)
		if setOut["intervalMinutes"] != float64(1440) {
			t.Errorf("intervalMinutes = %v, want 1440 (floored from 0)", setOut["intervalMinutes"])
		}

		getRec := httptest.NewRecorder()
		h.GetAttackPathSchedule(getRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var getOut attackPathSchedule
		json.Unmarshal(getRec.Body.Bytes(), &getOut)
		if !getOut.Enabled || getOut.Segment != "dmz" || len(getOut.Targets) != 1 {
			t.Fatalf("getOut = %+v, want enabled dmz with 1 target", getOut)
		}
	})
}

func TestSetAttackPathSchedule_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte(`{"enabled":`)))
		rec := httptest.NewRecorder()
		h.SetAttackPathSchedule(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestDispatchAttackPathCollect_WritesRequestLog pins that a successful
// dispatch persists the requested targets/runSharpHound flag for later
// coverage reconciliation (Task 4).
func TestDispatchAttackPathCollect_WritesRequestLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		agent := startFakeAgent(t, h.hub, "reqlog-agent")
		defer agent.Disconnect(t)

		rec := httptest.NewRecorder()
		req := withURLParam(dispatchCollectReq(map[string]any{
			"targets": []string{"10.0.0.1", "10.0.0.2"}, "runSharpHound": true,
		}), "agentId", "reqlog-agent")
		h.DispatchAttackPathCollect(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var targetsRaw []byte
		var runSharpHound bool
		if err := pool.QueryRow(context.Background(),
			`SELECT targets, run_sharphound FROM attackpath_collection_requests WHERE agent_id=$1`,
			"reqlog-agent").Scan(&targetsRaw, &runSharpHound); err != nil {
			t.Fatalf("read request log: %v", err)
		}
		var targets []string
		json.Unmarshal(targetsRaw, &targets)
		if len(targets) != 2 || !runSharpHound {
			t.Fatalf("targets=%v runSharpHound=%v, want 2 targets and runSharpHound=true", targets, runSharpHound)
		}
	})
}
