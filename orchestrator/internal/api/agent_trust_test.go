package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	trustTestTrustedHash   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	trustTestUntrustedHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func trustTestManifest(t *testing.T) *integrity.Manifest {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "BINARIES.sha256")
	content := trustTestTrustedHash + "  test-binary\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}
	return integrity.LoadManifest(path)
}

func heartbeatBodyWithHash(agentID, hash string) []byte {
	b, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "h", "status": "idle", "binaryHash": hash})
	return b
}

func enrollBodyWithHash(agentID, hash string) []byte {
	b, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "h", "binaryHash": hash})
	return b
}

func TestAgentTrust_FullMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		manifest := trustTestManifest(t)

		type manifestCase struct {
			name    string
			m       *integrity.Manifest
			hash    string
			trusted bool
		}
		manifestCases := []manifestCase{
			{"no-manifest-loaded", nil, trustTestTrustedHash, false},
			{"trusted-hash", manifest, trustTestTrustedHash, true},
			{"untrusted-hash", manifest, trustTestUntrustedHash, false},
		}
		priorStates := []string{"active", "quarantined", "retired"}

		for _, mc := range manifestCases {
			for _, prior := range priorStates {
				t.Run(mc.name+"/prior="+prior, func(t *testing.T) {
					h := New(pool, ws.NewHub(), nil, "")
					if mc.m != nil {
						h = h.WithManifest(mc.m)
					}
					agentID := "agent-trust-" + mc.name + "-" + prior

					enrollRec := httptest.NewRecorder()
					h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
					if enrollRec.Code != http.StatusOK {
						t.Fatalf("seed enroll: status = %d", enrollRec.Code)
					}
					if _, err := pool.Exec(context.Background(), `UPDATE agents SET state=$1 WHERE agent_id=$2`, prior, agentID); err != nil {
						t.Fatalf("set prior state: %v", err)
					}

					hbRec := httptest.NewRecorder()
					h.Heartbeat(hbRec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBodyWithHash(agentID, mc.hash))))
					if hbRec.Code != http.StatusOK {
						t.Fatalf("heartbeat: status = %d, body = %s", hbRec.Code, hbRec.Body.String())
					}

					var gotTrusted bool
					var gotState string
					if err := pool.QueryRow(context.Background(), `SELECT binary_trusted, state FROM agents WHERE agent_id=$1`, agentID).Scan(&gotTrusted, &gotState); err != nil {
						t.Fatalf("read: %v", err)
					}
					if gotTrusted != mc.trusted {
						t.Fatalf("binary_trusted = %v, want %v", gotTrusted, mc.trusted)
					}

					wantState := prior
					if prior == "active" && mc.m != nil && !mc.trusted {
						wantState = "quarantined" // only active->quarantined auto-transitions
					}
					if gotState != wantState {
						t.Fatalf("state = %q, want %q (prior=%s trusted=%v manifestLoaded=%v)", gotState, wantState, prior, mc.trusted, mc.m != nil)
					}
				})
			}
		}
	})
}

func TestAgentTrust_RatchetSequence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		manifest := trustTestManifest(t)
		h := New(pool, ws.NewHub(), nil, "").WithManifest(manifest)
		agentID := "agent-trust-ratchet"

		enrollRec := httptest.NewRecorder()
		h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if enrollRec.Code != http.StatusOK {
			t.Fatalf("enroll: status = %d", enrollRec.Code)
		}

		beat := func(hash string) string {
			rec := httptest.NewRecorder()
			h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBodyWithHash(agentID, hash))))
			if rec.Code != http.StatusOK {
				t.Fatalf("heartbeat: status = %d", rec.Code)
			}
			var state string
			if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&state); err != nil {
				t.Fatalf("read state: %v", err)
			}
			return state
		}

		if s := beat(trustTestTrustedHash); s != "active" {
			t.Fatalf("after trusted heartbeat: state = %q, want active", s)
		}
		if s := beat(trustTestUntrustedHash); s != "quarantined" {
			t.Fatalf("after untrusted heartbeat: state = %q, want quarantined", s)
		}
		if s := beat(trustTestTrustedHash); s != "quarantined" {
			t.Fatalf("after trusted heartbeat post-quarantine: state = %q, want quarantined (no auto-restore)", s)
		}

		stateBody, _ := json.Marshal(map[string]string{"state": "active"})
		stateReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(stateBody)), "agentId", agentID)
		stateRec := httptest.NewRecorder()
		h.SetAgentState(stateRec, stateReq)
		if stateRec.Code != http.StatusOK {
			t.Fatalf("admin restore: status = %d", stateRec.Code)
		}

		if s := beat(trustTestTrustedHash); s != "active" {
			t.Fatalf("after admin restore + trusted heartbeat: state = %q, want active", s)
		}
	})
}

func TestEnrollAgent_TrustedAndUntrustedHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		manifest := trustTestManifest(t)
		h := New(pool, ws.NewHub(), nil, "").WithManifest(manifest)

		trustedID := "agent-enroll-trusted"
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBodyWithHash(trustedID, trustTestTrustedHash))))
		if rec.Code != http.StatusOK {
			t.Fatalf("enroll trusted: status = %d", rec.Code)
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["trusted"] != true {
			t.Fatalf("enroll response trusted = %v, want true", resp["trusted"])
		}

		untrustedID := "agent-enroll-untrusted"
		rec2 := httptest.NewRecorder()
		h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBodyWithHash(untrustedID, trustTestUntrustedHash))))
		if rec2.Code != http.StatusOK {
			t.Fatalf("enroll untrusted: status = %d", rec2.Code)
		}
		var resp2 map[string]any
		_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
		if resp2["trusted"] != false {
			t.Fatalf("enroll response trusted = %v, want false", resp2["trusted"])
		}
		// EnrollAgent itself never quarantines on an untrusted hash — only
		// Heartbeat's post-enroll check does. Enroll always leaves state
		// active (or preserves quarantined/retired per the CASE clause).
		var state string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, untrustedID).Scan(&state); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if state != "active" {
			t.Fatalf("state after untrusted enroll = %q, want active (enroll doesn't auto-quarantine, only heartbeat does)", state)
		}
	})
}
