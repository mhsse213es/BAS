package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/pki"
	"github.com/audspect/bas/internal/ws"
)

func rotationHandler(t *testing.T, pool *pgxpool.Pool, hub *ws.Hub) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	return New(pool, hub, nil, "").WithPKI(ca).WithPKIDir(dir), dir
}

func rotationRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/ca-rotation/distribute", h.DistributeCARoot)
	r.Get("/api/ca-rotation/status", h.CARotationStatus)
	return r
}

func nextFingerprint(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "next-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	s := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(s[:])
}

func TestCARotationDistribute_OnlyWhilePrepared(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, dir := rotationHandler(t, pool, ws.NewHub())
		rec := httptest.NewRecorder()
		rotationRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ca-rotation/distribute", nil))
		if rec.Code != http.StatusConflict {
			t.Errorf("distribute with no rotation = %d, want 409", rec.Code)
		}
		if _, err := pki.StartRotation(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := pki.PromoteRotation(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		rotationRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ca-rotation/distribute", nil))
		if rec.Code != http.StatusConflict {
			t.Errorf("distribute after promote = %d, want 409", rec.Code)
		}
	})
}

func TestCARotationDistribute_SendsTheRootAndCrossCertToEveryConnectedAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		hub := ws.NewHub()
		h, dir := rotationHandler(t, pool, hub)
		if _, err := pki.StartRotation(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{revAgentA, revAgentB, "abc123deadbeef03"} {
			seedAgentRow(t, pool, id)
		}
		a := startFakeAgent(t, hub, revAgentA)
		b := startFakeAgent(t, hub, revAgentB) // abc123deadbeef03 stays offline

		rec := httptest.NewRecorder()
		rotationRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ca-rotation/distribute", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("distribute = %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Sent         int      `json:"sent"`
			NotConnected []string `json:"notConnected"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Sent != 2 || len(out.NotConnected) != 1 || out.NotConnected[0] != "abc123deadbeef03" {
			t.Errorf("sent=%d notConnected=%v, want 2 sent and the offline agent reported", out.Sent, out.NotConnected)
		}
		wantRoot, _ := os.ReadFile(filepath.Join(dir, "next-ca-cert.pem"))
		wantCross, _ := os.ReadFile(filepath.Join(dir, "next-ca-cross.pem"))
		for _, f := range []*fakeAgent{a, b} {
			env := f.WaitForMessage(t, 2*time.Second)
			if env.Type != models.MsgCommandTrustCA {
				t.Fatalf("message type = %q, want %q", env.Type, models.MsgCommandTrustCA)
			}
			var d struct {
				RootPEM  string `json:"rootPem"`
				CrossPEM string `json:"crossPem"`
			}
			json.Unmarshal(env.Data, &d)
			if d.RootPEM != string(wantRoot) || d.CrossPEM != string(wantCross) {
				t.Error("the command must carry exactly the prepared root and its cross-certificate")
			}
		}
		if n := auditActionCount(t, pool, "ca_rotation.distribute", "ca_rotation", 1); n != 1 {
			t.Errorf("audit events = %d, want 1", n)
		}
	})
}

func TestHeartbeat_StoresTheTrustedRootFingerprints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "").WithAgentSecret("shh")
		seedAgentRow(t, pool, revAgentA)
		body, _ := json.Marshal(map[string]any{"agentId": revAgentA, "hostname": "h", "trustedRootFingerprints": []string{"aa", "bb"}})
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "shh")
		rec := httptest.NewRecorder()
		h.Heartbeat(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat = %d: %s", rec.Code, rec.Body.String())
		}
		var got string
		if err := pool.QueryRow(context.Background(), `SELECT trusted_root_fps::text FROM agents WHERE agent_id=$1`, revAgentA).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != `["aa", "bb"]` {
			t.Errorf("trusted_root_fps = %s", got)
		}
	})
}

func TestCARotationStatus_ReadyOnlyWhenEveryActiveAgentHasTheNewRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, dir := rotationHandler(t, pool, ws.NewHub())
		if _, err := pki.StartRotation(dir, time.Now()); err != nil {
			t.Fatal(err)
		}
		fp := nextFingerprint(t, dir)
		for _, id := range []string{revAgentA, revAgentB} {
			seedAgentRow(t, pool, id)
		}
		status := func() (state string, ready bool, have, total int, pending []string) {
			rec := httptest.NewRecorder()
			rotationRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ca-rotation/status", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			var out struct {
				State   string   `json:"state"`
				Ready   bool     `json:"readyToPromote"`
				Have    int      `json:"agentsWithNewRoot"`
				Total   int      `json:"agentsTotal"`
				Pending []string `json:"agentsPending"`
			}
			json.Unmarshal(rec.Body.Bytes(), &out)
			return out.State, out.Ready, out.Have, out.Total, out.Pending
		}
		if st, ready, have, total, _ := status(); st != "prepared" || ready || have != 0 || total != 2 {
			t.Errorf("state=%s ready=%v have=%d total=%d, want prepared, not ready, 0 of 2", st, ready, have, total)
		}
		pool.Exec(context.Background(), `UPDATE agents SET trusted_root_fps=$2::jsonb WHERE agent_id=$1`, revAgentA, `["`+fp+`"]`)
		if _, ready, have, _, pending := status(); ready || have != 1 || len(pending) != 1 || pending[0] != revAgentB {
			t.Errorf("ready=%v have=%d pending=%v, want one agent still pending", ready, have, pending)
		}
		pool.Exec(context.Background(), `UPDATE agents SET trusted_root_fps=$2::jsonb WHERE agent_id=$1`, revAgentB, `["`+fp+`"]`)
		if _, ready, have, _, _ := status(); !ready || have != 2 {
			t.Errorf("ready=%v have=%d, want ready with both agents", ready, have)
		}
		// A revoked agent can no longer connect and must not block the switch.
		seedAgentRow(t, pool, "abc123deadbeef09")
		pool.Exec(context.Background(), `UPDATE agents SET state='revoked' WHERE agent_id=$1`, "abc123deadbeef09")
		if _, ready, _, total, _ := status(); !ready || total != 2 {
			t.Errorf("ready=%v total=%d, a revoked agent must not count", ready, total)
		}
	})
}
