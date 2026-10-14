package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func testVantagePoint() networkgraph.VantagePoint {
	return networkgraph.VantagePoint{ID: "vp-test-1", NetworkPosition: "test-harness-network"}
}

func networkDiscoveryReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "netdiscovery-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

// TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone_NoAuth_Rejected
// and its sibling tests below pin Task 6's wiring of
// otsafety.CheckActiveTestAuthorization into the discovery-run
// handler -- the exhaustive edge-case matrix itself is Task 2's.
func TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "discovery-op-ot", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"targets":          []map[string]any{{"host": "10.0.2.5", "port": 502}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- a target in a declared sensitive zone with no authorization must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone_Authorized_Permitted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "discovery-op-ot-auth", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"targets":          []map[string]any{{"host": "10.0.2.5", "port": 502}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
			"activeTestAuthorization": map[string]any{
				"authorized": true,
				"signOff":    "approved by J.Singh, CHG-1234",
			},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- a valid authorization must permit the run", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerNetworkDiscoveryRun_OmittingSafetyFields_BehaviorUnchanged
// pins this plan's Global Constraint for this handler specifically.
func TestTriggerNetworkDiscoveryRun_OmittingSafetyFields_BehaviorUnchanged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "discovery-op-plain", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": 1}}}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- omitting the new safety fields must behave exactly as before this task", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_ObservedAndBlockedTargets(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		closedLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		closedPort := closedLn.Addr().(*net.TCPAddr).Port
		closedLn.Close()

		body := map[string]any{"targets": []map[string]any{
			{"host": "127.0.0.1", "port": openPort},
			{"host": "127.0.0.1", "port": closedPort},
		}}
		req := networkDiscoveryReq(t, pool, body)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RunID    string `json:"runId"`
			Status   string `json:"status"`
			Findings []struct {
				Target struct{ Port int } `json:"target"`
				State  string             `json:"state"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.RunID == "" {
			t.Fatal("want non-empty runId")
		}
		if resp.Status != "completed" {
			t.Fatalf("status = %q, want completed", resp.Status)
		}
		var observedSeen, blockedSeen bool
		for _, f := range resp.Findings {
			if f.Target.Port == openPort && f.State == "observed" {
				observedSeen = true
			}
			if f.Target.Port == closedPort && f.State == "blocked" {
				blockedSeen = true
			}
		}
		if !observedSeen || !blockedSeen {
			t.Fatalf("findings = %+v, want one observed (port %d) and one blocked (port %d)", resp.Findings, openPort, closedPort)
		}
	})
}

func TestTriggerNetworkDiscoveryRun_EmptyTargetsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{}})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_TooManyTargetsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		targets := make([]map[string]any, networkgraph.MaxTargetsPerRun+1)
		for i := range targets {
			targets[i] = map[string]any{"host": "127.0.0.1", "port": 9}
		}
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": targets})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_InvalidPortRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": 0}}})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_TimeoutAboveMaxRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		body := map[string]any{
			"targets":            []map[string]any{{"host": "127.0.0.1", "port": 9}},
			"timeoutPerTargetMs": 10000,
		}
		req := networkDiscoveryReq(t, pool, body)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_UnconfiguredVantagePointReturns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no WithNetworkVantagePoint call
		req := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": 9}}})
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerNetworkDiscoveryRun_ObservationInsertFailureMarksRunFailed
// forces a real, deterministic Postgres write failure on the
// observations insert (a target label containing an embedded NUL byte,
// which text columns reject outright) while the run row insert still
// succeeds -- reproducing the finding from the final review: without a
// fix, the run row is left claiming "completed" with zero backing
// observations. The label never reaches DialerProbe (only Host/Port are
// dialed), so RunDiscovery itself completes normally; only the DB write
// fails.
func TestTriggerNetworkDiscoveryRun_ObservationInsertFailureMarksRunFailed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "netdiscovery-op-insertfail", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{"targets": []map[string]any{
			{"host": "127.0.0.1", "port": 9, "label": "bad\x00label"},
		}}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		runs, err := db.ListNetworkDiscoveryRuns(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list runs: %v", err)
		}
		var found *db.NetworkDiscoveryRun
		for _, r := range runs {
			if r.RequestedBy == userID {
				found = r
			}
		}
		if found == nil {
			t.Fatal("expected the run row to have been persisted despite the observation-insert failure")
		}
		if found.Status != "failed" {
			t.Fatalf("Status = %q, want failed -- a run must never be left claiming completed/partial with zero backing observations", found.Status)
		}
	})
}

func TestTriggerNetworkDiscoveryRun_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "netdiscovery-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"targets":[{"host":"` + strings.Repeat("x", maxNetworkDiscoveryRequestBytes+1) + `"}]}`)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "too large") {
			t.Fatalf("expected a body-too-large error, got: %s", rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_RequestedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(testVantagePoint())
		userID := seedUser(t, pool, "netdiscovery-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{
			"targets":     []map[string]any{{"host": "127.0.0.1", "port": 9}},
			"requestedBy": "spoofed-user",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}

		run, err := db.GetNetworkDiscoveryRun(context.Background(), pool, resp.RunID)
		if err != nil {
			t.Fatalf("lookup run: %v", err)
		}
		if run.RequestedBy != userID {
			t.Fatalf("RequestedBy = %q, want %q (the authenticated caller, not the spoofed body value)", run.RequestedBy, userID)
		}
	})
}
