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
		var resp struct{ RunID string `json:"runId"` }
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
