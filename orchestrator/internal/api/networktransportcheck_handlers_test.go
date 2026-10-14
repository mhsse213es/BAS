package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networktransport"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// startRefusingPort returns host/port of an address nothing is
// listening on -- real, fast, deterministic (Secure for cleartext,
// Unknown for cert), mirroring Phase 1's own closedPort pattern.
func startRefusingPort(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	return addr.IP.String(), addr.Port
}

func transportCheckBody(host string, port int) map[string]any {
	return map[string]any{
		"checks": []map[string]any{
			{"checkType": "cleartext", "target": map[string]any{"host": host, "port": port}},
		},
	}
}

func TestTriggerTransportSecurityCheckRun_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "transportcheck-op-ot", "pw12345678", string(auth.RoleAnalyst), true)
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
			"checks":           []map[string]any{{"checkType": "cleartext", "target": map[string]any{"host": "10.0.2.5", "port": 23}}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerTransportSecurityCheckRun_ValidChecksPersist(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transport-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.RunID == "" {
			t.Fatal("want non-empty runId")
		}
	})
}

// TestTriggerTransportSecurityCheckRun_UnrecognizedCheckTypeRejected
// pins the fix for a real bug: an unrecognized checkType (a typo, or a
// stale client sending a since-removed type) must be rejected at the
// API boundary, not silently accepted and routed to the wrong probe.
func TestTriggerTransportSecurityCheckRun_UnrecognizedCheckTypeRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		body := map[string]any{
			"checks": []map[string]any{
				{"checkType": "certt", "target": map[string]any{"host": "10.0.1.5", "port": 443}},
			},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "transport-op-badtype", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unrecognized checkType must be rejected, never silently routed to a probe", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerTransportSecurityCheckRun_EmptyChecksRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		body := map[string]any{"checks": []map[string]any{}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "transport-op-empty", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerTransportSecurityCheckRun_UnconfiguredVantagePointReturns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no vantage point configured
		b, _ := json.Marshal(transportCheckBody("10.0.1.5", 80))
		userID := seedUser(t, pool, "transport-op-novp", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetTransportSecurityCheckRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transport-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		triggerReq := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		triggerRec := callAuthed(h.TriggerTransportSecurityCheckRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var created struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode trigger: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/transport-security-checks", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListTransportSecurityCheckRuns, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/transport-security-checks/"+created.RunID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.RunID)
		getRec := callAuthed(h.GetTransportSecurityCheckRun, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
		var getResp struct {
			Results []db.TransportSecurityCheckResult `json:"results"`
		}
		if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(getResp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(getResp.Results))
		}
		if getResp.Results[0].CheckType != networktransport.CheckCleartext {
			t.Fatalf("CheckType = %q, want %q -- a caller must be able to tell which check a result belongs to", getResp.Results[0].CheckType, networktransport.CheckCleartext)
		}
	})
}
