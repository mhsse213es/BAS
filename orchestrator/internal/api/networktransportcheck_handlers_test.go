package api

import (
	"bytes"
	"context"
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

// TestTriggerTransportSecurityCheckRun_TopologyIDExplicit_OTSafetyIDOmitted_AutoResolvesAndGates
// replaces the old "must be supplied together" rejection: omitting
// otSafetyImportId must auto-resolve the latest ot safety import and
// still gate a target in a declared sensitive zone.
func TestTriggerTransportSecurityCheckRun_TopologyIDExplicit_OTSafetyIDOmitted_AutoResolvesAndGates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "transportcheck-op-partial", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		_ = createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})

		body := map[string]any{
			"checks":           []map[string]any{{"checkType": "cleartext", "target": map[string]any{"host": "10.0.2.5", "port": 23}}},
			"topologyImportId": topoID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- omitting otSafetyImportId must auto-resolve the latest ot safety import and still gate", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerTransportSecurityCheckRun_BothOmitted_ImportsExist_AutoResolvesAndGates
// is the regression test for the fixed gap.
func TestTriggerTransportSecurityCheckRun_BothOmitted_ImportsExist_AutoResolvesAndGates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "transportcheck-op-autoresolve", "pw12345678", string(auth.RoleAnalyst), true)
		_ = createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		_ = createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})

		body := map[string]any{
			"checks": []map[string]any{{"checkType": "cleartext", "target": map[string]any{"host": "10.0.2.5", "port": 23}}},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- omitting both fields must not bypass gating once topology+ot-safety data has been declared", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerTransportSecurityCheckRun_ExplicitHistoricalIDs_PinSpecificImport_NotUpgradedToLatest
// proves an explicit id always wins over auto-resolution.
func TestTriggerTransportSecurityCheckRun_ExplicitHistoricalIDs_PinSpecificImport_NotUpgradedToLatest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "transportcheck-op-pin", "pw12345678", string(auth.RoleAnalyst), true)

		olderTopoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "benign", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		olderSafetyID := createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})
		_ = createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		_ = createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})

		body := map[string]any{
			"checks":           []map[string]any{{"checkType": "cleartext", "target": map[string]any{"host": "10.0.2.5", "port": 23}}},
			"topologyImportId": olderTopoID,
			"otSafetyImportId": olderSafetyID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- explicit ids must pin the older pair, not be upgraded to the newer, more-restrictive one", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerTransportSecurityCheckRun_OmittingSafetyFields_NoImportsExist_FailsOpen
// pins the only legitimate skip: nothing has ever been imported.
func TestTriggerTransportSecurityCheckRun_OmittingSafetyFields_NoImportsExist_FailsOpen(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transportcheck-op-plain", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- omitting the safety fields with no imports ever declared must fail open", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerTransportSecurityCheckRun_SafetyGatingLookupFailure_FailsClosed
// proves a genuine lookup failure during auto-resolution fails closed.
func TestTriggerTransportSecurityCheckRun_SafetyGatingLookupFailure_FailsClosed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transportcheck-op-lookupfail", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req = req.WithContext(ctx)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code < 500 {
			t.Fatalf("status = %d, body = %s, want a 5xx -- a lookup failure must fail closed", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerTransportSecurityCheckRun_TargetOutsideDeclaredScope_Rejected
// is the regression test for the RBAC-only target authorization gap.
func TestTriggerTransportSecurityCheckRun_TargetOutsideDeclaredScope_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		_ = createTestTargetScopeImport(t, h, pool, map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.1.0/24"}},
			"limitations":       []string{"x"},
		})
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transportcheck-op-outofscope", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- a target outside the declared scope must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerTransportSecurityCheckRun_TargetInsideDeclaredScope_Permitted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		_ = createTestTargetScopeImport(t, h, pool, map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "127.0.0.0/8"}},
			"limitations":       []string{"x"},
		})
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transportcheck-op-inscope", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- a target covered by the declared scope must be permitted", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerTransportSecurityCheckRun_NoScopeEverDeclared_FailsOpen(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startRefusingPort(t)
		b, _ := json.Marshal(transportCheckBody(host, port))
		userID := seedUser(t, pool, "transportcheck-op-noscope", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- with no target-scope import ever declared, gating must fail open", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerTransportSecurityCheckRun_TargetInSensitiveZone_Authorized_Permitted
// closes a final-review gap: the plan's own Task 6 prose calls for a
// permit-with-authorization smoke test on this handler, matching the
// one that already exists for TriggerNetworkDiscoveryRun.
func TestTriggerTransportSecurityCheckRun_TargetInSensitiveZone_Authorized_Permitted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "transportcheck-op-ot-auth", "pw12345678", string(auth.RoleAnalyst), true)
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
			"activeTestAuthorization": map[string]any{
				"authorized": true,
				"signOff":    "approved by J.Singh, CHG-1234",
			},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- a valid authorization must permit the run", rec.Code, rec.Body.String())
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
