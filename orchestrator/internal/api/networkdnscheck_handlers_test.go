package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkdns"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// startTestDNSServer spins up a real local UDP DNS server bound to an
// ephemeral loopback port, always answering with rcode -- mirrors
// networkdiscovery_handlers_test.go's own real-local-listener pattern
// (an ephemeral net.Listen'd TCP port there; an ephemeral dns.Server
// here) rather than pointing at an arbitrary unreachable IP, which
// would make the test's timing depend on the test host's network
// stack instead of being fast and deterministic.
func startTestDNSServer(t *testing.T, rcode int) (host string, port int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = rcode
		_ = w.WriteMsg(resp)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	return addr.IP.String(), addr.Port
}

func validDNSCheckBody(host string, port int) map[string]any {
	return map[string]any{
		"checks": []map[string]any{
			{"checkType": "open-resolver", "target": map[string]any{"host": host, "port": port}, "queryDomain": "example.test."},
		},
	}
}

func TestTriggerDNSSecurityCheckRun_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "dnscheck-op-ot", "pw12345678", string(auth.RoleAnalyst), true)
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
			"checks":           []map[string]any{{"checkType": "open-resolver", "target": map[string]any{"host": "10.0.2.5", "port": 53}, "queryDomain": "example.com"}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerDNSSecurityCheckRun_DNSSECCheckWithNoTarget_NeverGated
// pins Spec §6's own carve-out: a dnssec-type check carries no IP
// target at all (enforced by existing validation), so it has nothing
// to resolve to a zone and must never be gated even when
// topologyImportId/otSafetyImportId are both supplied.
func TestTriggerDNSSecurityCheckRun_DNSSECCheckWithNoTarget_NeverGated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "dnscheck-op-dnssec", "pw12345678", string(auth.RoleAnalyst), true)
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
			"checks":           []map[string]any{{"checkType": "dnssec", "queryDomain": "example.com"}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- a dnssec check has no IP target and must never be gated", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerDNSSecurityCheckRun_ValidChecksPersist(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startTestDNSServer(t, dns.RcodeRefused)
		b, _ := json.Marshal(validDNSCheckBody(host, port))
		userID := seedUser(t, pool, "dns-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
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

func TestTriggerDNSSecurityCheckRun_EmptyChecksRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		body := map[string]any{"checks": []map[string]any{}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "dns-op-empty", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerDNSSecurityCheckRun_UnconfiguredVantagePointReturns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret) // no vantage point configured
		// Rejected before any probe is attempted, so the target need not
		// resolve to anything real -- the 503 fires on the Configured()
		// check alone.
		b, _ := json.Marshal(validDNSCheckBody("10.0.1.5", 53))
		userID := seedUser(t, pool, "dns-op-novp", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// dnssecCheckBody builds a dnssec-check request with no target --
// DNSSEC validation resolves the chain itself starting from the root
// trust anchor, so a target has no meaning for this check type.
func dnssecCheckBody(queryDomain string) map[string]any {
	return map[string]any{
		"checks": []map[string]any{
			{"checkType": "dnssec", "queryDomain": queryDomain},
		},
	}
}

func TestTriggerDNSSecurityCheckRun_DNSSECCheckPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		b, _ := json.Marshal(dnssecCheckBody("example-test."))
		userID := seedUser(t, pool, "dns-op-dnssec", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
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

		getReq := authedRequest(t, http.MethodGet, "/api/dns-security-checks/"+resp.RunID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", resp.RunID)
		getRec := callAuthed(h.GetDNSSecurityCheckRun, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
		var getResp struct {
			Results []networkdns.DNSCheckResult `json:"results"`
		}
		if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(getResp.Results) != 1 || getResp.Results[0].CheckType != networkdns.CheckDNSSEC {
			t.Fatalf("got %+v, want one dnssec result", getResp.Results)
		}
		if getResp.Results[0].DNSSEC == nil {
			t.Fatal("DNSSEC must be populated for a persisted dnssec check result")
		}
	})
}

// TestTriggerDNSSecurityCheckRun_DNSSECWithTargetRejected pins spec
// §4.2's explicit requirement: a CheckDNSSEC request carrying a
// non-zero Target is rejected rather than silently ignored, so a
// caller can never mistake it for having had any effect.
func TestTriggerDNSSecurityCheckRun_DNSSECWithTargetRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		body := map[string]any{
			"checks": []map[string]any{
				{"checkType": "dnssec", "queryDomain": "example-test.", "target": map[string]any{"host": "10.0.1.5", "port": 53}},
			},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "dns-op-dnssec-target", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- a target on a dnssec check must be rejected, never silently ignored", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetDNSSecurityCheckRun_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		host, port := startTestDNSServer(t, dns.RcodeRefused)
		b, _ := json.Marshal(validDNSCheckBody(host, port))
		userID := seedUser(t, pool, "dns-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		triggerReq := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		triggerRec := callAuthed(h.TriggerDNSSecurityCheckRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}
		var created struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode trigger: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/dns-security-checks", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListDNSSecurityCheckRuns, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/dns-security-checks/"+created.RunID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.RunID)
		getRec := callAuthed(h.GetDNSSecurityCheckRun, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
		var getResp struct {
			Results []networkdns.DNSCheckResult `json:"results"`
		}
		if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
			t.Fatalf("decode get: %v", err)
		}
		if len(getResp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(getResp.Results))
		}
	})
}
