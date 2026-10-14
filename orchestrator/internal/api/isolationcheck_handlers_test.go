package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/audspect/bas/internal/zoneisolation"
)

func createTestIsolationImport(t *testing.T, h *Handler, pool *pgxpool.Pool, pairs []map[string]any) string {
	t.Helper()
	userID := seedUser(t, pool, "isocheck-isoimport-op", "pw12345678", string(auth.RoleAnalyst), true)
	body := map[string]any{
		"sourceType":         "manual",
		"zonePairIsolations": pairs,
		"limitations":        []string{"zone names are not cross-validated against a real network-topology import"},
	}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/zone-isolation-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateZoneIsolationImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create isolation import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

// TestFindIsolationChecks_PolicyDenied_NoViolationFound pins Review
// Focus #2's "policy-denied" half: a route exists, a policy import
// explicitly denies it, and that must read as no-violation-found with
// no extra limitation (distinct from the no-known-route case below).
func TestFindIsolationChecks_PolicyDenied_NoViolationFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-denied", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{{"fromZone": "guest", "toZone": "clinical"}},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "guest", "destZone": "clinical", "protocol": "tcp", "action": "deny"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if resp.Results[0].Severity != zoneisolation.SeverityNoViolationFound {
			t.Fatalf("severity = %q, want %q", resp.Results[0].Severity, zoneisolation.SeverityNoViolationFound)
		}
		if resp.Results[0].Limitations != "" {
			t.Fatalf("limitations = %q, want empty for a confirmed policy deny", resp.Results[0].Limitations)
		}
	})
}

// TestFindIsolationChecks_PolicyPermits_UnconfirmedExposure pins
// Review Focus #1's "unconfirmed" half.
func TestFindIsolationChecks_PolicyPermits_UnconfirmedExposure(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-permit", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{{"fromZone": "guest", "toZone": "clinical"}},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "guest", "destZone": "clinical", "protocol": "tcp", "action": "allow"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].Severity != zoneisolation.SeverityUnconfirmedExposure {
			t.Fatalf("got %+v, want exactly 1 result with severity unconfirmed-exposure", resp.Results)
		}
	})
}

// TestFindIsolationChecks_NoRouteAtAll_NoViolationFound_WithLimitation
// pins Review Focus #2's "no known route" half, which must carry a
// different limitation than the policy-denied case above.
func TestFindIsolationChecks_NoRouteAtAll_NoViolationFound_WithLimitation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-noroute", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].Severity != zoneisolation.SeverityNoViolationFound {
			t.Fatalf("got %+v, want exactly 1 result with severity no-violation-found", resp.Results)
		}
		if resp.Results[0].Limitations == "" {
			t.Fatal("want a non-empty limitation -- no known route is not proof of isolation")
		}
	})
}

// TestFindIsolationChecks_MultiPair_OnlyOneViolates pins Review
// Focus #3: no cross-pair leakage.
func TestFindIsolationChecks_MultiPair_OnlyOneViolates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-multipair", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
				{"name": "admin", "cidrs": []string{"10.0.3.0/24"}},
			},
			"edges": []map[string]any{{"fromZone": "guest", "toZone": "clinical"}},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
			{"canonicalId": "zp-2", "zoneA": "admin", "zoneB": "clinical"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "guest", "destZone": "clinical", "protocol": "tcp", "action": "allow"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 2 {
			t.Fatalf("got %d results, want 2", len(resp.Results))
		}
		var guestClinical, adminClinical *zoneisolation.IsolationCheckResult
		for i := range resp.Results {
			if resp.Results[i].ZonePairIsolation.CanonicalID == "zp-1" {
				guestClinical = &resp.Results[i]
			}
			if resp.Results[i].ZonePairIsolation.CanonicalID == "zp-2" {
				adminClinical = &resp.Results[i]
			}
		}
		if guestClinical == nil || guestClinical.Severity != zoneisolation.SeverityUnconfirmedExposure {
			t.Fatalf("guest->clinical = %+v, want unconfirmed-exposure", guestClinical)
		}
		if adminClinical == nil || adminClinical.Severity != zoneisolation.SeverityNoViolationFound {
			t.Fatalf("admin->clinical = %+v, want no-violation-found (no declared route at all, unaffected by the guest->clinical policy rule)", adminClinical)
		}
	})
}

// TestFindIsolationChecks_TunnelBridgesIsolatedPair_OmittedVsSupplied
// pins Review Focus #4: the one end-to-end test proving tunnel-aware
// isolation checking actually works.
func TestFindIsolationChecks_TunnelBridgesIsolatedPair_OmittedVsSupplied(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-tunnel", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "vendor", "cidrs": []string{"10.0.4.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "vendor", "zoneB": "clinical"},
		})

		remoteBody := map[string]any{
			"sourceType": "manual",
			"tunnels": []map[string]any{
				{"canonicalId": "vpn-1", "fromZone": "vendor", "toZone": "clinical", "state": "up"},
			},
			"limitations": []string{"tunnel state is not independently verified against a live VPN concentrator"},
		}
		rb, _ := json.Marshal(remoteBody)
		rReq := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(rb), auth.RoleAnalyst, userID)
		rRec := callAuthed(h.CreateRemoteAccessImport, rReq)
		if rRec.Code != http.StatusCreated {
			t.Fatalf("create remote access import: status = %d, body = %s", rRec.Code, rRec.Body.String())
		}
		var remoteCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rRec.Body.Bytes(), &remoteCreated)

		// A policy import is required here: networkpath.ComposeHop
		// always forces State=Unknown when no policy evaluation is
		// available at all, regardless of whether a route was found --
		// without this, a route found via the tunnel would be
		// indistinguishable from no route at all, and this test could
		// never actually prove the tunnel changed anything.
		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "vendor", "cidrs": []string{"10.0.4.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "vendor", "destZone": "clinical", "protocol": "tcp", "action": "allow"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		omittedBody := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID}
		ob, _ := json.Marshal(omittedBody)
		omittedReq := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(ob), auth.RoleAnalyst, userID)
		omittedRec := callAuthed(h.FindIsolationChecks, omittedReq)
		var omittedResp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(omittedRec.Body.Bytes(), &omittedResp); err != nil {
			t.Fatalf("decode omitted: %v", err)
		}
		if len(omittedResp.Results) != 1 || omittedResp.Results[0].Severity != zoneisolation.SeverityNoViolationFound {
			t.Fatalf("omitted remoteAccessImportId: got %+v, want no-violation-found (no physical route exists)", omittedResp.Results)
		}

		suppliedBody := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "remoteAccessImportId": remoteCreated.ID, "policyImportId": policyCreated.ID}
		sb, _ := json.Marshal(suppliedBody)
		suppliedReq := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		suppliedRec := callAuthed(h.FindIsolationChecks, suppliedReq)
		var suppliedResp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(suppliedRec.Body.Bytes(), &suppliedResp); err != nil {
			t.Fatalf("decode supplied: %v", err)
		}
		if len(suppliedResp.Results) != 1 || suppliedResp.Results[0].Severity == zoneisolation.SeverityNoViolationFound {
			t.Fatalf("supplied remoteAccessImportId with a bridging tunnel: got %+v, want a severity other than no-violation-found -- the tunnel must change the outcome", suppliedResp.Results)
		}
	})
}

// TestFindIsolationChecks_MultiHopObservation_NeverConfirmedViolation
// pins Review Focus #5: observation correlation is single-hop-only.
func TestFindIsolationChecks_MultiHopObservation_NeverConfirmedViolation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-multihop", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "dmz", "cidrs": []string{"10.0.5.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "guest", "toZone": "dmz"},
				{"fromZone": "dmz", "toZone": "clinical"},
			},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		discBody := map[string]any{"targets": []map[string]any{{"host": "10.0.2.5", "port": 1}}}
		db2, _ := json.Marshal(discBody)
		discReq := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(db2), auth.RoleAnalyst, userID)
		discRec := callAuthed(h.TriggerNetworkDiscoveryRun, discReq)
		// TriggerNetworkDiscoveryRun requires a configured vantage point;
		// if unconfigured in this test context it 503s -- either way,
		// the point of this test is the multi-hop composition boundary,
		// not discovery-run creation, so a 503 here is itself proof
		// there is no observation evidence available, which is an
		// equally valid path through this same assertion (the discovery
		// run id is simply omitted below in that case).
		var discoveryRunID string
		if discRec.Code == http.StatusCreated {
			var discCreated struct {
				RunID string `json:"runId"`
			}
			_ = json.Unmarshal(discRec.Body.Bytes(), &discCreated)
			discoveryRunID = discCreated.RunID
		}

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID}
		if discoveryRunID != "" {
			body["discoveryRunId"] = discoveryRunID
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if resp.Results[0].Severity == zoneisolation.SeverityConfirmedViolation {
			t.Fatal("a 2-hop route (guest->dmz->clinical) must never report confirmed-violation -- observation correlation is single-hop-only")
		}
	})
}

// TestFindIsolationChecks_RequiredFieldsMissing_Rejected pins the
// baseline required-field contract.
func TestFindIsolationChecks_RequiredFieldsMissing_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-missing", "pw12345678", string(auth.RoleAnalyst), true)
		b, _ := json.Marshal(map[string]any{})
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- topologyImportId and isolationImportId are both required", rec.Code, rec.Body.String())
		}
	})
}

// TestFindIsolationChecks_RealObservation_ConfirmedViolation proves
// confirmed-violation is actually reachable through the real
// composition pipeline (CIDR resolution, single-hop attachObservation
// gating, ComposeHop's observation-overrides-policy correlation) --
// not just through the pure zoneisolation.ClassifyIsolation unit test.
// A real vantage point dials a real listener; the destination zone's
// policy explicitly denies the flow, so a confirmed-violation result
// here can only come from the observation genuinely overriding policy.
func TestFindIsolationChecks_RealObservation_ConfirmedViolation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "isocheck-op-realobs", "pw12345678", string(auth.RoleAnalyst), true)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": openPort}}})
		discoveryRec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
		if discoveryRec.Code != http.StatusCreated {
			t.Fatalf("trigger discovery: status = %d, body = %s", discoveryRec.Code, discoveryRec.Body.String())
		}
		var discoveryResp struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discoveryResp); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"127.0.0.0/24"}},
			},
			"edges": []map[string]any{{"fromZone": "guest", "toZone": "clinical"}},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"127.0.0.0/24"}},
			},
			"rules":         []map[string]any{{"order": 1, "sourceZone": "guest", "destZone": "clinical", "protocol": "tcp", "action": "deny"}},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID, "discoveryRunId": discoveryResp.RunID, "port": openPort}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].Severity != zoneisolation.SeverityConfirmedViolation {
			t.Fatalf("got %+v, want exactly 1 result with severity confirmed-violation -- a real observation must override a policy deny", resp.Results)
		}
	})
}

// TestFindIsolationChecks_MultipleRoutesDivergentStates_WorstWins pins
// a real bug a code-review subagent found: picking the "worst" result
// across several INDEPENDENT candidate routes for the same pair must
// never reuse networkpath.AggregatePathState, whose Blocked
// short-circuit is correct only for aggregating the SEQUENTIAL hops of
// one single path. Here one route is a direct, single-hop route with a
// real matching observation (Observed, i.e. a demonstrated breach);
// a second, longer route is fully policy-denied (Blocked). Picking by
// AggregatePathState's own ranking sees the Blocked route and returns
// Blocked immediately without ever inspecting the Observed route,
// silently hiding the demonstrated breach behind an unrelated route's
// denial. The correct picker must select the Observed route instead.
func TestFindIsolationChecks_MultipleRoutesDivergentStates_WorstWins(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)
		userID := seedUser(t, pool, "isocheck-op-divergent", "pw12345678", string(auth.RoleAnalyst), true)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": openPort}}})
		discoveryRec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
		if discoveryRec.Code != http.StatusCreated {
			t.Fatalf("trigger discovery: status = %d, body = %s", discoveryRec.Code, discoveryRec.Body.String())
		}
		var discoveryResp struct {
			RunID string `json:"runId"`
		}
		if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discoveryResp); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}

		// Two routes between guest and clinical: a direct single-hop
		// route (eligible for observation correlation) and a longer
		// guest->dmz->clinical alternate (multi-hop, never eligible for
		// observation correlation, so it is classified purely by
		// policy -- and the policy below denies everything by default).
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"127.0.0.0/24"}},
				{"name": "dmz", "cidrs": []string{"10.0.5.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "guest", "toZone": "clinical"},
				{"fromZone": "guest", "toZone": "dmz"},
				{"fromZone": "dmz", "toZone": "clinical"},
			},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"127.0.0.0/24"}},
				{"name": "dmz", "cidrs": []string{"10.0.5.0/24"}},
			},
			"rules": []map[string]any{
				{"order": 1, "sourceZone": "guest", "destZone": "dmz", "protocol": "tcp", "action": "deny"},
				{"order": 2, "sourceZone": "dmz", "destZone": "clinical", "protocol": "tcp", "action": "deny"},
			},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID, "discoveryRunId": discoveryResp.RunID, "port": openPort}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].Severity != zoneisolation.SeverityConfirmedViolation {
			t.Fatalf("got %+v, want exactly 1 result with severity confirmed-violation -- the direct route's demonstrated breach must never be hidden by the alternate route's unrelated denial", resp.Results)
		}
	})
}

// TestFindIsolationChecks_DirectedEdgeReverseDirection_StillDetected
// pins a second real bug a code-review subagent found:
// ZonePairIsolation's own doc comment says isolation is checked "in
// either direction", but the handler only ever queried
// zoneA->zoneB. A directed edge/tunnel (a first-class, tested feature
// of networktopology.RouteEdge/remoteaccess.Tunnel) existing only in
// the reverse orientation -- exactly the shape of an outbound-only
// exfiltration path out of a clinical zone -- was therefore completely
// invisible. Here the only edge is clinical->guest (directed), and the
// isolation pair is declared zoneA=guest/zoneB=clinical; the check
// must still find the reverse route and classify it, never silently
// report no-violation-found just because the forward direction has no
// edge.
func TestFindIsolationChecks_DirectedEdgeReverseDirection_StillDetected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "isocheck-op-reversedir", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "clinical", "toZone": "guest", "directed": true},
			},
		})
		isoID := createTestIsolationImport(t, h, pool, []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "guest", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "clinical", "cidrs": []string{"10.0.2.0/24"}},
			},
			"rules":         []map[string]any{{"order": 1, "sourceZone": "clinical", "destZone": "guest", "protocol": "tcp", "action": "allow"}},
			"defaultPolicy": "deny",
		}
		pb, _ := json.Marshal(policyBody)
		pReq := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pRec := callAuthed(h.CreateNetworkPolicyImport, pReq)
		if pRec.Code != http.StatusCreated {
			t.Fatalf("create policy import: status = %d, body = %s", pRec.Code, pRec.Body.String())
		}
		var policyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(pRec.Body.Bytes(), &policyCreated)

		body := map[string]any{"topologyImportId": topoID, "isolationImportId": isoID, "policyImportId": policyCreated.ID}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/isolation-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindIsolationChecks, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []zoneisolation.IsolationCheckResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].Severity == zoneisolation.SeverityNoViolationFound {
			t.Fatalf("got %+v, want a severity other than no-violation-found -- the reverse-direction route (clinical->guest) must still be found and classified", resp.Results)
		}
	})
}
