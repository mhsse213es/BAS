package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createNetworkTopologyImportForRemoteAccessTest(t *testing.T, h *Handler, userID string, zones []map[string]any, edges []map[string]any) string {
	t.Helper()
	body := map[string]any{"sourceType": "manual", "zones": zones, "edges": edges}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateNetworkTopologyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create network topology import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

func createRemoteAccessImportForPathTest(t *testing.T, h *Handler, userID string, tunnels []map[string]any) string {
	t.Helper()
	body := map[string]any{
		"sourceType":  "manual",
		"tunnels":     tunnels,
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateRemoteAccessImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create remote access import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

// TestFindRemoteAccessPaths_TunnelOnlyConnectivity_RouteFound pins that
// a VPN tunnel alone (no physical edge at all) makes two zones
// reachable, and (with no policy import supplied) the handler still
// composes a route-declared-but-unevaluated-policy hop consistently
// with networkpath.ComposeHop's own existing semantics.
func TestFindRemoteAccessPaths_TunnelOnlyConnectivity_RouteFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-tunnel", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "branch", "cidrs": []string{"10.1.0.0/24"}},
				{"name": "datacenter", "cidrs": []string{"10.2.0.0/24"}},
			}, []map[string]any{})
		remoteID := createRemoteAccessImportForPathTest(t, h, userID, []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "up"},
		})

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteID,
			"sourceHost":           "10.1.0.5",
			"destHost":             "10.2.0.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []networkpath.PathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if !resp.Results[0].Hops[0].RouteDeclared {
			t.Fatal("want RouteDeclared=true -- the tunnel provides a route even with no physical edge")
		}
	})
}

// TestFindRemoteAccessPaths_TunnelDown_NoOtherRoute_Unknown pins
// Review Focus #1's end-to-end half.
func TestFindRemoteAccessPaths_TunnelDown_NoOtherRoute_Unknown(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-down", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "branch", "cidrs": []string{"10.1.0.0/24"}},
				{"name": "datacenter", "cidrs": []string{"10.2.0.0/24"}},
			}, []map[string]any{})
		remoteID := createRemoteAccessImportForPathTest(t, h, userID, []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "down"},
		})

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteID,
			"sourceHost":           "10.1.0.5",
			"destHost":             "10.2.0.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []networkpath.PathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].State != "unknown" {
			t.Fatalf("Results = %v, want exactly 1 result with State unknown -- a down tunnel with no other route must never read as blocked", resp.Results)
		}
	})
}

// TestFindRemoteAccessPaths_BypassRoute_TransitViolationAttached pins
// Review Focus #2's end-to-end half.
func TestFindRemoteAccessPaths_BypassRoute_TransitViolationAttached(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-bypass", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "production", "cidrs": []string{"10.0.2.0/24"}},
			},
			[]map[string]any{
				{"fromZone": "corporate", "toZone": "production"},
			})
		// This test needs a MandatoryTransit, which
		// createRemoteAccessImportForPathTest's helper signature does
		// not take -- build the import body directly instead.
		remoteBody := map[string]any{
			"sourceType": "manual",
			"transits": []map[string]any{
				{"canonicalId": "mt-1", "fromZone": "corporate", "toZone": "production", "viaZone": "bastion"},
			},
			"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
		}
		rb, _ := json.Marshal(remoteBody)
		remoteReq := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(rb), auth.RoleAnalyst, userID)
		remoteRec := callAuthed(h.CreateRemoteAccessImport, remoteReq)
		if remoteRec.Code != http.StatusCreated {
			t.Fatalf("create remote access import with transit: status = %d, body = %s", remoteRec.Code, remoteRec.Body.String())
		}
		var remoteCreated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(remoteRec.Body.Bytes(), &remoteCreated); err != nil {
			t.Fatalf("decode: %v", err)
		}

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteCreated.ID,
			"sourceHost":           "10.0.1.5",
			"destHost":             "10.0.2.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			TransitViolations []map[string]any `json:"transitViolations"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.TransitViolations) != 1 {
			t.Fatalf("transitViolations = %v, want exactly 1 -- the direct corporate->production route bypasses the required bastion zone", resp.TransitViolations)
		}
	})
}

func TestFindRemoteAccessPaths_MissingRequiredFields_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-bad", "pw12345678", string(auth.RoleAnalyst), true)
		b, _ := json.Marshal(map[string]any{"sourceHost": "10.1.0.5"})
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

// TestFindRemoteAccessPaths_MixedTunnelAndPhysicalHops_OneHopPolicyBlocks_WholePathBlocked
// pins Review Focus #4: a 3-zone path (corporate -[physical]-> bastion
// -[tunnel]-> production) where the policy import blocks the second
// (tunnel) hop and permits the first -- the whole path must still
// aggregate to Blocked via the reused, unmodified
// networkpath.AggregatePath.
func TestFindRemoteAccessPaths_MixedTunnelAndPhysicalHops_OneHopPolicyBlocks_WholePathBlocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "raPath-op-mixed", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForRemoteAccessTest(t, h, userID,
			[]map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "bastion", "cidrs": []string{"10.0.2.0/24"}},
				{"name": "production", "cidrs": []string{"10.0.3.0/24"}},
			},
			[]map[string]any{
				{"fromZone": "corporate", "toZone": "bastion"},
			})
		remoteID := createRemoteAccessImportForPathTest(t, h, userID, []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "bastion", "toZone": "production", "state": "up"},
		})

		policyBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "bastion", "cidrs": []string{"10.0.2.0/24"}},
				{"name": "production", "cidrs": []string{"10.0.3.0/24"}},
			},
			"defaultPolicy": "allow",
			"rules": []map[string]any{
				{"id": "deny-bastion-to-prod", "order": 10, "sourceZone": "bastion", "destZone": "production", "action": "deny", "protocol": "tcp", "portRange": "443"},
			},
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
		if err := json.Unmarshal(pRec.Body.Bytes(), &policyCreated); err != nil {
			t.Fatalf("decode: %v", err)
		}

		body := map[string]any{
			"topologyImportId":     topoID,
			"remoteAccessImportId": remoteID,
			"policyImportId":       policyCreated.ID,
			"sourceHost":           "10.0.1.5",
			"destHost":             "10.0.3.5",
			"port":                 443,
			"protocol":             "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindRemoteAccessPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []networkpath.PathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].State != "blocked" {
			t.Fatalf("Results = %v, want exactly 1 result with State blocked -- one blocking hop must still block the whole mixed-kind path", resp.Results)
		}
	})
}
