package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestTopologyImport(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	req := networkTopologyImportReq(t, pool, body)
	rec := callAuthed(h.CreateNetworkTopologyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create topology import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

func TestFindNetworkPaths_SameZoneQueryReturnsSingleHopResult(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}},
			"edges":      []map[string]any{},
		})

		body := map[string]any{"topologyImportId": topoID, "sourceHost": "10.0.1.5", "destHost": "10.0.1.50", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-samezone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || len(results[0].Hops) != 1 {
			t.Fatalf("got %+v, want exactly one result with one hop -- a same-zone query must still produce a meaningful single hop", results)
		}
	})
}

func TestFindNetworkPaths_NoRouteProducesUnknownNotBlocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}, {"name": "isolated", "cidrs": []string{"10.0.9.0/24"}}},
			"edges":      []map[string]any{},
		})

		body := map[string]any{"topologyImportId": topoID, "sourceHost": "10.0.1.5", "destHost": "10.0.9.5", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-noroute", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("got %d results, want exactly one synthetic result for the no-route case", len(results))
		}
		if results[0].State != cloudgraph.Unknown {
			t.Fatalf("State = %q, want unknown -- a missing route must never read as blocked", results[0].State)
		}
	})
}

func TestFindNetworkPaths_DisjointZoneNamingBetweenTopologyAndPolicyDegradesToUnknown(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		topoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "topology-zone-a", "cidrs": []string{"10.0.1.0/24"}}, {"name": "topology-zone-b", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{{"fromZone": "topology-zone-a", "toZone": "topology-zone-b"}},
		})
		policyReq := networkPolicyImportReq(t, pool, map[string]any{
			"sourceType": "manual-normalized", "defaultPolicy": "deny",
			"zones": []map[string]any{{"name": "completely-different-policy-zone-name", "cidrs": []string{"10.0.1.0/24"}}},
			"rules": []map[string]any{{"id": "r1", "order": 1, "sourceZone": "completely-different-policy-zone-name", "destCidr": "10.0.2.0/24", "action": "allow"}},
		})
		policyRec := callAuthed(h.CreateNetworkPolicyImport, policyReq)
		if policyRec.Code != http.StatusCreated {
			t.Fatalf("create policy: status = %d, body = %s", policyRec.Code, policyRec.Body.String())
		}
		var policyResp struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(policyRec.Body.Bytes(), &policyResp); err != nil {
			t.Fatalf("decode policy: %v", err)
		}

		body := map[string]any{"topologyImportId": topoID, "policyImportId": policyResp.ID, "sourceHost": "10.0.1.5", "destHost": "10.0.2.5", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-disjoint", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || results[0].State != cloudgraph.Unknown {
			t.Fatalf("got %+v, want one result with state unknown -- disjoint zone-naming schemes must degrade honestly, never crash or misattribute a policy verdict", results)
		}
	})
}

func TestFindNetworkPaths_MultiHopWithDiscoveryRunNotesNoObservationOnIntermediateHops(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

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
			"sourceType": "manual-declared",
			"zones":      []map[string]any{{"name": "a", "cidrs": []string{"10.0.1.0/24"}}, {"name": "pivot", "cidrs": []string{"10.0.2.0/24"}}, {"name": "b", "cidrs": []string{"127.0.0.0/24"}}},
			"edges":      []map[string]any{{"fromZone": "a", "toZone": "pivot"}, {"fromZone": "pivot", "toZone": "b"}},
		})

		body := map[string]any{"topologyImportId": topoID, "discoveryRunId": discoveryResp.RunID, "sourceHost": "10.0.1.5", "destHost": "127.0.0.1", "port": openPort}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-multihop", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var results []networkpath.PathResult
		if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(results) != 1 || len(results[0].Hops) != 2 {
			t.Fatalf("got %+v, want one result with 2 hops (a->pivot, pivot->b)", results)
		}
		firstHop := results[0].Hops[0]
		if firstHop.Observation != nil {
			t.Fatal("want no observation on the intermediate hop a->pivot -- Phase 1 never observes an arbitrary intermediate hop")
		}
		if firstHop.Limitations == "" {
			t.Fatal("want a non-empty limitation explaining why no observation was attempted on this intermediate hop, since a discovery run was supplied")
		}
	})
}

func TestFindNetworkPaths_UnknownTopologyImportReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"topologyImportId": "nonexistent-id", "sourceHost": "10.0.1.5", "destHost": "10.0.1.50", "port": 443}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-404", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestFindNetworkPaths_MissingRequiredFieldsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"topologyImportId": "some-id"}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpath-op-missing", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
