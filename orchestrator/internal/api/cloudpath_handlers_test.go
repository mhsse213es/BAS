package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createCloudTopologyImportForPathTest(t *testing.T, h *Handler, userID string) string {
	t.Helper()
	body := map[string]any{
		"sourceType": "manual",
		"networks":   []map[string]any{{"canonicalId": "vpc-1", "cidrBlocks": []string{"10.0.0.0/16"}}},
		"subnets": []map[string]any{
			{"canonicalId": "subnet-a", "networkId": "vpc-1", "cidrBlock": "10.0.1.0/24"},
			{"canonicalId": "subnet-b", "networkId": "vpc-1", "cidrBlock": "10.0.2.0/24"},
		},
		"groups": []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "network"}},
		"rules": []map[string]any{
			{"id": "r1", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "10.0.2.0/24"},
			{"id": "r2", "groupId": "sg-1", "order": 10, "direction": "inbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "10.0.1.0/24"},
		},
		"routes": []map[string]any{
			{"id": "rt-1", "subnetId": "subnet-a", "destinationCidr": "10.0.2.0/24", "target": "local"},
		},
	}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateCloudTopologyImport, req)
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

func TestFindCloudPaths_RouteFoundAndPolicyPermits_PolicySupported(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createCloudTopologyImportForPathTest(t, h, userID)

		body := map[string]any{
			"topologyImportId": topoID,
			"sourceHost":       "10.0.1.5",
			"destHost":         "10.0.2.5",
			"port":             443,
			"protocol":         "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindCloudPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []cloudpath.CloudPathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if resp.Results[0].State != "policy_supported" {
			t.Fatalf("State = %q, want %q", resp.Results[0].State, "policy_supported")
		}
	})
}

// TestFindCloudPaths_DestinationInboundSecurityGroupDenies_Blocked
// proves the Critical fix end-to-end through the real HTTP API: the
// source subnet's shared, VPC-wide security group permits the flow
// outbound, but the destination subnet carries its own
// ScopeSubnet security group with an explicit inbound deny for the
// same flow -- the textbook AWS pattern (a destination-only inbound
// rule a VPC-wide egress rule says nothing about). Before the fix,
// only the source's outbound rule was ever evaluated, so this
// topology would have incorrectly returned policy_supported.
func TestFindCloudPaths_DestinationInboundSecurityGroupDenies_Blocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op-destdeny", "pw12345678", string(auth.RoleAnalyst), true)

		body := map[string]any{
			"sourceType": "manual",
			"networks":   []map[string]any{{"canonicalId": "vpc-1", "cidrBlocks": []string{"10.0.0.0/16"}}},
			"subnets": []map[string]any{
				{"canonicalId": "subnet-a", "networkId": "vpc-1", "cidrBlock": "10.0.1.0/24"},
				{"canonicalId": "subnet-b", "networkId": "vpc-1", "cidrBlock": "10.0.2.0/24"},
			},
			"groups": []map[string]any{
				{"canonicalId": "sg-vpc", "networkId": "vpc-1", "scope": "network"},
				{"canonicalId": "sg-b-inbound", "networkId": "vpc-1", "subnetId": "subnet-b", "scope": "subnet"},
			},
			"rules": []map[string]any{
				{"id": "r-egress", "groupId": "sg-vpc", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "10.0.2.0/24"},
				{"id": "r-ingress-deny", "groupId": "sg-b-inbound", "order": 10, "direction": "inbound", "action": "deny", "protocol": "tcp", "portRange": "443", "cidr": "10.0.1.0/24"},
			},
			"routes": []map[string]any{
				{"id": "rt-1", "subnetId": "subnet-a", "destinationCidr": "10.0.2.0/24", "target": "local"},
			},
		}
		b, _ := json.Marshal(body)
		createReq := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateCloudTopologyImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create topology import: status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}

		pathBody := map[string]any{
			"topologyImportId": created.ID,
			"sourceHost":       "10.0.1.5",
			"destHost":         "10.0.2.5",
			"port":             443,
			"protocol":         "tcp",
		}
		pb, _ := json.Marshal(pathBody)
		pathReq := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pathRec := callAuthed(h.FindCloudPaths, pathReq)
		if pathRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", pathRec.Code, pathRec.Body.String())
		}
		var resp struct {
			Results []cloudpath.CloudPathResult `json:"results"`
		}
		if err := json.Unmarshal(pathRec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if resp.Results[0].State != "blocked" {
			t.Fatalf("State = %q, want %q -- the destination's own inbound deny must be consulted, not just the source's outbound allow", resp.Results[0].State, "blocked")
		}
	})
}

// TestFindCloudPaths_SameSubnetQuery_EvaluatesSecurityGroups proves
// the Important fix: a query whose sourceHost and destHost resolve to
// the same subnet must still return a real, evaluated result (real
// clouds still enforce security groups on intra-subnet traffic at the
// instance/ENI level), never an empty results array.
func TestFindCloudPaths_SameSubnetQuery_EvaluatesSecurityGroups(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op-samesub", "pw12345678", string(auth.RoleAnalyst), true)

		body := map[string]any{
			"sourceType": "manual",
			"networks":   []map[string]any{{"canonicalId": "vpc-1", "cidrBlocks": []string{"10.0.0.0/16"}}},
			"subnets":    []map[string]any{{"canonicalId": "subnet-a", "networkId": "vpc-1", "cidrBlock": "10.0.1.0/24"}},
			"groups":     []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "network"}},
			"rules": []map[string]any{
				{"id": "r-intra-out", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "10.0.1.0/24"},
				{"id": "r-intra-in", "groupId": "sg-1", "order": 10, "direction": "inbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "10.0.1.0/24"},
			},
			"routes": []map[string]any{},
		}
		b, _ := json.Marshal(body)
		createReq := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateCloudTopologyImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create topology import: status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}

		pathBody := map[string]any{
			"topologyImportId": created.ID,
			"sourceHost":       "10.0.1.5",
			"destHost":         "10.0.1.6",
			"port":             443,
			"protocol":         "tcp",
		}
		pb, _ := json.Marshal(pathBody)
		pathReq := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(pb), auth.RoleAnalyst, userID)
		pathRec := callAuthed(h.FindCloudPaths, pathReq)
		if pathRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", pathRec.Code, pathRec.Body.String())
		}
		var resp struct {
			Results []cloudpath.CloudPathResult `json:"results"`
		}
		if err := json.Unmarshal(pathRec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1 -- a same-subnet query must return a real evaluated result, not an empty array", len(resp.Results))
		}
		if resp.Results[0].State != "policy_supported" {
			t.Fatalf("State = %q, want %q", resp.Results[0].State, "policy_supported")
		}
	})
}

func TestFindCloudPaths_MissingRequiredFields_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op-bad", "pw12345678", string(auth.RoleAnalyst), true)
		b, _ := json.Marshal(map[string]any{"sourceHost": "10.0.1.5"})
		req := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindCloudPaths, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestFindCloudPaths_UnknownTopologyImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op-404", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{"topologyImportId": "does-not-exist", "sourceHost": "10.0.1.5", "destHost": "10.0.2.5", "port": 443}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindCloudPaths, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want 404", rec.Code, rec.Body.String())
		}
	})
}
