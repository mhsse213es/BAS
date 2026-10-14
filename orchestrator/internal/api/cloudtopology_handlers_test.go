package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validCloudTopologyImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"networks":   []map[string]any{{"canonicalId": "vpc-1", "cidrBlocks": []string{"10.0.0.0/16"}}},
		"subnets":    []map[string]any{{"canonicalId": "subnet-1", "networkId": "vpc-1", "cidrBlock": "10.0.1.0/24"}},
		"groups":     []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "network"}},
		"rules": []map[string]any{
			{"id": "r1", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "0.0.0.0/0"},
		},
		"routes": []map[string]any{
			{"id": "rt-1", "subnetId": "subnet-1", "destinationCidr": "0.0.0.0/0", "target": "internet-gateway"},
		},
	}
}

func TestCreateCloudTopologyImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validCloudTopologyImportBody())
		userID := seedUser(t, pool, "cloudtopo-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateCloudTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created cloudtopology.CloudTopologyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

// TestCreateCloudTopologyImport_UnresolvedGroupWithoutLimitations_Rejected
// pins Review Focus #1 at the import-validation boundary: a
// ScopeUnresolved group declared without a non-empty top-level
// Limitations entry must be rejected, not silently accepted.
func TestCreateCloudTopologyImport_UnresolvedGroupWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudTopologyImportBody()
		body["groups"] = []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "unresolved"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "cloudtopo-op-unresolved", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateCloudTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateCloudTopologyImport_SGReferenceRuleWithoutUnresolvedAction_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudTopologyImportBody()
		body["rules"] = []map[string]any{
			{"id": "r1", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "referencedGroupId": "sg-2"},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "cloudtopo-op-sgref", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateCloudTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an SG-to-SG reference rule cannot be resolved by this schema and must be marked unresolved, never allow/deny", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetCloudTopologyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validCloudTopologyImportBody())
		userID := seedUser(t, pool, "cloudtopo-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateCloudTopologyImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created cloudtopology.CloudTopologyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/cloud-topology-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListCloudTopologyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/cloud-topology-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetCloudTopologyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
