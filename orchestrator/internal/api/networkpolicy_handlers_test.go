package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validPolicyImportBody() map[string]any {
	return map[string]any{
		"sourceType":    "manual-normalized",
		"defaultPolicy": "deny",
		"zones":         []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}},
		"rules": []map[string]any{
			{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "portRange": "443", "action": "allow"},
		},
	}
}

func networkPolicyImportReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "netpolicy-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestCreateNetworkPolicyImport_ValidImportPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkPolicyImportReq(t, pool, validPolicyImportBody())
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkpolicy.PolicyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("want non-empty id")
		}
	})
}

func TestCreateNetworkPolicyImport_EmptyZonesRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["zones"] = []map[string]any{}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_EmptyRulesRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_InvalidCIDRRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["zones"] = []map[string]any{{"name": "dmz", "cidrs": []string{"not-a-cidr"}}}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_UnknownActionRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "action": "maybe"}}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_UnresolvedWithoutNoteRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "action": "unresolved"}}
		body["limitations"] = []string{"something"}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_UnresolvedWithoutLimitationsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "action": "unresolved", "note": "NAT, cannot translate"}}
		req := networkPolicyImportReq(t, pool, body) // no top-level "limitations" key
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpolicy-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"sourceType":"` + strings.Repeat("x", maxNetworkPolicyImportRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_ImportedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpolicy-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := validPolicyImportBody()
		body["importedBy"] = "spoofed-user"
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkpolicy.PolicyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}

		got, err := db.GetNetworkPolicyImport(context.Background(), pool, resp.ID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ImportedBy != userID {
			t.Fatalf("ImportedBy = %q, want %q (the authenticated caller, not the spoofed body value)", got.ImportedBy, userID)
		}
	})
}

func TestListAndGetNetworkPolicyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkPolicyImportReq(t, pool, validPolicyImportBody())
		createRec := callAuthed(h.CreateNetworkPolicyImport, req)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created networkpolicy.PolicyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/network-policy-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListNetworkPolicyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/network-policy-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetNetworkPolicyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
