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
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validControlExpectationImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual-declared",
		"expectations": []map[string]any{
			{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.2.0/24", "flowPort": 443, "flowProtocol": "tcp", "expectedAction": "block", "controlProduct": "opnsense"},
		},
	}
}

func networkControlExpectationImportReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "nce-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-control-expectations", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestCreateNetworkControlExpectationImport_ValidImportPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkControlExpectationImportReq(t, pool, validControlExpectationImportBody())
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkefficacy.ControlExpectationImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("want non-empty id")
		}
	})
}

func TestCreateNetworkControlExpectationImport_EmptyExpectationsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_InvalidCIDRRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{{"flowSourceCidr": "not-a-cidr", "flowDestCidr": "10.0.2.0/24", "flowPort": 443, "expectedAction": "block"}}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_InvalidExpectedActionRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.2.0/24", "flowPort": 443, "expectedAction": "redirect"}}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s -- \"redirect\" is not a declared ExpectedControlAction", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_InvalidPortRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validControlExpectationImportBody()
		body["expectations"] = []map[string]any{{"flowSourceCidr": "10.0.1.0/24", "flowDestCidr": "10.0.2.0/24", "flowPort": 70000, "expectedAction": "block"}}
		req := networkControlExpectationImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nce-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"sourceType":"` + strings.Repeat("x", maxNetworkControlExpectationImportRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-control-expectations", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkControlExpectationImport_ImportedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "nce-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := validControlExpectationImportBody()
		body["importedBy"] = "spoofed-user"
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-control-expectations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkefficacy.ControlExpectationImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got, err := db.GetNetworkControlExpectationImport(context.Background(), pool, resp.ID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ImportedBy != userID {
			t.Fatalf("ImportedBy = %q, want %q (the authenticated caller, not the spoofed body value)", got.ImportedBy, userID)
		}
	})
}

func TestListAndGetNetworkControlExpectationImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkControlExpectationImportReq(t, pool, validControlExpectationImportBody())
		createRec := callAuthed(h.CreateNetworkControlExpectationImport, req)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created networkefficacy.ControlExpectationImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/network-control-expectations", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListNetworkControlExpectationImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/network-control-expectations/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetNetworkControlExpectationImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
