package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/remoteaccess"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validRemoteAccessImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"tunnels": []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "up"},
		},
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
}

func TestCreateRemoteAccessImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validRemoteAccessImportBody())
		userID := seedUser(t, pool, "remoteaccess-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created remoteaccess.RemoteAccessImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

func TestCreateRemoteAccessImport_InvalidTunnelState_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validRemoteAccessImportBody()
		body["tunnels"] = []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "branch", "toZone": "datacenter", "state": "Active"},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "remoteaccess-op-badstate", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unknown tunnel state must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRemoteAccessImport_TunnelsWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validRemoteAccessImportBody()
		delete(body, "limitations")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "remoteaccess-op-nolim", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- any Tunnels/Transits present requires non-empty Limitations (zone names are never cross-validated)", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateRemoteAccessImport_EmptyZoneName_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validRemoteAccessImportBody()
		body["tunnels"] = []map[string]any{
			{"canonicalId": "vpn-1", "fromZone": "", "toZone": "datacenter", "state": "up"},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "remoteaccess-op-emptyzone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateRemoteAccessImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an empty zone name must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetRemoteAccessImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validRemoteAccessImportBody())
		userID := seedUser(t, pool, "remoteaccess-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/remote-access-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateRemoteAccessImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created remoteaccess.RemoteAccessImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/remote-access-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListRemoteAccessImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/remote-access-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetRemoteAccessImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
