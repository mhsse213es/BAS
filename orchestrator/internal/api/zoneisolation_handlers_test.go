package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/audspect/bas/internal/zoneisolation"
)

func validZoneIsolationImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"zonePairIsolations": []map[string]any{
			{"canonicalId": "zp-1", "zoneA": "guest", "zoneB": "clinical", "note": "guest wifi must never reach clinical systems"},
		},
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
}

func TestCreateZoneIsolationImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validZoneIsolationImportBody())
		userID := seedUser(t, pool, "zoneiso-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/zone-isolation-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateZoneIsolationImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created zoneisolation.IsolationImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

func TestCreateZoneIsolationImport_ZonePairsWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validZoneIsolationImportBody()
		delete(body, "limitations")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "zoneiso-op-nolim", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/zone-isolation-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateZoneIsolationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- any zonePairIsolation present requires non-empty limitations", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateZoneIsolationImport_EmptyZoneName_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validZoneIsolationImportBody()
		body["zonePairIsolations"] = []map[string]any{{"canonicalId": "zp-1", "zoneA": "", "zoneB": "clinical"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "zoneiso-op-emptyzone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/zone-isolation-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateZoneIsolationImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an empty zone name must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetZoneIsolationImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validZoneIsolationImportBody())
		userID := seedUser(t, pool, "zoneiso-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/zone-isolation-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateZoneIsolationImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created zoneisolation.IsolationImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/zone-isolation-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListZoneIsolationImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/zone-isolation-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetZoneIsolationImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
