package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/taxii"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testTAXIIHandler(pool *pgxpool.Pool) *Handler {
	store := taxii.NewStore(pool)
	manager := taxii.NewManager(pool, store)
	return New(pool, ws.NewHub(), nil, testJWTSecret).WithTAXII(store, manager)
}

func TestCreateTAXIIConnector_PersistsAndReturnsWithoutSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-create-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{
			"name": "FS-ISAC Test", "serverUrl": "https://taxii.example.org", "authType": "basic",
			"username": "user1", "password": "secret1", "enabled": true,
		})
		req := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateTAXIIConnector, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["name"] != "FS-ISAC Test" {
			t.Fatalf("response name = %v", out["name"])
		}
		if _, present := out["password"]; present {
			t.Fatal("response must never include the raw password field")
		}
		if out["hasPassword"] != true {
			t.Fatalf("hasPassword = %v, want true", out["hasPassword"])
		}
	})
}

func TestListTAXIIConnectors_ReturnsCreatedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-list-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"name": "ListMe", "serverUrl": "https://a.example"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(body), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateTAXIIConnector, createReq); rec.Code != http.StatusCreated {
			t.Fatalf("create: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		listReq := authedRequest(t, http.MethodGet, "/api/taxii/connectors", nil, auth.RoleAdmin, uid)
		listRec := callAuthed(h.ListTAXIIConnectors, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
		}
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		found := false
		for _, c := range out {
			if c["name"] == "ListMe" {
				found = true
			}
		}
		if !found {
			t.Fatalf("ListTAXIIConnectors did not include the created row: %+v", out)
		}
	})
}

func TestUpdateTAXIIConnector_EmptyPasswordKeepsStoredValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-update-user", "pw-Password1!", "admin", true)
		createBody, _ := json.Marshal(map[string]any{"name": "Orig", "serverUrl": "https://a.example", "password": "orig-secret"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(createBody), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateTAXIIConnector, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		id, _ := created["id"].(string)
		if id == "" {
			t.Fatalf("no id in create response: %s", createRec.Body.String())
		}

		updateBody, _ := json.Marshal(map[string]any{"name": "Renamed", "serverUrl": "https://a.example", "password": "", "enabled": true})
		updateReq := withURLParam(authedRequest(t, http.MethodPut, "/api/taxii/connectors/"+id, bytes.NewReader(updateBody), auth.RoleAdmin, uid), "id", id)
		updateRec := callAuthed(h.UpdateTAXIIConnector, updateReq)
		if updateRec.Code != http.StatusOK {
			t.Fatalf("update status = %d, body = %s", updateRec.Code, updateRec.Body.String())
		}

		var pw string
		if err := pool.QueryRow(context.Background(), `SELECT password FROM taxii_connector_config WHERE id = $1`, id).Scan(&pw); err != nil {
			t.Fatalf("query password: %v", err)
		}
		if pw != "orig-secret" {
			t.Fatalf("password = %q, want kept value %q", pw, "orig-secret")
		}
	})
}

func TestDeleteTAXIIConnector_RemovesRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-delete-user", "pw-Password1!", "admin", true)
		createBody, _ := json.Marshal(map[string]any{"name": "ToDelete", "serverUrl": "https://a.example"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(createBody), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateTAXIIConnector, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		id, _ := created["id"].(string)

		delReq := withURLParam(authedRequest(t, http.MethodDelete, "/api/taxii/connectors/"+id, nil, auth.RoleAdmin, uid), "id", id)
		delRec := callAuthed(h.DeleteTAXIIConnector, delReq)
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete status = %d, body = %s", delRec.Code, delRec.Body.String())
		}

		getReq := withURLParam(authedRequest(t, http.MethodGet, "/api/taxii/connectors/"+id, nil, auth.RoleAdmin, uid), "id", id)
		getRec := callAuthed(h.GetTAXIIConnector, getReq)
		if getRec.Code != http.StatusNotFound {
			t.Fatalf("get after delete: status = %d, want 404", getRec.Code)
		}
	})
}

func TestTestTAXIIConnector_ReportsFailureForUnreachableServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-test-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"serverUrl": "http://127.0.0.1:1", "authType": "none"})
		req := authedRequest(t, http.MethodPost, "/api/taxii/connectors/test", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.TestTAXIIConnector, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (test result reported in body, not HTTP status)", rec.Code)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["ok"] != false {
			t.Fatalf("ok = %v, want false for an unreachable server", out["ok"])
		}
	})
}

func TestSyncTAXIIConnector_TriggersOneSync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := testTAXIIHandler(pool)
		uid := seedUser(t, pool, "taxii-sync-user", "pw-Password1!", "admin", true)
		createBody, _ := json.Marshal(map[string]any{"name": "SyncTest", "serverUrl": "http://127.0.0.1:1"})
		createReq := authedRequest(t, http.MethodPost, "/api/taxii/connectors", bytes.NewReader(createBody), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateTAXIIConnector, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		id, _ := created["id"].(string)

		syncReq := withURLParam(authedRequest(t, http.MethodPost, "/api/taxii/connectors/"+id+"/sync", nil, auth.RoleAdmin, uid), "id", id)
		syncRec := callAuthed(h.SyncTAXIIConnector, syncReq)
		if syncRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", syncRec.Code, syncRec.Body.String())
		}
	})
}
