package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func actionsHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func actionsConfigReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/actions/configs", bytes.NewReader(b))
}

func TestListResponseConnectors_EmptyAndPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListResponseConnectors(rec, httptest.NewRequest(http.MethodGet, "/api/actions/configs", nil))
		var empty []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 connectors, got %d", len(empty))
		}

		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{
			"name": "Prod CrowdStrike", "provider": "crowdstrike", "baseUrl": "https://api.crowdstrike.com",
		}))
		if createRec.Code != http.StatusOK {
			t.Fatalf("create: status = %d, want 200, body = %s", createRec.Code, createRec.Body.String())
		}

		listRec := httptest.NewRecorder()
		h.ListResponseConnectors(listRec, httptest.NewRequest(http.MethodGet, "/api/actions/configs", nil))
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["name"] != "Prod CrowdStrike" || out[0]["provider"] != "crowdstrike" {
			t.Fatalf("out = %+v, want 1 entry named Prod CrowdStrike/crowdstrike", out)
		}
	})
}

func TestCreateResponseConnector_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing name", map[string]any{"provider": "crowdstrike"}},
			{"missing provider", map[string]any{"name": "x"}},
			{"invalid provider", map[string]any{"name": "x", "provider": "sentinelone"}},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.CreateResponseConnector(rec, actionsConfigReq(c.body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestUpdateResponseConnector_PreservesMaskedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{
			"name": "x", "provider": "crowdstrike", "clientSecret": "real-secret",
		}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		b, _ := json.Marshal(map[string]any{"name": "x-renamed", "clientSecret": "***"})
		req := withURLParam(httptest.NewRequest(http.MethodPut, "/x", bytes.NewReader(b)), "id", created.ID)
		rec := httptest.NewRecorder()
		h.UpdateResponseConnector(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		var name, secret string
		pool.QueryRow(context.Background(),
			`SELECT name, client_secret FROM action_connectors WHERE id=$1`, created.ID,
		).Scan(&name, &secret)
		if name != "x-renamed" {
			t.Errorf("name = %q, want x-renamed", name)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want the original secret preserved", secret)
		}
	})
}

func TestDeleteResponseConnector_NotFoundAndSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		notFoundRec := httptest.NewRecorder()
		h.DeleteResponseConnector(notFoundRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", "nope"))
		if notFoundRec.Code != http.StatusNotFound {
			t.Fatalf("not found: status = %d, want 404", notFoundRec.Code)
		}

		createRec := httptest.NewRecorder()
		h.CreateResponseConnector(createRec, actionsConfigReq(map[string]any{"name": "x", "provider": "microsoft_defender"}))
		var created struct {
			ID string `json:"id"`
		}
		json.Unmarshal(createRec.Body.Bytes(), &created)

		delRec := httptest.NewRecorder()
		h.DeleteResponseConnector(delRec, withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "id", created.ID))
		if delRec.Code != http.StatusOK {
			t.Fatalf("delete: status = %d, want 200", delRec.Code)
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM action_connectors WHERE id=$1`, created.ID).Scan(&n)
		if n != 0 {
			t.Fatalf("expected the connector to be gone, found %d rows", n)
		}
	})
}

func TestTestResponseConnector_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := actionsHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TestResponseConnector(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
