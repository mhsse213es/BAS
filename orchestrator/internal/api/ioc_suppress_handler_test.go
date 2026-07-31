package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSetIOCSuppressed_SetsFlagAndReturnsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var id string
		if err := pool.QueryRow(context.Background(),
			`INSERT INTO iocs (type, value, source) VALUES ('command_line', 'suppress-me', 'detection_alert') RETURNING id`).
			Scan(&id); err != nil {
			t.Fatalf("seed ioc: %v", err)
		}

		h := &Handler{db: pool}
		body := `{"suppressed":true,"reason":"known lab tool"}`
		req := httptest.NewRequest(http.MethodPost, "/api/iocs/"+id+"/suppress", strings.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		rec := httptest.NewRecorder()
		h.SetIOCSuppressed(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["suppressed"] != true || got["reason"] != "known lab tool" {
			t.Errorf("response = %+v, want suppressed=true reason=\"known lab tool\"", got)
		}

		var suppressed bool
		if err := pool.QueryRow(context.Background(), `SELECT suppressed FROM iocs WHERE id = $1`, id).Scan(&suppressed); err != nil {
			t.Fatalf("query: %v", err)
		}
		if !suppressed {
			t.Error("iocs.suppressed = false after suppress call")
		}
	})
}

func TestSetIOCSuppressed_InvalidBody_Returns400(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/api/iocs/x/suppress", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	h.SetIOCSuppressed(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
