package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
)

// Expectations, written before the cases run:
//   - no identity and a Viewer are refused with 403; an Analyst and an Admin are admitted.
//   - a limit outside 1 to 500 is refused with 400; an unknown run is 404.
//   - the detail view lists one evidence reference per stored exchange, and includes the leaked-value count.
//   - a planted body value never appears in any response: the results API shows no response bodies.
const planted = "PLANTED-BODY-VALUE-7731"

func apibasRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/runs", h.ListAPIBASRuns)
	r.With(auth.RequirePermission(auth.CanViewAPIBASRuns)).Get("/api/apibas/runs/{id}", h.GetAPIBASRun)
	return r
}

func seedAPIBASRun(t *testing.T, tag string) string {
	t.Helper()
	report := []byte(`{"RunTag":"` + tag + `","ScenarioID":"API-BAS-AUTHZ-001",` +
		`"Outcome":{"Result":"FAIL","Exploitability":"exploited"},` +
		`"Exchanges":[` +
		`{"StepID":"baseline-owner-read","Method":"GET","Path":"/api/orders/ORD-2001","Status":200,"Body":"` + planted + `","Leaked":0},` +
		`{"StepID":"attack-cross-identity-read","Method":"GET","Path":"/api/orders/ORD-2001","Status":200,"Body":"` + planted + `","Leaked":2}` +
		`]}`)
	id, err := db.SaveAPIBASRun(context.Background(), sharedDB.Pool, db.APIBASRun{
		RunTag: tag, ScenarioID: "API-BAS-AUTHZ-001", Build: "vulnerable",
		Result: "FAIL", Exploitability: "exploited", Detection: "detected", Report: report,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return id
}

func getAs(t *testing.T, h http.Handler, path string, role auth.Role) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if role != "" {
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "u", Role: role}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPIBASRunsAuthorization(t *testing.T) {
	h := apibasRouter(&Handler{db: sharedDB.Pool})
	seedAPIBASRun(t, "authz-run")
	cases := []struct {
		name string
		role auth.Role
		want int
	}{
		{"no identity", "", http.StatusForbidden},
		{"viewer", auth.RoleViewer, http.StatusForbidden},
		{"analyst", auth.RoleAnalyst, http.StatusOK},
		{"admin", auth.RoleAdmin, http.StatusOK},
	}
	for _, c := range cases {
		if rec := getAs(t, h, "/api/apibas/runs", c.role); rec.Code != c.want {
			t.Errorf("%s: list status = %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestAPIBASRunsListAndDetail(t *testing.T) {
	h := apibasRouter(&Handler{db: sharedDB.Pool})
	id := seedAPIBASRun(t, "detail-run")

	if rec := getAs(t, h, "/api/apibas/runs?limit=0", auth.RoleAnalyst); rec.Code != http.StatusBadRequest {
		t.Fatalf("limit=0 status = %d, want 400", rec.Code)
	}
	if rec := getAs(t, h, "/api/apibas/runs/no-such-id", auth.RoleAnalyst); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown run status = %d, want 404", rec.Code)
	}

	rec := getAs(t, h, "/api/apibas/runs/"+id, auth.RoleAnalyst)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200", rec.Code)
	}
	var d struct {
		Result   string `json:"result"`
		Evidence []struct {
			Ref          string `json:"ref"`
			StepID       string `json:"step_id"`
			LeakedValues int    `json:"leaked_values"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Result != "FAIL" || len(d.Evidence) != 2 {
		t.Fatalf("detail = %+v, want FAIL with two evidence references", d)
	}
	if d.Evidence[0].Ref != "detail-run#0" || d.Evidence[1].LeakedValues != 2 {
		t.Fatalf("evidence refs = %+v", d.Evidence)
	}
	if strings.Contains(rec.Body.String(), planted) {
		t.Fatal("detail response exposed a response body")
	}
}

func TestAPIBASRunsListNeverShowsBodies(t *testing.T) {
	h := apibasRouter(&Handler{db: sharedDB.Pool})
	seedAPIBASRun(t, "list-body-run")
	for _, path := range []string{"/api/apibas/runs", "/api/apibas/runs?scenario=API-BAS-AUTHZ-001"} {
		if rec := getAs(t, h, path, auth.RoleAdmin); strings.Contains(rec.Body.String(), planted) {
			t.Fatalf("%s exposed a response body", path)
		}
	}
}
