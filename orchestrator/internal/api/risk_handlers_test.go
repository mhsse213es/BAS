package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/riskinputs"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// riskRouter mounts the risk handlers the way routes.go does, so chi URL parameters resolve.
func riskRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Get("/api/risk/inputs", h.GetRiskInputs)
	r.Get("/api/risk/inputs/{technique}/history", h.GetRiskInputHistory)
	r.Put("/api/risk/currency", h.SetRiskCurrency)
	r.Put("/api/risk/inputs/{technique}", h.PutRiskInput)
	r.Delete("/api/risk/inputs/{technique}", h.DeleteRiskInput)
	return r
}

func riskAdmin(req *http.Request) *http.Request {
	ctx := auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-test", Role: auth.RoleAdmin})
	return req.WithContext(ctx)
}

func resetRisk(t *testing.T, h *Handler) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.db.Exec(ctx, `DELETE FROM risk_exposure_input`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(ctx, `DELETE FROM risk_settings`); err != nil {
		t.Fatal(err)
	}
}

func putInput(t *testing.T, router http.Handler, tech, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := riskAdmin(httptest.NewRequest(http.MethodPut, "/api/risk/inputs/"+tech, bytes.NewBufferString(body)))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// A missing range is an error, never an implicit zero.
func TestPutRiskInputRejectsMissingRange(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		rec := putInput(t, riskRouter(h), "T-API-MISS", `{"frequency":{"low":1,"likely":1,"high":1}}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("missing magnitude: status %d, want 400", rec.Code)
		}
		if list, _ := riskinputs.List(context.Background(), pool); len(list) != 0 {
			t.Error("a rejected input must not be stored")
		}
	})
}

// Negative and unordered financial values are rejected and nothing is written.
func TestPutRiskInputRejectsInvalidValues(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		router := riskRouter(h)
		if rec := putInput(t, router, "T-API-NEG", `{"frequency":{"low":-1,"likely":1,"high":2},"magnitude":{"low":1,"likely":1,"high":1}}`); rec.Code != http.StatusBadRequest {
			t.Errorf("negative frequency: status %d, want 400", rec.Code)
		}
		if rec := putInput(t, router, "T-API-ORD", `{"frequency":{"low":3,"likely":2,"high":4},"magnitude":{"low":1,"likely":1,"high":1}}`); rec.Code != http.StatusBadRequest {
			t.Errorf("unordered frequency: status %d, want 400", rec.Code)
		}
		if h, _ := riskinputs.History(context.Background(), pool, "T-API-NEG"); len(h) != 0 {
			t.Error("a rejected write must leave no history")
		}
	})
}

// Changing an input, then reading history, shows the value before and after.
func TestRiskInputHistoryReadsBackPriorValue(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		router := riskRouter(h)
		putInput(t, router, "T-API-HIST", `{"frequency":{"low":1,"likely":2,"high":3},"magnitude":{"low":10,"likely":20,"high":30}}`)
		putInput(t, router, "T-API-HIST", `{"frequency":{"low":2,"likely":3,"high":4},"magnitude":{"low":10,"likely":20,"high":30}}`)
		req := riskAdmin(httptest.NewRequest(http.MethodGet, "/api/risk/inputs/T-API-HIST/history", nil))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("history status %d", rec.Code)
		}
		var entries []struct {
			Action   string `json:"action"`
			Previous *struct {
				Frequency struct{ Likely float64 } `json:"frequency"`
			} `json:"previous"`
			Current *struct {
				Frequency struct{ Likely float64 } `json:"frequency"`
			} `json:"current"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 || entries[1].Previous == nil || entries[1].Previous.Frequency.Likely != 2 || entries[1].Current.Frequency.Likely != 3 {
			t.Errorf("history must reconstruct the prior value, got %s", rec.Body.String())
		}
	})
}

// No currency set: there is no loss figure, even with inputs stored.
func TestRiskQuantificationHiddenWithoutCurrency(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		putInput(t, riskRouter(h), "T-API-NOCUR", `{"frequency":{"low":1,"likely":1,"high":1},"magnitude":{"low":5,"likely":5,"high":5}}`)
		rep := &reporting.FullReport{TopFindings: []reporting.Finding{{TechniqueID: "T-API-NOCUR"}}}
		rq, err := h.riskQuantification(context.Background(), rep)
		if err != nil || rq != nil {
			t.Fatalf("no currency: want nil figure, got %+v, %v", rq, err)
		}
	})
}

// With currency set, only open findings count, and a stored input for a technique that is not open is ignored.
func TestRiskQuantificationCountsOnlyOpenFindings(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		router := riskRouter(h)
		req := riskAdmin(httptest.NewRequest(http.MethodPut, "/api/risk/currency", strings.NewReader(`{"currency":"USD"}`)))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("set currency status %d: %s", rec.Code, rec.Body.String())
		}
		putInput(t, router, "T-API-OPEN", `{"frequency":{"low":2,"likely":2,"high":2},"magnitude":{"low":100,"likely":100,"high":100}}`)
		putInput(t, router, "T-API-CLOSED", `{"frequency":{"low":9,"likely":9,"high":9},"magnitude":{"low":9,"likely":9,"high":9}}`)
		rep := &reporting.FullReport{TopFindings: []reporting.Finding{{TechniqueID: "T-API-OPEN"}, {TechniqueID: "T-API-NOINPUT"}}}
		rq, err := h.riskQuantification(context.Background(), rep)
		if err != nil || rq == nil {
			t.Fatalf("want a figure, got %+v, %v", rq, err)
		}
		if rq.Currency != "USD" || rq.Total.Likely != 200 {
			t.Errorf("total = %+v in %s, want 200 USD", rq.Total, rq.Currency)
		}
		if len(rq.Items) != 2 || len(rq.Unquantified) != 1 || rq.Unquantified[0] != "T-API-NOINPUT" {
			t.Errorf("items %d, unquantified %v; want 2 items with T-API-NOINPUT unquantified", len(rq.Items), rq.Unquantified)
		}
	})
}

// A report whose open findings have no inputs keeps hiding the card.
func TestRiskQuantificationNilWhenNoOpenInput(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		if _, err := riskinputs.SetCurrency(context.Background(), pool, "USD", "admin-test"); err != nil {
			t.Fatal(err)
		}
		putInput(t, riskRouter(h), "T-API-OTHER", `{"frequency":{"low":1,"likely":1,"high":1},"magnitude":{"low":1,"likely":1,"high":1}}`)
		rep := &reporting.FullReport{TopFindings: []reporting.Finding{{TechniqueID: "T-API-UNRATED"}}}
		rq, err := h.riskQuantification(context.Background(), rep)
		if err != nil || rq != nil {
			t.Fatalf("no input for any open finding: want nil, got %+v, %v", rq, err)
		}
	})
}

// Delete returns the exposure to unquantified; deleting it again is a 404.
func TestDeleteRiskInputClearsAndReportsMissing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		resetRisk(t, h)
		router := riskRouter(h)
		putInput(t, router, "T-API-DEL", `{"frequency":{"low":1,"likely":1,"high":1},"magnitude":{"low":1,"likely":1,"high":1}}`)
		del := func() int {
			req := riskAdmin(httptest.NewRequest(http.MethodDelete, "/api/risk/inputs/T-API-DEL", nil))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			return rec.Code
		}
		if code := del(); code != http.StatusNoContent {
			t.Fatalf("first delete status %d, want 204", code)
		}
		if code := del(); code != http.StatusNotFound {
			t.Fatalf("second delete status %d, want 404", code)
		}
	})
}
