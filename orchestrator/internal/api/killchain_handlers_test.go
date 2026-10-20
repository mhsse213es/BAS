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

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

const killChainTestDef = `{"id":"kc-api-1","name":"API chain","version":1,"stages":[
  {"key":"initial","scenarioId":"s-a","policy":{"shouldBlock":true,"source":"baseline"}},
  {"key":"exec","scenarioId":"s-b","requires":["initial"]}]}`

// killChainCall runs one handler with the chi route parameter set, the same way
// the router would. id is empty for routes without one.
func killChainCall(h *Handler, method, path, id, body string) *httptest.ResponseRecorder {
	if method == http.MethodPost && !strings.HasSuffix(path, "/advance") {
		body = signedEnvelope(body)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	switch {
	case method == http.MethodPost && strings.HasSuffix(path, "/advance"):
		h.AdvanceKillChainCampaign(rec, req)
	case method == http.MethodPost:
		h.CreateKillChainCampaign(rec, req)
	case id != "":
		h.GetKillChainCampaign(rec, req)
	default:
		h.ListKillChainCampaigns(rec, req)
	}
	return rec
}

func TestKillChainAPI_WithoutDatabaseIs503(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	if rec := killChainCall(h, http.MethodPost, "/api/killchain/campaigns", "", killChainTestDef); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestKillChainAPI_CreateValidateAdvanceAndRead(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)

		if rec := killChainCall(h, http.MethodPost, "/api/killchain/campaigns", "", killChainTestDef); rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
		if rec := killChainCall(h, http.MethodPost, "/api/killchain/campaigns", "", killChainTestDef); rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create = %d, want 409", rec.Code)
		}

		cycle := `{"id":"kc-api-cycle","name":"x","version":1,"stages":[
		  {"key":"a","scenarioId":"s","requires":["b"]},{"key":"b","scenarioId":"s","requires":["a"]}]}`
		if rec := killChainCall(h, http.MethodPost, "/api/killchain/campaigns", "", cycle); rec.Code != http.StatusBadRequest {
			t.Fatalf("cycle = %d, want 400", rec.Code)
		}
		unknown := strings.Replace(killChainTestDef, `"name":"API chain"`, `"name":"API chain","surprise":1`, 1)
		if rec := killChainCall(h, http.MethodPost, "/api/killchain/campaigns", "", unknown); rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown field = %d, want 400", rec.Code)
		}

		if rec := killChainCall(h, http.MethodPost, "/api/killchain/campaigns/kc-api-1/advance", "kc-api-1", ""); rec.Code != http.StatusOK {
			t.Fatalf("advance = %d: %s", rec.Code, rec.Body.String())
		}
		get := killChainCall(h, http.MethodGet, "/api/killchain/campaigns/kc-api-1", "kc-api-1", "")
		if get.Code != http.StatusOK {
			t.Fatalf("get = %d", get.Code)
		}
		var view struct {
			Stages []struct {
				Key     string   `json:"key"`
				Verdict string   `json:"verdict"`
				Reasons []string `json:"reasons"`
			} `json:"stages"`
			Rollup struct {
				Status string `json:"status"`
				Failed bool   `json:"failed"`
			} `json:"rollup"`
		}
		if err := json.Unmarshal(get.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if len(view.Stages) != 2 || view.Stages[0].Key != "initial" {
			t.Fatalf("stages not in topological order: %+v", view.Stages)
		}
		if view.Stages[0].Verdict != "ERROR" || !strings.Contains(strings.Join(view.Stages[0].Reasons, " "), "not executable") {
			t.Fatalf("unwired stage must be ERROR with a reason, got %+v", view.Stages[0])
		}
		if view.Stages[1].Verdict != "NOT_TESTED" {
			t.Fatalf("downstream after ERROR = %s, want NOT_TESTED", view.Stages[1].Verdict)
		}
		if view.Rollup.Status != "failed" || !view.Rollup.Failed {
			t.Fatalf("rollup = %+v, want failed", view.Rollup)
		}
	})
}

func TestKillChainAPI_UnknownCampaignIs404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		if rec := killChainCall(h, http.MethodGet, "/api/killchain/campaigns/missing-one", "missing-one", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
