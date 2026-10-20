package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func approvalCampaign(t *testing.T, pool *pgxpool.Pool, id, mode string) {
	t.Helper()
	def := killchain.CampaignDef{ID: id, Name: id, Version: 1, Stages: []killchain.StageDef{
		{Key: "identity", ScenarioID: "credential-access", Mode: mode},
	}}
	if err := (db.KillChainStore{Pool: pool}).CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
		t.Fatal(err)
	}
}

func advance(h *Handler, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/killchain/campaigns/"+id+"/advance", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.AdvanceKillChainCampaign(rec, req)
	return rec
}

// A campaign with a live stage cannot advance without the operator's confirmation.
func TestApproval_LiveCampaignNeedsConfirmLive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		approvalCampaign(t, pool, "appr-live-1", "telemetry")
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := advance(h, "appr-live-1", "")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "confirmLive") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// Approval must carry a reason, so the record says why the live stages were approved.
func TestApproval_LiveCampaignNeedsReason(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		approvalCampaign(t, pool, "appr-live-2", "telemetry")
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := advance(h, "appr-live-2", `{"confirmLive":true}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reason") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// A lab stage needs confirmLab on top of confirmLive.
func TestApproval_LabCampaignNeedsConfirmLab(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		approvalCampaign(t, pool, "appr-lab-1", "lab")
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := advance(h, "appr-lab-1", `{"confirmLive":true,"reason":"CHG-1"}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "confirmLab") {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// A posture campaign needs no approval, and advances without a body as before.
func TestApproval_PostureCampaignNeedsNoApproval(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		approvalCampaign(t, pool, "appr-post-1", "posture")
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := advance(h, "appr-post-1", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// An unknown field in the approval body is refused, so a typo cannot silently drop
// the confirmation.
func TestApproval_UnknownFieldRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		approvalCampaign(t, pool, "appr-typo-1", "posture")
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := advance(h, "appr-typo-1", `{"confirmLiv":true}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}
