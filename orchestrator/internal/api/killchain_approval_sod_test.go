package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func labCampaignDef() killchain.CampaignDef {
	return killchain.CampaignDef{ID: "sod", Version: 1, Stages: []killchain.StageDef{
		{Key: "lat", ScenarioID: "caldera-lateral-movement", Mode: killchain.ModeLab},
	}}
}

func fullApproval() advanceApproval {
	return advanceApproval{ConfirmLive: true, ConfirmLab: true, Reason: "CHG-1"}
}

// A single-person lab team may approve its own lab stages. The audit records both.
func TestLabSelfApproval_CreatorMayApproveLab(t *testing.T) {
	if err := checkCampaignApproval(labCampaignDef(), fullApproval(), "alice"); err != nil {
		t.Fatalf("creator self-approval refused: %v", err)
	}
}

// Lab stages still need an identified approver.
func TestLabSelfApproval_UnidentifiedApproverRefused(t *testing.T) {
	err := checkCampaignApproval(labCampaignDef(), fullApproval(), "")
	if err == nil || !strings.Contains(err.Error(), "identify") {
		t.Fatalf("err = %v, want a refusal because the approver is unknown", err)
	}
}

// Telemetry approval is not affected by the lab rule.
func TestLabSelfApproval_TelemetryNotAffected(t *testing.T) {
	def := killchain.CampaignDef{ID: "tel", Version: 1, Stages: []killchain.StageDef{
		{Key: "x", ScenarioID: "credential-access", Mode: killchain.ModeTelemetry},
	}}
	if err := checkCampaignApproval(def, advanceApproval{ConfirmLive: true, Reason: "CHG-2"}, "alice"); err != nil {
		t.Fatalf("telemetry approval refused: %v", err)
	}
}

// Posture campaigns need no approver at all.
func TestLabSelfApproval_PostureNeedsNoApprover(t *testing.T) {
	def := killchain.CampaignDef{ID: "p", Version: 1, Stages: []killchain.StageDef{{Key: "x", ScenarioID: "s"}}}
	if err := checkCampaignApproval(def, advanceApproval{}, ""); err != nil {
		t.Fatalf("posture refused: %v", err)
	}
}

// advanceAs sends the advance request with the given user's identity in the context.
func advanceAs(h *Handler, id, body, userID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/killchain/campaigns/"+id+"/advance", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = auth.ContextWithClaims(ctx, &auth.Claims{UserID: userID})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.AdvanceKillChainCampaign(rec, req)
	return rec
}

// Through the handler: the creator's lab approval is not refused by the approval check.
func TestLabSelfApproval_HandlerAllowsCreator(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		def := labCampaignDef()
		def.ID = "sod-handler-1"
		if err := (db.KillChainStore{Pool: pool}).CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := advanceAs(h, def.ID, `{"confirmLive":true,"confirmLab":true,"reason":"CHG-9"}`, "owner-1")
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("creator self-approval refused at the approval check: %s", rec.Body.String())
		}
	})
}
