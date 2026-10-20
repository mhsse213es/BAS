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

// The creator cannot also approve lab stages.
func TestSeparationOfDuties_CreatorCannotApproveLab(t *testing.T) {
	err := checkCampaignApproval(labCampaignDef(), fullApproval(), "alice", "alice")
	if err == nil || !strings.Contains(err.Error(), "different user") {
		t.Fatalf("err = %v, want a refusal naming the separation of duties", err)
	}
}

// A second user may approve the lab stages.
func TestSeparationOfDuties_OtherUserCanApproveLab(t *testing.T) {
	if err := checkCampaignApproval(labCampaignDef(), fullApproval(), "bob", "alice"); err != nil {
		t.Fatalf("a different approver was refused: %v", err)
	}
}

// If the approver cannot be identified, the lab approval is refused. It is not allowed by default.
func TestSeparationOfDuties_UnidentifiedApproverRefused(t *testing.T) {
	err := checkCampaignApproval(labCampaignDef(), fullApproval(), "", "alice")
	if err == nil || !strings.Contains(err.Error(), "identify") {
		t.Fatalf("err = %v, want a refusal because the approver is unknown", err)
	}
}

// The rule applies to lab stages only. A live (telemetry) campaign is approved by the creator.
func TestSeparationOfDuties_TelemetryNotAffected(t *testing.T) {
	def := killchain.CampaignDef{ID: "tel", Version: 1, Stages: []killchain.StageDef{
		{Key: "x", ScenarioID: "credential-access", Mode: killchain.ModeTelemetry},
	}}
	if err := checkCampaignApproval(def, advanceApproval{ConfirmLive: true, Reason: "CHG-2"}, "alice", "alice"); err != nil {
		t.Fatalf("telemetry approved by its creator was refused: %v", err)
	}
}

// Posture campaigns need no approver at all.
func TestSeparationOfDuties_PostureNeedsNoApprover(t *testing.T) {
	def := killchain.CampaignDef{ID: "p", Version: 1, Stages: []killchain.StageDef{{Key: "x", ScenarioID: "s"}}}
	if err := checkCampaignApproval(def, advanceApproval{}, "", "alice"); err != nil {
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

// Through the handler: the campaign's creator is refused for a lab campaign, and a
// different user passes the approval check.
func TestSeparationOfDuties_HandlerRefusesCreator(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		def := labCampaignDef()
		def.ID = "sod-handler-1"
		if err := (db.KillChainStore{Pool: pool}).CreateCampaign(context.Background(), def, "owner-1", ""); err != nil {
			t.Fatal(err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := `{"confirmLive":true,"confirmLab":true,"reason":"CHG-9"}`

		rec := advanceAs(h, def.ID, body, "owner-1")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "different user") {
			t.Fatalf("creator approval: status=%d body=%s", rec.Code, rec.Body.String())
		}
		rec = advanceAs(h, def.ID, body, "approver-2")
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("a different approver was refused at the approval check: %s", rec.Body.String())
		}
	})
}
