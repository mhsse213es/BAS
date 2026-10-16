package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/emailgwcampaign"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func triggerEmailGWCampaignReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("emailgwcampaign-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/emailgw-campaigns", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestTriggerEmailGWCampaignHandler_NotConfigured_Returns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := triggerEmailGWCampaignReq(t, pool, map[string]any{"templateId": emailgwcampaign.BECSupplierFraudCampaignID})
		rec := callAuthed(h.TriggerEmailGWCampaign, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusServiceUnavailable)
		}
	})
}

func TestTriggerEmailGWCampaignHandler_MissingTemplateID_Returns400(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWCampaignReq(t, pool, map[string]any{})
		rec := callAuthed(h.TriggerEmailGWCampaign, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusBadRequest)
		}
	})
}

func TestTriggerEmailGWCampaignHandler_UnknownTemplateID_Returns400(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWCampaignReq(t, pool, map[string]any{"templateId": "no-such-template"})
		rec := callAuthed(h.TriggerEmailGWCampaign, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusBadRequest)
		}
	})
}

func TestTriggerEmailGWCampaignHandler_Success_Returns201AndDispatchesFirstStage(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWCampaignReq(t, pool, map[string]any{"templateId": emailgwcampaign.BECSupplierFraudCampaignID})
		rec := callAuthed(h.TriggerEmailGWCampaign, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusCreated)
		}
		var campaign emailgwcampaign.Campaign
		if err := json.Unmarshal(rec.Body.Bytes(), &campaign); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if campaign.ID == "" || campaign.Status != emailgwcampaign.CampaignRunning {
			t.Errorf("campaign = %+v, want a non-empty id and status=running", campaign)
		}
	})
}

func TestGetEmailGWCampaignHandler_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, fmt.Sprintf("emailgwcampaign-reader-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodGet, "/api/emailgw-campaigns/no-such-id", nil, auth.RoleAnalyst, userID)
		rec := callAuthed(h.GetEmailGWCampaign, withURLParam(req, "id", "no-such-id"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusNotFound)
		}
	})
}

func TestGetEmailGWCampaignHandler_ReturnsStagesAndRollup(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWCampaignReq(t, pool, map[string]any{"templateId": emailgwcampaign.BECSupplierFraudCampaignID})
		rec := callAuthed(h.TriggerEmailGWCampaign, req)
		var created emailgwcampaign.Campaign
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create response: %v", err)
		}

		userID := seedUser(t, pool, fmt.Sprintf("emailgwcampaign-reader2-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
		getReq := authedRequest(t, http.MethodGet, "/api/emailgw-campaigns/"+created.ID, nil, auth.RoleAnalyst, userID)
		getRec := callAuthed(h.GetEmailGWCampaign, withURLParam(getReq, "id", created.ID))
		if getRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want %d", getRec.Code, getRec.Body.String(), http.StatusOK)
		}
		var view EmailGWCampaignView
		if err := json.Unmarshal(getRec.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(view.Stages) != 1 {
			t.Fatalf("len(Stages) = %d, want 1 (only identity-probe dispatched so far)", len(view.Stages))
		}
		if view.Stages[0].Run == nil {
			t.Error("Stages[0].Run is nil, want the inlined underlying run")
		}
		if view.Rollup.TotalStages != 1 || view.Rollup.Dispatched != 1 {
			t.Errorf("Rollup = %+v, want TotalStages=1 Dispatched=1", view.Rollup)
		}
	})
}

func TestListEmailGWCampaignsHandler_ReturnsCreatedCampaigns(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWCampaignReq(t, pool, map[string]any{"templateId": emailgwcampaign.BECSupplierFraudCampaignID})
		callAuthed(h.TriggerEmailGWCampaign, req)

		userID := seedUser(t, pool, fmt.Sprintf("emailgwcampaign-lister-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
		listReq := authedRequest(t, http.MethodGet, "/api/emailgw-campaigns", nil, auth.RoleAnalyst, userID)
		rec := callAuthed(h.ListEmailGWCampaigns, listReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusOK)
		}
		var campaigns []emailgwcampaign.Campaign
		if err := json.Unmarshal(rec.Body.Bytes(), &campaigns); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(campaigns) < 1 {
			t.Error("want at least the just-created campaign")
		}
	})
}

func TestCancelEmailGWCampaignHandler_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, fmt.Sprintf("emailgwcampaign-canceller-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/emailgw-campaigns/no-such-id/cancel", nil, auth.RoleAnalyst, userID)
		rec := callAuthed(h.CancelEmailGWCampaignHandler, withURLParam(req, "id", "no-such-id"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusNotFound)
		}
	})
}

func TestCancelEmailGWCampaignHandler_Success_SetsCancelling(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		createReq := triggerEmailGWCampaignReq(t, pool, map[string]any{"templateId": emailgwcampaign.BECSupplierFraudCampaignID})
		createRec := callAuthed(h.TriggerEmailGWCampaign, createReq)
		var created emailgwcampaign.Campaign
		json.Unmarshal(createRec.Body.Bytes(), &created)

		userID := seedUser(t, pool, fmt.Sprintf("emailgwcampaign-canceller2-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
		cancelReq := authedRequest(t, http.MethodPost, "/api/emailgw-campaigns/"+created.ID+"/cancel", nil, auth.RoleAnalyst, userID)
		rec := callAuthed(h.CancelEmailGWCampaignHandler, withURLParam(cancelReq, "id", created.ID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusOK)
		}
		var campaign emailgwcampaign.Campaign
		if err := json.Unmarshal(rec.Body.Bytes(), &campaign); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if campaign.Status != emailgwcampaign.CampaignCancelling {
			t.Errorf("Status = %q, want %q", campaign.Status, emailgwcampaign.CampaignCancelling)
		}
	})
}
