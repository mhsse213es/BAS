package api

import (
	"encoding/json"
	"net/http"
	"slices"
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

func TestEmailGWInjectionGaps_MatchesExecuteEmailGWRunsOwnCheck(t *testing.T) {
	gaps := emailGWInjectionGaps()

	// EG-002.known-bad is one of the genuinely wired IDs (confirmed in
	// the QA log) -- must never appear as a gap.
	if slices.Contains(gaps, "EG-002.known-bad") {
		t.Errorf("gaps = %v, want EG-002.known-bad absent (it is genuinely wired)", gaps)
	}
	// EG-006 (OutboundDLPExpectation) is wired via OutboundSenderMailbox,
	// not EnvelopeFrom -- must never be misreported as a gap just
	// because its EnvelopeFrom happens to be empty.
	if slices.Contains(gaps, "EG-006.known-good") || slices.Contains(gaps, "EG-006.known-bad") {
		t.Errorf("gaps = %v, want EG-006.known-good/known-bad absent (wired via OutboundSenderMailbox)", gaps)
	}
	// EG-007's IDs are not a MailExpectation at all (inbox-rule-based) --
	// must appear as a gap via the !ok branch, not silently skipped.
	foundEG007 := false
	for _, g := range gaps {
		if len(g) >= 6 && g[:6] == "EG-007" {
			foundEG007 = true
		}
	}
	if !foundEG007 {
		t.Errorf("gaps = %v, want at least one EG-007 id present", gaps)
	}
	// Every returned gap must independently satisfy the same condition
	// ExecuteEmailGWRun itself checks -- never a drive-by hand-written
	// list that could drift from the real runtime behavior.
	for _, id := range gaps {
		exp, ok := emailgwefficacy.ExpectationByID(id)
		if ok && (exp.EnvelopeFrom != "" || exp.OutboundSenderMailbox != "") {
			t.Errorf("gap id %q actually resolves with a non-empty EnvelopeFrom or OutboundSenderMailbox -- not a real gap", id)
		}
	}
}

func TestBuildEmailGWCampaignOutcomeCounts(t *testing.T) {
	campaigns := []*emailgwcampaign.Campaign{
		{ID: "c1", TemplateID: "bec-supplier-fraud", Status: emailgwcampaign.CampaignCompleted},
		{ID: "c2", TemplateID: "bec-supplier-fraud", Status: emailgwcampaign.CampaignRunning},
		{ID: "c3", TemplateID: "other-template", Status: emailgwcampaign.CampaignFailed},
	}
	got := buildEmailGWCampaignOutcomeCounts(campaigns)
	if got.Total != 3 {
		t.Fatalf("Total = %d, want 3", got.Total)
	}
	if got.ByTemplateID["bec-supplier-fraud"] != 2 || got.ByTemplateID["other-template"] != 1 {
		t.Errorf("ByTemplateID = %+v, want bec-supplier-fraud:2 other-template:1", got.ByTemplateID)
	}
	if got.ByStatus[string(emailgwcampaign.CampaignCompleted)] != 1 || got.ByStatus[string(emailgwcampaign.CampaignRunning)] != 1 {
		t.Errorf("ByStatus = %+v, want completed:1 running:1", got.ByStatus)
	}
}

func TestLatestStartedAt_EmptyInput_ReturnsNil(t *testing.T) {
	if got := latestStartedAt(nil); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestLatestStartedAt_PicksMostRecentNotListOrder(t *testing.T) {
	older := time.Now().UTC().Add(-time.Hour)
	newer := time.Now().UTC()
	runs := []*emailgwrun.EmailGWRun{
		{ID: "a", StartedAt: newer},
		{ID: "b", StartedAt: older},
	}
	got := latestStartedAt(runs)
	if got == nil || !got.Equal(newer) {
		t.Fatalf("got %v, want %v", got, newer)
	}
}

func TestGetEmailGWReport_ComposesRealDataEndToEnd(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)

		triggerReq := triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-002.known-bad"})
		triggerRec := callAuthed(h.TriggerEmailGWRun, triggerReq)
		if triggerRec.Code != http.StatusCreated {
			t.Fatalf("trigger status = %d, body = %s", triggerRec.Code, triggerRec.Body.String())
		}

		req := authedRequest(t, http.MethodGet, "/api/emailgw/report", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := callAuthed(h.GetEmailGWReport, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var got EmailGWUnifiedReport
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Coverage.Summary == "" {
			t.Error("Coverage.Summary is empty, want the real coverage summary text")
		}
		if got.RunsSummary.Total < 1 {
			t.Errorf("RunsSummary.Total = %d, want at least 1 (the just-triggered run)", got.RunsSummary.Total)
		}
		if got.Metrics.Lab.RunsConsidered < 1 {
			t.Errorf("Metrics.Lab.RunsConsidered = %d, want at least 1", got.Metrics.Lab.RunsConsidered)
		}
		if got.LastExecutionAt == nil {
			t.Error("LastExecutionAt is nil, want the just-triggered run's StartedAt")
		}
		if len(got.InjectionGaps) == 0 {
			t.Error("InjectionGaps is empty, want the known-unwired scenario IDs to show up")
		}
		if got.MaturityNote == "" {
			t.Error("MaturityNote is empty, want an explicit note on the omitted axis")
		}
	})
}

