package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwcampaign"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

// TestEmailGWCampaignGateStringsMatchEmailGWEfficacyVerdicts guards
// against drift: internal/emailgwcampaign can't import
// emailgwefficacy (see that package's own comment), so its BEC
// template duplicates "confirmed-failure" as a raw string literal.
// This proves that literal still equals emailgwefficacy's own
// VerdictConfirmedFailure value.
func TestEmailGWCampaignGateStringsMatchEmailGWEfficacyVerdicts(t *testing.T) {
	tmpl := emailgwcampaign.BECSupplierFraudTemplate()
	stage, ok := tmpl.StageByKey("fraud-payload")
	if !ok || stage.Gate == nil {
		t.Fatal("fraud-payload stage or its gate not found")
	}
	if len(stage.Gate.PermittedVerdicts) != 1 || stage.Gate.PermittedVerdicts[0] != string(emailgwefficacy.VerdictConfirmedFailure) {
		t.Errorf("PermittedVerdicts = %v, want exactly [%q]", stage.Gate.PermittedVerdicts, emailgwefficacy.VerdictConfirmedFailure)
	}
}

func marshalResult(t *testing.T, r emailgwefficacy.EfficacyResult) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return b
}

// insertTerminalRun inserts a standalone email_gw_runs row already at
// a terminal status with the given result -- the same shape
// finishEmailGWRunAfterWindow itself would have written, but without
// waiting out a real dwell window. Used throughout this file to drive
// campaign sequencing deterministically.
func insertTerminalRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, scenarioID string, status emailgwrun.Status, result json.RawMessage) {
	t.Helper()
	run := &emailgwrun.EmailGWRun{ID: id, ScenarioID: scenarioID, Status: emailgwrun.StatusRunning, StartedAt: time.Now().UTC()}
	if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
		t.Fatalf("insert run %s: %v", id, err)
	}
	if err := db.UpdateEmailGWRunStatus(ctx, pool, id, status, result, "", time.Now().UTC()); err != nil {
		t.Fatalf("update run %s status: %v", id, err)
	}
}

func stageByKey(t *testing.T, stages []*emailgwcampaign.CampaignStage, key string) *emailgwcampaign.CampaignStage {
	t.Helper()
	for _, s := range stages {
		if s.StageKey == key {
			return s
		}
	}
	t.Fatalf("no stage with key %q among %d stages", key, len(stages))
	return nil
}

// ── evaluateGateBlock: the three explicitly distinct branches ──────────────

func TestEvaluateGateBlock_UpstreamNotFound_Blocks(t *testing.T) {
	gate := &emailgwcampaign.GateCondition{UpstreamStageKey: "missing", UpstreamDimension: emailgwcampaign.DimensionPrevention, PermittedVerdicts: []string{"confirmed-failure"}}
	reason, blocked := evaluateGateBlock(context.Background(), nil, nil, false, gate)
	if !blocked || reason == "" {
		t.Fatalf("blocked=%v reason=%q, want blocked with a reason", blocked, reason)
	}
}

func TestEvaluateGateBlock_UpstreamNeverExecuted_Blocks(t *testing.T) {
	upstream := &emailgwcampaign.CampaignStage{StageKey: "identity-probe", Status: emailgwcampaign.StageBlockedByPrerequisite, BlockedReason: "some upstream reason"}
	gate := &emailgwcampaign.GateCondition{UpstreamStageKey: "identity-probe", UpstreamDimension: emailgwcampaign.DimensionPrevention, PermittedVerdicts: []string{"confirmed-failure"}}
	reason, blocked := evaluateGateBlock(context.Background(), nil, upstream, true, gate)
	if !blocked {
		t.Fatal("want blocked=true when upstream never ran")
	}
	if reason == "" {
		t.Error("want a non-empty reason citing the upstream's own block reason")
	}
}

func TestEvaluateGateBlock_ConfirmedPermittedVerdict_DoesNotBlock(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insertTerminalRun(t, ctx, pool, "gate-permit-run-1", "EG-002.known-good", emailgwrun.StatusCompleted,
			marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}}))
		runID := "gate-permit-run-1"
		upstream := &emailgwcampaign.CampaignStage{StageKey: "identity-probe", Status: emailgwcampaign.StageCompleted, RunID: &runID}
		gate := &emailgwcampaign.GateCondition{UpstreamStageKey: "identity-probe", UpstreamDimension: emailgwcampaign.DimensionPrevention, PermittedVerdicts: []string{string(emailgwefficacy.VerdictConfirmedFailure)}}

		reason, blocked := evaluateGateBlock(ctx, pool, upstream, true, gate)
		if blocked {
			t.Fatalf("want blocked=false for a permitted verdict, got blocked with reason %q", reason)
		}
	})
}

func TestEvaluateGateBlock_ConfirmedNonPermittedVerdict_BlocksWithVerdictReason(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insertTerminalRun(t, ctx, pool, "gate-block-success-1", "EG-002.known-good", emailgwrun.StatusCompleted,
			marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess}}))
		runID := "gate-block-success-1"
		upstream := &emailgwcampaign.CampaignStage{StageKey: "identity-probe", Status: emailgwcampaign.StageCompleted, RunID: &runID}
		gate := &emailgwcampaign.GateCondition{UpstreamStageKey: "identity-probe", UpstreamDimension: emailgwcampaign.DimensionPrevention, PermittedVerdicts: []string{string(emailgwefficacy.VerdictConfirmedFailure)}}

		reason, blocked := evaluateGateBlock(ctx, pool, upstream, true, gate)
		if !blocked {
			t.Fatal("want blocked=true: confirmed-success is not in PermittedVerdicts")
		}
		if reason == "" {
			t.Error("want a non-empty reason naming the actual verdict")
		}
	})
}

func TestEvaluateGateBlock_Inconclusive_BlocksWithDistinctReason(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insertTerminalRun(t, ctx, pool, "gate-block-inconclusive-1", "EG-002.known-good", emailgwrun.StatusPartial,
			marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive, Reason: "no evidence"}}))
		runID := "gate-block-inconclusive-1"
		upstream := &emailgwcampaign.CampaignStage{StageKey: "identity-probe", Status: emailgwcampaign.StageCompleted, RunID: &runID}
		gate := &emailgwcampaign.GateCondition{UpstreamStageKey: "identity-probe", UpstreamDimension: emailgwcampaign.DimensionPrevention, PermittedVerdicts: []string{string(emailgwefficacy.VerdictConfirmedFailure)}}

		inconclusiveReason, blocked := evaluateGateBlock(ctx, pool, upstream, true, gate)
		if !blocked {
			t.Fatal("want blocked=true for Inconclusive")
		}
		if inconclusiveReason == "" {
			t.Fatal("want a reason")
		}

		// Confirm this is a genuinely distinct branch from the
		// confirmed-non-permitted case (TestEvaluateGateBlock_ConfirmedNonPermittedVerdict_BlocksWithVerdictReason),
		// not the same undifferentiated check -- the reason text for
		// an indeterminate upstream outcome must read differently
		// from the reason text for a definite, non-permitted verdict.
		insertTerminalRun(t, ctx, pool, "gate-block-inconclusive-compare-1", "EG-002.known-good", emailgwrun.StatusCompleted,
			marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess}}))
		compareRunID := "gate-block-inconclusive-compare-1"
		confirmedUpstream := &emailgwcampaign.CampaignStage{StageKey: "identity-probe", Status: emailgwcampaign.StageCompleted, RunID: &compareRunID}
		confirmedReason, _ := evaluateGateBlock(ctx, pool, confirmedUpstream, true, gate)
		if inconclusiveReason == confirmedReason {
			t.Errorf("inconclusive reason and confirmed-non-permitted reason are identical (%q) -- must be distinct branches", inconclusiveReason)
		}
	})
}

func TestEvaluateGateBlock_MissingEvidence_BlocksWithUndecodableReason(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insertTerminalRun(t, ctx, pool, "gate-block-missing-1", "EG-002.known-good", emailgwrun.StatusCompleted, nil)
		runID := "gate-block-missing-1"
		upstream := &emailgwcampaign.CampaignStage{StageKey: "identity-probe", Status: emailgwcampaign.StageCompleted, RunID: &runID}
		gate := &emailgwcampaign.GateCondition{UpstreamStageKey: "identity-probe", UpstreamDimension: emailgwcampaign.DimensionPrevention, PermittedVerdicts: []string{string(emailgwefficacy.VerdictConfirmedFailure)}}

		reason, blocked := evaluateGateBlock(ctx, pool, upstream, true, gate)
		if !blocked || reason == "" {
			t.Fatalf("blocked=%v reason=%q, want blocked with a reason for undecodable/missing evidence", blocked, reason)
		}
	})
}

// ── Full sequencing: trigger, gate, derived stages, finalize ───────────────

func triggerBECCampaign(t *testing.T, ctx context.Context, pool *pgxpool.Pool, target emailgwefficacy.InjectionTarget) *emailgwcampaign.Campaign {
	t.Helper()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)
	campaign, err := TriggerEmailGWCampaign(ctx, pool, provider, target, emailgwrun.EnvironmentLab, emailgwcampaign.BECSupplierFraudCampaignID, "tester")
	if err != nil {
		t.Fatalf("TriggerEmailGWCampaign: %v", err)
	}
	return campaign
}

func TestTriggerEmailGWCampaign_UnknownTemplateID_ReturnsError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := TriggerEmailGWCampaign(context.Background(), pool, emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil),
			emailgwefficacy.InjectionTarget{}, emailgwrun.EnvironmentLab, "no-such-template", "tester")
		if err == nil {
			t.Fatal("want an error for an unknown template id")
		}
	})
}

func TestAdvanceEmailGWCampaign_StageOneDelivered_PermitsStageTwo_DerivedStagesComplete(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign := triggerBECCampaign(t, ctx, pool, target)

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		if len(stages) != 1 {
			t.Fatalf("len(stages) = %d, want 1 (only identity-probe dispatched so far)", len(stages))
		}
		stage1 := stageByKey(t, stages, "identity-probe")
		if stage1.Status != emailgwcampaign.StageDispatched || stage1.RunID == nil {
			t.Fatalf("stage1 = %+v, want StageDispatched with a real RunID", stage1)
		}

		// Simulate stage 1 finishing: the impersonation probe was
		// delivered (ConfirmedFailure) -- the one verdict BEC's own
		// gate permits.
		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}})
		if err := db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusCompleted, result1, "", time.Now().UTC()); err != nil {
			t.Fatalf("update stage1 run: %v", err)
		}
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage1.RunID)

		stages, err = db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages after stage1: %v", err)
		}
		if len(stages) != 2 {
			t.Fatalf("len(stages) = %d, want 2 (fraud-payload now dispatched)", len(stages))
		}
		stage2 := stageByKey(t, stages, "fraud-payload")
		if stage2.Status != emailgwcampaign.StageDispatched || stage2.RunID == nil {
			t.Fatalf("stage2 = %+v, want StageDispatched with a real RunID", stage2)
		}

		// Simulate stage 2 finishing: caught at delivery (confirmed-success),
		// detection confirmed, response inconclusive -- an honest partial.
		result2 := marshalResult(t, emailgwefficacy.EfficacyResult{
			Prevention:       emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
			DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
			ResponseVerdict:  emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive, Reason: "no remediation evidence"},
		})
		if err := db.UpdateEmailGWRunStatus(ctx, pool, *stage2.RunID, emailgwrun.StatusPartial, result2, "", time.Now().UTC()); err != nil {
			t.Fatalf("update stage2 run: %v", err)
		}
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage2.RunID)

		stages, err = db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages after stage2: %v", err)
		}
		if len(stages) != 4 {
			t.Fatalf("len(stages) = %d, want 4 (both derived stages now resolved)", len(stages))
		}
		detectionStage := stageByKey(t, stages, "detection-check")
		responseStage := stageByKey(t, stages, "response-check")
		if detectionStage.Status != emailgwcampaign.StageCompleted || detectionStage.RunID != nil {
			t.Errorf("detection-check = %+v, want StageCompleted with a nil RunID (derived, no run of its own)", detectionStage)
		}
		if responseStage.Status != emailgwcampaign.StageCompleted || responseStage.RunID != nil {
			t.Errorf("response-check = %+v, want StageCompleted with a nil RunID", responseStage)
		}

		final, err := db.GetEmailGWCampaign(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("get campaign: %v", err)
		}
		if final.Status != emailgwcampaign.CampaignCompleted {
			t.Errorf("campaign status = %q, want %q (no stage failed/blocked/cancelled, even though stage2's own run was partial)", final.Status, emailgwcampaign.CampaignCompleted)
		}
	})
}

// TestAdvanceEmailGWCampaign_CredentialPhishingURLChain_HappyPath_RealScenarioIDsDispatch
// proves the SECOND real campaign template -- not just BEC -- wires
// through the real engine end to end: its own ExpectationID strings
// actually resolve to real EG-003 scenarios (a typo here would surface
// as StageFailed/retry exhaustion, not a silently-wrong dispatch), its
// own gate permits progression on the same ConfirmedFailure verdict
// BEC's gate uses, and its derived stages resolve off the SECOND
// stage, not the first -- the one detail genuinely specific to this
// template that the engine's existing BEC-only tests can't catch.
func TestAdvanceEmailGWCampaign_CredentialPhishingURLChain_HappyPath_RealScenarioIDsDispatch(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign, err := TriggerEmailGWCampaign(ctx, pool, provider, target, emailgwrun.EnvironmentLab, emailgwcampaign.CredentialPhishingURLChainCampaignID, "tester")
		if err != nil {
			t.Fatalf("TriggerEmailGWCampaign: %v", err)
		}

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		if len(stages) != 1 {
			t.Fatalf("len(stages) = %d, want 1 (only initial-lure dispatched so far)", len(stages))
		}
		stage1 := stageByKey(t, stages, "initial-lure")
		if stage1.Status != emailgwcampaign.StageDispatched || stage1.RunID == nil {
			t.Fatalf("stage1 = %+v, want StageDispatched with a real RunID", stage1)
		}
		run1, err := db.GetEmailGWRun(ctx, pool, *stage1.RunID)
		if err != nil {
			t.Fatalf("get run1: %v", err)
		}
		if run1.ScenarioID != "EG-003.credential-url.known-good" {
			t.Errorf("run1.ScenarioID = %q, want %q", run1.ScenarioID, "EG-003.credential-url.known-good")
		}

		// Stage 1: the static lure reached the target uninspected --
		// the one verdict this template's own gate permits.
		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}})
		if err := db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusCompleted, result1, "", time.Now().UTC()); err != nil {
			t.Fatalf("update stage1 run: %v", err)
		}
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage1.RunID)

		stages, err = db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages after stage1: %v", err)
		}
		if len(stages) != 2 {
			t.Fatalf("len(stages) = %d, want 2 (click-time-bypass-probe now dispatched)", len(stages))
		}
		stage2 := stageByKey(t, stages, "click-time-bypass-probe")
		if stage2.Status != emailgwcampaign.StageDispatched || stage2.RunID == nil {
			t.Fatalf("stage2 = %+v, want StageDispatched with a real RunID", stage2)
		}
		run2, err := db.GetEmailGWRun(ctx, pool, *stage2.RunID)
		if err != nil {
			t.Fatalf("get run2: %v", err)
		}
		if run2.ScenarioID != "EG-003.url-rewrite.known-bad" {
			t.Errorf("run2.ScenarioID = %q, want %q", run2.ScenarioID, "EG-003.url-rewrite.known-bad")
		}

		// Stage 2: the bad-reputation URL WAS caught by click-time
		// re-evaluation (confirmed-success), detection and response
		// both confirmed -- an honest full pass through the second
		// control layer.
		result2 := marshalResult(t, emailgwefficacy.EfficacyResult{
			Prevention:       emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
			DetectionVerdict: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
			ResponseVerdict:  emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess},
		})
		if err := db.UpdateEmailGWRunStatus(ctx, pool, *stage2.RunID, emailgwrun.StatusCompleted, result2, "", time.Now().UTC()); err != nil {
			t.Fatalf("update stage2 run: %v", err)
		}
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage2.RunID)

		stages, err = db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages after stage2: %v", err)
		}
		if len(stages) != 4 {
			t.Fatalf("len(stages) = %d, want 4 (both derived stages now resolved)", len(stages))
		}
		detectionStage := stageByKey(t, stages, "detection-check")
		responseStage := stageByKey(t, stages, "response-check")
		if detectionStage.Status != emailgwcampaign.StageCompleted || detectionStage.RunID != nil {
			t.Errorf("detection-check = %+v, want StageCompleted with a nil RunID (derived, reads stage 2, not stage 1)", detectionStage)
		}
		if responseStage.Status != emailgwcampaign.StageCompleted || responseStage.RunID != nil {
			t.Errorf("response-check = %+v, want StageCompleted with a nil RunID", responseStage)
		}

		final, err := db.GetEmailGWCampaign(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("get campaign: %v", err)
		}
		if final.Status != emailgwcampaign.CampaignCompleted {
			t.Errorf("campaign status = %q, want %q", final.Status, emailgwcampaign.CampaignCompleted)
		}
	})
}

func TestAdvanceEmailGWCampaign_StageOneBlocked_CascadesBlockThroughAllDownstream(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign := triggerBECCampaign(t, ctx, pool, target)
		stages, _ := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		stage1 := stageByKey(t, stages, "identity-probe")

		// Stage 1 was blocked (confirmed-success): the pretext never
		// reached the target.
		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedSuccess}})
		db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusCompleted, result1, "", time.Now().UTC())
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage1.RunID)

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		if len(stages) != 4 {
			t.Fatalf("len(stages) = %d, want 4 (all three downstream stages cascade-blocked in one pass)", len(stages))
		}
		for _, key := range []string{"fraud-payload", "detection-check", "response-check"} {
			s := stageByKey(t, stages, key)
			if s.Status != emailgwcampaign.StageBlockedByPrerequisite {
				t.Errorf("stage %q status = %q, want %q", key, s.Status, emailgwcampaign.StageBlockedByPrerequisite)
			}
			if s.RunID != nil {
				t.Errorf("stage %q has a non-nil RunID = %v, want nil -- a blocked stage must never have a run", key, *s.RunID)
			}
			if s.BlockedReason == "" {
				t.Errorf("stage %q has no blocked reason", key)
			}
		}

		final, err := db.GetEmailGWCampaign(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("get campaign: %v", err)
		}
		if final.Status != emailgwcampaign.CampaignPartial {
			t.Errorf("campaign status = %q, want %q", final.Status, emailgwcampaign.CampaignPartial)
		}
	})
}

func TestAdvanceEmailGWCampaign_StageOneInconclusive_BlocksWithDistinctReasonFromConfirmedBlock(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign := triggerBECCampaign(t, ctx, pool, target)
		stages, _ := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		stage1 := stageByKey(t, stages, "identity-probe")

		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive, Reason: "no enforcement evidence found"}})
		db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusPartial, result1, "", time.Now().UTC())
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage1.RunID)

		stages, _ = db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		fraudStage := stageByKey(t, stages, "fraud-payload")
		if fraudStage.Status != emailgwcampaign.StageBlockedByPrerequisite {
			t.Fatalf("fraud-payload status = %q, want %q", fraudStage.Status, emailgwcampaign.StageBlockedByPrerequisite)
		}
		if fraudStage.BlockedReason == "" {
			t.Fatal("want a non-empty blocked reason")
		}
	})
}

func TestAdvanceEmailGWCampaign_Cancellation_StopsBeforeNextDispatchAndCascadesCancelled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign := triggerBECCampaign(t, ctx, pool, target)
		stages, _ := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		stage1 := stageByKey(t, stages, "identity-probe")

		if err := CancelEmailGWCampaign(ctx, pool, campaign.ID); err != nil {
			t.Fatalf("CancelEmailGWCampaign: %v", err)
		}

		// Stage 1 was already dispatched before cancellation -- it
		// still finishes exactly as it would have (best-effort, never
		// retroactive).
		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}})
		db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusCompleted, result1, "", time.Now().UTC())
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage1.RunID)

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		if len(stages) != 4 {
			t.Fatalf("len(stages) = %d, want 4", len(stages))
		}
		for _, key := range []string{"fraud-payload", "detection-check", "response-check"} {
			s := stageByKey(t, stages, key)
			if s.Status != emailgwcampaign.StageCancelled {
				t.Errorf("stage %q status = %q, want %q (not blocked_by_prerequisite -- cancellation is an operator decision, not an evidentiary gate)", key, s.Status, emailgwcampaign.StageCancelled)
			}
			if s.RunID != nil {
				t.Errorf("stage %q has a non-nil RunID, want nil", key)
			}
		}

		final, err := db.GetEmailGWCampaign(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("get campaign: %v", err)
		}
		if final.Status != emailgwcampaign.CampaignCancelled {
			t.Errorf("campaign status = %q, want %q", final.Status, emailgwcampaign.CampaignCancelled)
		}
	})
}

// ── Restart recovery and duplicate-dispatch safety ──────────────────────────

func TestRecoverEmailGWCampaigns_StageRunAlreadyTerminalButCampaignNeverAdvanced_Resumes(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign := triggerBECCampaign(t, ctx, pool, target)
		stages, _ := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		stage1 := stageByKey(t, stages, "identity-probe")

		// Simulate the crash: the run finished (terminal status
		// written) but the process died before continueEmailGWCampaignFromRun
		// ran -- the stage row itself is still StageDispatched.
		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}})
		if err := db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusCompleted, result1, "", time.Now().UTC()); err != nil {
			t.Fatalf("update stage1 run: %v", err)
		}

		if err := RecoverEmailGWCampaigns(ctx, pool, provider, target, emailgwrun.EnvironmentLab); err != nil {
			t.Fatalf("RecoverEmailGWCampaigns: %v", err)
		}

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		if len(stages) != 2 {
			t.Fatalf("len(stages) = %d, want 2 -- recovery must dispatch fraud-payload, not leave the campaign stuck", len(stages))
		}
		stage2 := stageByKey(t, stages, "fraud-payload")
		if stage2.Status != emailgwcampaign.StageDispatched || stage2.RunID == nil {
			t.Fatalf("stage2 = %+v, want StageDispatched with a real RunID after recovery", stage2)
		}
	})
}

func TestContinueEmailGWCampaignFromRun_CalledTwiceConcurrently_NeverDuplicateDispatches(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		_, addr := startEmailGWRunTestServer(t)
		target := emailgwefficacy.InjectionTarget{TargetMX: addr}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)

		campaign := triggerBECCampaign(t, ctx, pool, target)
		stages, _ := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		stage1 := stageByKey(t, stages, "identity-probe")

		result1 := marshalResult(t, emailgwefficacy.EfficacyResult{Prevention: emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}})
		db.UpdateEmailGWRunStatus(ctx, pool, *stage1.RunID, emailgwrun.StatusCompleted, result1, "", time.Now().UTC())

		done := make(chan struct{}, 2)
		for i := 0; i < 2; i++ {
			go func() {
				continueEmailGWCampaignFromRun(ctx, pool, provider, target, emailgwrun.EnvironmentLab, *stage1.RunID)
				done <- struct{}{}
			}()
		}
		<-done
		<-done

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		fraudCount := 0
		for _, s := range stages {
			if s.StageKey == "fraud-payload" {
				fraudCount++
			}
		}
		if fraudCount != 1 {
			t.Fatalf("fraud-payload appears %d times, want exactly 1 -- the unique(campaign_id,ordinal) guard must prevent duplicate dispatch", fraudCount)
		}
	})
}

// ── Dispatch retry/failure ──────────────────────────────────────────────────

func TestDispatchInjectedStage_PersistentInjectionFailure_MarksFailedAfterRetriesAndCascadesBlock(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// Port 1 refuses connections deterministically -- every
		// attempt fails, proving the bounded retry gives up rather
		// than looping forever, and that the failure cascades.
		target := emailgwefficacy.InjectionTarget{TargetMX: "127.0.0.1:1"}

		campaign := triggerBECCampaign(t, ctx, pool, target)

		stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("list stages: %v", err)
		}
		if len(stages) != 4 {
			t.Fatalf("len(stages) = %d, want 4 -- a persistent dispatch failure must cascade through every downstream stage synchronously", len(stages))
		}
		stage1 := stageByKey(t, stages, "identity-probe")
		if stage1.Status != emailgwcampaign.StageFailed {
			t.Errorf("identity-probe status = %q, want %q", stage1.Status, emailgwcampaign.StageFailed)
		}
		if stage1.BlockedReason == "" {
			t.Error("want a non-empty failure reason")
		}
		for _, key := range []string{"fraud-payload", "detection-check", "response-check"} {
			s := stageByKey(t, stages, key)
			if s.Status != emailgwcampaign.StageBlockedByPrerequisite {
				t.Errorf("stage %q status = %q, want %q", key, s.Status, emailgwcampaign.StageBlockedByPrerequisite)
			}
		}

		final, err := db.GetEmailGWCampaign(ctx, pool, campaign.ID)
		if err != nil {
			t.Fatalf("get campaign: %v", err)
		}
		if final.Status != emailgwcampaign.CampaignFailed {
			t.Errorf("campaign status = %q, want %q", final.Status, emailgwcampaign.CampaignFailed)
		}
	})
}
