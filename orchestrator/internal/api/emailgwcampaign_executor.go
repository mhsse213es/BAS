package api

// Real EmailGW campaign execution. Lives in internal/api for the same
// import-cycle reason internal/emailgwrun's own executor does (see
// that file's own package comment) -- this file additionally depends
// on internal/emailgwcampaign, which is itself dependency-free of
// emailgwefficacy/exercise for exactly that reason (see that
// package's own comment).
//
// advanceEmailGWCampaign is the single place sequencing happens: it
// walks forward from the last known stage, synchronously resolving
// every StageKindDerived stage and every blocked/cancelled cascade in
// one pass, and returns as soon as it has dispatched one real
// StageKindInjected run (or reached the end of the template). The
// next call back into it -- via continueEmailGWCampaignFromRun, which
// finishEmailGWRunAfterWindow calls on every run completion, campaign
// or not -- resumes exactly where this one left off, by re-deriving
// "where we are" from the persisted stage rows rather than from any
// in-memory state. This is what makes the whole chain restart-safe:
// RecoverEmailGWCampaigns (the boot sweep below) calls the exact same
// function for the exact same reason.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwcampaign"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

// Fixed, small, non-configurable -- matching the design doc's own
// "bounded, not a tunable policy" decision. Only a genuinely transient
// injection failure (e.g. a momentary SMTP connection error) is worth
// retrying; ExecuteEmailGWRun's own up-front validation errors (unknown
// scenario, unwired EnvelopeFrom) never are, and are never retried
// here either (see dispatchInjectedStage).
const maxEmailGWCampaignStageDispatchAttempts = 3

// dimensionDetail decodes runResult (an email_gw_runs.result column
// value) and returns the VerdictDetail for dim. ok is false when
// runResult can't be decoded at all (treated by callers as "missing
// evidence", its own distinct branch -- never silently equivalent to
// VerdictInconclusive, even though both currently block progression
// the same way).
func dimensionDetail(runResult json.RawMessage, dim emailgwcampaign.Dimension) (emailgwefficacy.VerdictDetail, bool) {
	if len(runResult) == 0 {
		return emailgwefficacy.VerdictDetail{}, false
	}
	var result emailgwefficacy.EfficacyResult
	if err := json.Unmarshal(runResult, &result); err != nil {
		return emailgwefficacy.VerdictDetail{}, false
	}
	switch dim {
	case emailgwcampaign.DimensionPrevention:
		return result.Prevention, true
	case emailgwcampaign.DimensionDetection:
		return result.DetectionVerdict, true
	case emailgwcampaign.DimensionResponse:
		return result.ResponseVerdict, true
	default:
		return emailgwefficacy.VerdictDetail{}, false
	}
}

func findCampaignStageByKey(stages []*emailgwcampaign.CampaignStage, key string) (*emailgwcampaign.CampaignStage, bool) {
	for _, s := range stages {
		if s.StageKey == key {
			return s, true
		}
	}
	return nil, false
}

func permitsVerdict(permitted []string, verdict emailgwefficacy.EmailGWVerdict) bool {
	for _, p := range permitted {
		if p == string(verdict) {
			return true
		}
	}
	return false
}

// TriggerEmailGWCampaign creates a campaign row for templateID and
// starts sequencing it. Mirrors TriggerEmailGWRun's own 503-when-
// unconfigured posture -- callers check h.emailgwProvider == nil
// before calling this, same as before any email_gw_runs row exists.
func TriggerEmailGWCampaign(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, environment emailgwrun.Environment, templateID, initiatedBy string) (*emailgwcampaign.Campaign, error) {
	template, ok := emailgwcampaign.TemplateByID(templateID)
	if !ok {
		return nil, fmt.Errorf("emailgwcampaign: unknown template id %q", templateID)
	}
	if len(template.Stages) == 0 {
		return nil, fmt.Errorf("emailgwcampaign: template %q has no stages", templateID)
	}
	c := &emailgwcampaign.Campaign{
		ID:          newID(),
		TemplateID:  templateID,
		Status:      emailgwcampaign.CampaignRunning,
		InitiatedBy: initiatedBy,
		CreatedAt:   time.Now().UTC(),
	}
	if err := db.InsertEmailGWCampaign(ctx, pool, c); err != nil {
		return nil, err
	}
	advanceEmailGWCampaign(ctx, pool, provider, target, environment, c.ID)
	return db.GetEmailGWCampaign(ctx, pool, c.ID)
}

// CancelEmailGWCampaign requests cancellation. It never touches an
// already-dispatched stage's own in-flight run -- same best-effort
// posture as CancelRun's own cancelGracePeriod -- it only prevents the
// NEXT stage from dispatching; advanceEmailGWCampaign cascade-cancels
// every remaining stage the next time it runs (triggered by the
// in-flight stage's own completion).
func CancelEmailGWCampaign(ctx context.Context, pool *pgxpool.Pool, campaignID string) error {
	return db.UpdateEmailGWCampaignStatus(ctx, pool, campaignID, emailgwcampaign.CampaignCancelling, time.Time{})
}

// continueEmailGWCampaignFromRun is called by finishEmailGWRunAfterWindow
// on every run completion, campaign-stage or not. The common case (a
// standalone, non-campaign email_gw_runs row) is a cheap no-op via
// pgx.ErrNoRows.
func continueEmailGWCampaignFromRun(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, environment emailgwrun.Environment, runID string) {
	stage, err := db.GetEmailGWCampaignStageByRunID(ctx, pool, runID)
	if err != nil {
		return
	}
	run, err := db.GetEmailGWRun(ctx, pool, runID)
	if err != nil {
		return
	}
	status := emailgwcampaign.StageCompleted
	reason := ""
	if run.Status == emailgwrun.StatusFailed {
		status = emailgwcampaign.StageFailed
		reason = run.Error
	}
	_ = db.UpdateEmailGWCampaignStageTerminal(ctx, pool, stage.ID, status, reason, time.Now().UTC())
	advanceEmailGWCampaign(ctx, pool, provider, target, environment, stage.CampaignID)
}

// RecoverEmailGWCampaigns resumes every campaign whose most recently
// dispatched stage's run already finished before the process restarted
// -- the one recovery gap RecoverEmailGWRuns doesn't cover (that sweep
// only resumes a run still genuinely StatusRunning; this covers the
// narrower race where the run itself is already terminal but the
// campaign was never advanced past it). advanceEmailGWCampaign's own
// UNIQUE(campaign_id, ordinal) insert guard (via isUniqueViolation)
// makes calling it twice for the same campaign -- e.g. this sweep
// racing a continuation goroutine that was already mid-advance at
// crash time -- a benign no-op, never a duplicate dispatch.
func RecoverEmailGWCampaigns(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, environment emailgwrun.Environment) error {
	stuck, err := db.ListDispatchedEmailGWCampaignStagesWithTerminalRuns(ctx, pool)
	if err != nil {
		return fmt.Errorf("emailgwcampaign: recover: %w", err)
	}
	seen := map[string]bool{}
	for _, stage := range stuck {
		if seen[stage.CampaignID] {
			continue
		}
		seen[stage.CampaignID] = true
		if stage.RunID != nil {
			continueEmailGWCampaignFromRun(ctx, pool, provider, target, environment, *stage.RunID)
		}
	}
	return nil
}

// advanceEmailGWCampaign walks forward from the campaign's current
// stage set, resolving derived stages and prerequisite/cancellation
// cascades synchronously, stopping as soon as it dispatches one real
// run or reaches the end of the template.
func advanceEmailGWCampaign(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, environment emailgwrun.Environment, campaignID string) {
	campaign, err := db.GetEmailGWCampaign(ctx, pool, campaignID)
	if err != nil {
		return
	}
	if campaign.Status != emailgwcampaign.CampaignRunning && campaign.Status != emailgwcampaign.CampaignCancelling {
		return // already finalized -- nothing to advance
	}
	template, ok := emailgwcampaign.TemplateByID(campaign.TemplateID)
	if !ok {
		_ = db.UpdateEmailGWCampaignStatus(ctx, pool, campaignID, emailgwcampaign.CampaignFailed, time.Now().UTC())
		return
	}
	stages, err := db.ListEmailGWCampaignStages(ctx, pool, campaignID)
	if err != nil {
		return
	}

	for len(stages) < len(template.Stages) {
		ordinal := len(stages)
		st := template.Stages[ordinal]

		if campaign.Status == emailgwcampaign.CampaignCancelling {
			s, err := insertTerminalStage(ctx, pool, campaignID, ordinal, st.Key, emailgwcampaign.StageCancelled, "campaign cancelled by operator")
			if err != nil {
				return
			}
			stages = append(stages, s)
			continue
		}

		switch st.Kind {
		case emailgwcampaign.StageKindInjected:
			if st.Gate != nil {
				upstream, ok := findCampaignStageByKey(stages, st.Gate.UpstreamStageKey)
				blockedReason, blocked := evaluateGateBlock(ctx, pool, upstream, ok, st.Gate)
				if blocked {
					s, err := insertTerminalStage(ctx, pool, campaignID, ordinal, st.Key, emailgwcampaign.StageBlockedByPrerequisite, blockedReason)
					if err != nil {
						return
					}
					stages = append(stages, s)
					continue
				}
			}
			dispatched := dispatchInjectedStage(ctx, pool, provider, target, environment, campaignID, ordinal, st)
			if dispatched == nil {
				return // insert collided (already advanced elsewhere) or a hard error -- stop, don't loop forever
			}
			stages = append(stages, dispatched)
			if dispatched.Status == emailgwcampaign.StageFailed {
				// Every retry was exhausted -- there is no run left
				// to eventually call back in, so nothing will ever
				// re-invoke this function for this stage. Cascade the
				// failure through the rest of the template right now,
				// synchronously, in this same pass.
				continue
			}
			return // a real run is now in flight; wait for its own async completion to call back in

		case emailgwcampaign.StageKindDerived:
			source, ok := findCampaignStageByKey(stages, st.ReadsFromStageKey)
			if !ok || source.Status != emailgwcampaign.StageCompleted || source.RunID == nil {
				reason := fmt.Sprintf("source stage %q never produced a completed run to read from", st.ReadsFromStageKey)
				if ok && source.BlockedReason != "" {
					reason = fmt.Sprintf("source stage %q never executed: %s", st.ReadsFromStageKey, source.BlockedReason)
				}
				s, err := insertTerminalStage(ctx, pool, campaignID, ordinal, st.Key, emailgwcampaign.StageBlockedByPrerequisite, reason)
				if err != nil {
					return
				}
				stages = append(stages, s)
				continue
			}
			s, err := insertTerminalStage(ctx, pool, campaignID, ordinal, st.Key, emailgwcampaign.StageCompleted, "")
			if err != nil {
				return
			}
			stages = append(stages, s)
			continue
		}
	}

	finalizeEmailGWCampaign(ctx, pool, campaignID, campaign.Status, stages)
}

// evaluateGateBlock applies the design doc's three explicitly distinct
// branches: a confirmed, non-permitted verdict; VerdictInconclusive;
// and undecodable/missing evidence -- plus the cascade case where the
// upstream stage never ran at all. Only "verdict is in gate.PermittedVerdicts"
// returns blocked=false.
func evaluateGateBlock(ctx context.Context, pool *pgxpool.Pool, upstream *emailgwcampaign.CampaignStage, upstreamFound bool, gate *emailgwcampaign.GateCondition) (reason string, blocked bool) {
	if !upstreamFound {
		return fmt.Sprintf("upstream stage %q does not exist in this campaign", gate.UpstreamStageKey), true
	}
	if upstream.Status != emailgwcampaign.StageCompleted || upstream.RunID == nil {
		return fmt.Sprintf("upstream stage %q never executed: %s", gate.UpstreamStageKey, upstream.BlockedReason), true
	}
	run, err := db.GetEmailGWRun(ctx, pool, *upstream.RunID)
	if err != nil {
		return fmt.Sprintf("upstream stage %q's run could not be read", gate.UpstreamStageKey), true
	}
	detail, ok := dimensionDetail(run.Result, gate.UpstreamDimension)
	if !ok {
		return fmt.Sprintf("upstream stage %q produced no decodable %s evidence; insufficient evidence to justify continuation", gate.UpstreamStageKey, gate.UpstreamDimension), true
	}
	if permitsVerdict(gate.PermittedVerdicts, detail.Verdict) {
		return "", false
	}
	if detail.Verdict == emailgwefficacy.VerdictInconclusive {
		return fmt.Sprintf("upstream stage %q outcome indeterminate (%s); insufficient evidence to justify continuation", gate.UpstreamStageKey, detail.Reason), true
	}
	return fmt.Sprintf("upstream stage %q verdict = %s; required one of %v to continue", gate.UpstreamStageKey, detail.Verdict, gate.PermittedVerdicts), true
}

// insertTerminalStage records a stage that never dispatches a run --
// blocked, cancelled, or a derived stage's own immediate completion.
// RunID stays nil, always: the structural guarantee that nothing here
// could be mistaken for an executed result. A unique-violation on
// (campaign_id, ordinal) means another caller already advanced this
// campaign past ordinal; treated as a benign stop, not an error.
func insertTerminalStage(ctx context.Context, pool *pgxpool.Pool, campaignID string, ordinal int, stageKey string, status emailgwcampaign.StageStatus, reason string) (*emailgwcampaign.CampaignStage, error) {
	now := time.Now().UTC()
	s := &emailgwcampaign.CampaignStage{
		ID:            newID(),
		CampaignID:    campaignID,
		Ordinal:       ordinal,
		StageKey:      stageKey,
		Status:        status,
		BlockedReason: reason,
		CreatedAt:     now,
		CompletedAt:   &now,
	}
	if err := db.InsertEmailGWCampaignStage(ctx, pool, s); err != nil {
		return nil, err // isUniqueViolation(err): another caller already advanced this campaign -- stop, don't duplicate
	}
	return s, nil
}

// dispatchInjectedStage resolves st.ExpectationID and dispatches a
// real emailgwrun, retrying up to maxEmailGWCampaignStageDispatchAttempts
// times on a transient injection failure (ExecuteEmailGWRun returning
// a non-nil run alongside its error -- meaning the row was inserted
// and InjectScenarioMessage itself failed). A validation failure
// (ExecuteEmailGWRun returning a nil run -- unknown scenario id,
// unwired EnvelopeFrom, no registered content) is never retried: no
// number of attempts changes an unresolvable scenario id. Returns nil
// if the stage row itself could not be inserted (duplicate-ordinal
// race, or a hard DB error) -- the caller stops advancing rather than
// looping.
func dispatchInjectedStage(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, environment emailgwrun.Environment, campaignID string, ordinal int, st emailgwcampaign.StageTemplate) *emailgwcampaign.CampaignStage {
	now := time.Now().UTC()
	s := &emailgwcampaign.CampaignStage{
		ID: newID(), CampaignID: campaignID, Ordinal: ordinal, StageKey: st.Key,
		Status: emailgwcampaign.StagePending, CreatedAt: now,
	}
	if err := db.InsertEmailGWCampaignStage(ctx, pool, s); err != nil {
		return nil
	}

	var lastErr error
	for attempt := 1; attempt <= maxEmailGWCampaignStageDispatchAttempts; attempt++ {
		run, err := ExecuteEmailGWRun(ctx, pool, provider, target, environment, EmailGWRunRequest{ScenarioID: st.ExpectationID, InitiatedBy: "emailgwcampaign"})
		if err == nil {
			_ = db.UpdateEmailGWCampaignStageDispatched(ctx, pool, s.ID, run.ID)
			s.RunID = &run.ID
			s.Status = emailgwcampaign.StageDispatched
			return s
		}
		lastErr = err
		if run == nil {
			break // non-transient validation failure -- retrying can never succeed
		}
		// Transient: run was inserted and marked failed by
		// ExecuteEmailGWRun itself. Track it so, if every retry
		// exhausts, the stage still points at a real (failed) run
		// rather than none at all.
		s.RunID = &run.ID
		if attempt < maxEmailGWCampaignStageDispatchAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	_ = db.UpdateEmailGWCampaignStageTerminal(ctx, pool, s.ID, emailgwcampaign.StageFailed, lastErr.Error(), time.Now().UTC())
	s.Status = emailgwcampaign.StageFailed
	s.BlockedReason = lastErr.Error()
	return s
}

// finalizeEmailGWCampaign computes the campaign's own final status
// from its stages' real recorded statuses -- never hiding a
// failed/blocked/cancelled stage inside a falsely-clean "completed".
func finalizeEmailGWCampaign(ctx context.Context, pool *pgxpool.Pool, campaignID string, priorStatus emailgwcampaign.CampaignStatus, stages []*emailgwcampaign.CampaignStage) {
	if priorStatus == emailgwcampaign.CampaignCancelling {
		_ = db.UpdateEmailGWCampaignStatus(ctx, pool, campaignID, emailgwcampaign.CampaignCancelled, time.Now().UTC())
		return
	}
	final := emailgwcampaign.CampaignCompleted
	for _, s := range stages {
		switch s.Status {
		case emailgwcampaign.StageFailed:
			final = emailgwcampaign.CampaignFailed
		case emailgwcampaign.StageBlockedByPrerequisite, emailgwcampaign.StageCancelled:
			if final != emailgwcampaign.CampaignFailed {
				final = emailgwcampaign.CampaignPartial
			}
		}
	}
	_ = db.UpdateEmailGWCampaignStatus(ctx, pool, campaignID, final, time.Now().UTC())
}
