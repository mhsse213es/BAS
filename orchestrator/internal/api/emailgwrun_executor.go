package api

// Real EmailGW run execution -- deliberately NOT in package db, even
// though cloudrun's own equivalent (ExecuteCloudPlanRun) lives there.
// internal/db already imports internal/emailgwefficacy would create an
// import cycle: internal/exercise's own tests import internal/testutil,
// which imports internal/db for real-Postgres setup, and
// internal/emailgwefficacy imports internal/exercise (for
// SpoofableSMTPInjector) -- so db -> emailgwefficacy -> exercise,
// combined with exercise's test-only -> testutil -> db edge, cycles.
// internal/api already imports both db and emailgwefficacy with no such
// problem (nothing exercise's tests depend on imports back into api), so
// this orchestration lives here instead. The email_gw_runs store
// functions themselves (internal/db/emailgwrun_store.go) stay in db,
// same as every other store -- only the code that calls into
// emailgwefficacy moved.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

// Dwell-window defaults and bounds. Deliberately provisional values,
// not measured ones -- there is no real-tenant timing data yet to set
// them from (that is exactly what EmailGWRun's own
// InjectedAt/WindowStart/WindowEnd/VerifiedAt columns exist to
// collect). Prevention/detection scenarios get the short default;
// EG-008/EG-010, which score ResponseVerdict against Defender's own
// AIR/ZAP remediation, get the long one, because remediation
// completing is a slower, less predictable process than a mail
// gateway's own accept/block/alert decision. DwellWindowSeconds on
// EmailGWRunRequest overrides either default per run, specifically so
// these numbers can be corrected from real observed behavior without
// a code change.
const (
	DefaultEmailGWDwellWindowPreventionDetection = 5 * time.Minute
	DefaultEmailGWDwellWindowResponse            = 30 * time.Minute
	MinEmailGWDwellWindow                        = 30 * time.Second
	MaxEmailGWDwellWindow                        = 2 * time.Hour
)

// EmailGWRunRequest is the input to ExecuteEmailGWRun.
type EmailGWRunRequest struct {
	ScenarioID string `json:"scenarioId"`
	// DwellWindowSeconds overrides the scenario-class default when > 0,
	// clamped to [MinEmailGWDwellWindow, MaxEmailGWDwellWindow].
	DwellWindowSeconds int    `json:"dwellWindowSeconds,omitempty"`
	InitiatedBy        string `json:"-"`
}

// isEmailGWResponseScenario reports whether scenarioID is one of
// EG-008's or EG-010's four IDs -- the only scenarios whose real
// verdict depends on Defender's own post-delivery remediation, not
// just its delivery-time decision.
func isEmailGWResponseScenario(scenarioID string) bool {
	return strings.HasPrefix(scenarioID, "EG-008") || strings.HasPrefix(scenarioID, "EG-010")
}

// dwellWindowFor picks scenarioID's dwell window: overrideSeconds
// when positive (clamped), otherwise the scenario-class default.
func dwellWindowFor(scenarioID string, overrideSeconds int) time.Duration {
	if overrideSeconds > 0 {
		d := time.Duration(overrideSeconds) * time.Second
		switch {
		case d < MinEmailGWDwellWindow:
			return MinEmailGWDwellWindow
		case d > MaxEmailGWDwellWindow:
			return MaxEmailGWDwellWindow
		default:
			return d
		}
	}
	if isEmailGWResponseScenario(scenarioID) {
		return DefaultEmailGWDwellWindowResponse
	}
	return DefaultEmailGWDwellWindowPreventionDetection
}

// statusForEmailGWResult maps a completed EfficacyResult to an
// email_gw_runs status. Per the architecture doc's own instruction, a
// run finishing its verification window is never read as the control
// having passed or failed -- StatusCompleted here means "verification
// ran and every dimension returned a definitive verdict (success,
// failure, not-applicable, or not-tested)", and StatusPartial means
// "at least one dimension is Inconclusive", not "the run half-failed".
func statusForEmailGWResult(result emailgwefficacy.EfficacyResult) emailgwrun.Status {
	for _, v := range [...]emailgwefficacy.EmailGWVerdict{result.Prevention.Verdict, result.DetectionVerdict.Verdict, result.ResponseVerdict.Verdict} {
		if v == emailgwefficacy.VerdictInconclusive {
			return emailgwrun.StatusPartial
		}
	}
	return emailgwrun.StatusCompleted
}

func currentEmailGWRunOrNil(ctx context.Context, pool *pgxpool.Pool, id string) *emailgwrun.EmailGWRun {
	run, err := db.GetEmailGWRun(ctx, pool, id)
	if err != nil {
		return nil
	}
	return run
}

// ExecuteEmailGWRun starts one real EmailGW scenario run: resolves
// req.ScenarioID to a MailExpectation, sends it for real via
// emailgwefficacy.InjectScenarioMessage, and -- once that succeeds --
// returns immediately with the row at StatusRunning while a detached
// goroutine waits out the dwell window and calls
// emailgwefficacy.VerifyMailExpectation once to write the terminal
// result.
//
// Unlike db.ExecuteCloudPlanRun, this is NOT a plain synchronous
// function: see internal/emailgwrun's own package comment for why
// real SMTP delivery and real vendor-API evidence can't finish inside
// one HTTP request the way CloudPlan's zero-I/O graph search does.
func ExecuteEmailGWRun(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, outboundSender emailgwefficacy.OutboundSender, environment emailgwrun.Environment, req EmailGWRunRequest) (*emailgwrun.EmailGWRun, error) {
	exp, ok := emailgwefficacy.ExpectationByID(req.ScenarioID)
	if !ok {
		return nil, fmt.Errorf("emailgwrun: unknown scenario id %q", req.ScenarioID)
	}
	// Exactly one of these two sending mechanisms is ever used for one
	// expectation -- EnvelopeFrom (SpoofableSMTPInjector, inbound-
	// spoofed) and OutboundSenderMailbox (Graph sendMail, authenticated
	// outbound) are deliberately separate fields precisely because
	// they're not interchangeable (see outbound.go's own package
	// comment). Neither set is the same "not wired for real injection
	// yet" signal every other unwired scenario already returns.
	switch {
	case exp.EnvelopeFrom != "":
		content, ok := emailgwefficacy.ScenarioTestContent(exp)
		if !ok {
			return nil, fmt.Errorf("emailgwrun: %q has no registered test content", req.ScenarioID)
		}
		return executeEmailGWRunInbound(ctx, pool, provider, target, outboundSender, environment, req, exp, content)
	case exp.OutboundSenderMailbox != "":
		if outboundSender == nil {
			return nil, fmt.Errorf("emailgwrun: %q needs real outbound sending, but no OutboundSender is configured on this deployment", req.ScenarioID)
		}
		content, ok := emailgwefficacy.OutboundScenarioTestContent(exp)
		if !ok {
			return nil, fmt.Errorf("emailgwrun: %q has no registered outbound test content", req.ScenarioID)
		}
		return executeEmailGWRunOutbound(ctx, pool, provider, target, outboundSender, environment, req, exp, content)
	default:
		return nil, fmt.Errorf("emailgwrun: %q is not wired for real injection yet, see its own MailExpectation.Note", req.ScenarioID)
	}
}

func executeEmailGWRunInbound(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, outboundSender emailgwefficacy.OutboundSender, environment emailgwrun.Environment, req EmailGWRunRequest, exp emailgwefficacy.MailExpectation, content emailgwefficacy.InjectableMessage) (*emailgwrun.EmailGWRun, error) {
	if environment == "" {
		environment = emailgwrun.EnvironmentLab
	}

	run := &emailgwrun.EmailGWRun{
		ID:           newID(),
		ScenarioID:   req.ScenarioID,
		MessageClass: exp.MessageClass,
		Environment:  environment,
		Status:       emailgwrun.StatusPending,
		InitiatedBy:  req.InitiatedBy,
		StartedAt:    time.Now().UTC(),
	}
	if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
		return nil, err
	}

	observation, err := emailgwefficacy.InjectScenarioMessage(ctx, target, exp, content)
	if err != nil {
		_ = db.UpdateEmailGWRunStatus(ctx, pool, run.ID, emailgwrun.StatusFailed, nil, err.Error(), time.Time{})
		return currentEmailGWRunOrNil(ctx, pool, run.ID), fmt.Errorf("email gw run %s: %w", run.ID, err)
	}

	dwell := dwellWindowFor(req.ScenarioID, req.DwellWindowSeconds)
	window := emailgwefficacy.TimeWindow{Start: observation.Timestamp, End: observation.Timestamp.Add(dwell)}
	if err := db.UpdateEmailGWRunInjected(ctx, pool, run.ID, observation.SenderPayloadHash, observation.Timestamp, window.Start, window.End); err != nil {
		return currentEmailGWRunOrNil(ctx, pool, run.ID), fmt.Errorf("email gw run %s: %w", run.ID, err)
	}

	go finishEmailGWRunAfterWindow(pool, provider, target, outboundSender, environment, exp, observation, window, run.ID, emailGWWaiterStopChan())

	return currentEmailGWRunOrNil(ctx, pool, run.ID), nil
}

// executeEmailGWRunOutbound is executeEmailGWRunInbound's own
// counterpart for a scenario wired via OutboundSenderMailbox --
// everything past the actual send (row lifecycle, dwell window,
// verification, recovery) is identical and mechanism-agnostic; only
// the sending call itself differs.
func executeEmailGWRunOutbound(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, outboundSender emailgwefficacy.OutboundSender, environment emailgwrun.Environment, req EmailGWRunRequest, exp emailgwefficacy.MailExpectation, content emailgwefficacy.OutboundMessage) (*emailgwrun.EmailGWRun, error) {
	if environment == "" {
		environment = emailgwrun.EnvironmentLab
	}

	run := &emailgwrun.EmailGWRun{
		ID:           newID(),
		ScenarioID:   req.ScenarioID,
		MessageClass: exp.MessageClass,
		Environment:  environment,
		Status:       emailgwrun.StatusPending,
		InitiatedBy:  req.InitiatedBy,
		StartedAt:    time.Now().UTC(),
	}
	if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
		return nil, err
	}

	observation, err := emailgwefficacy.SendOutboundTestMessage(ctx, outboundSender, exp, content)
	if err != nil {
		_ = db.UpdateEmailGWRunStatus(ctx, pool, run.ID, emailgwrun.StatusFailed, nil, err.Error(), time.Time{})
		return currentEmailGWRunOrNil(ctx, pool, run.ID), fmt.Errorf("email gw run %s: %w", run.ID, err)
	}

	dwell := dwellWindowFor(req.ScenarioID, req.DwellWindowSeconds)
	window := emailgwefficacy.TimeWindow{Start: observation.Timestamp, End: observation.Timestamp.Add(dwell)}
	if err := db.UpdateEmailGWRunInjected(ctx, pool, run.ID, observation.SenderPayloadHash, observation.Timestamp, window.Start, window.End); err != nil {
		return currentEmailGWRunOrNil(ctx, pool, run.ID), fmt.Errorf("email gw run %s: %w", run.ID, err)
	}

	go finishEmailGWRunAfterWindow(pool, provider, target, outboundSender, environment, exp, observation, window, run.ID, emailGWWaiterStopChan())

	return currentEmailGWRunOrNil(ctx, pool, run.ID), nil
}

// finishEmailGWRunAfterWindow waits out window -- or returns
// immediately if it has already closed, the recovery-sweep case --
// then calls VerifyMailExpectation exactly once and writes the
// terminal result. Deliberately takes its own context.Background(),
// never the triggering HTTP request's context: that request returns
// long before the window closes, and its context would already be
// canceled by the time this runs.
//
// target is threaded through (unused by this run's own verification)
// solely so the campaign-continuation hook below -- reached by both
// this live path and RecoverEmailGWRuns's own recovery sweep -- has
// what it needs to dispatch a next stage for real, without a second,
// separate recovery mechanism.
// emailGWWaiterMu guards emailGWWaiterStop. Each generation of waiters shares
// one stop channel; StopEmailGWWaiters closes the current generation and starts
// a new one, so later waiters are not affected.
var (
	emailGWWaiterMu   sync.Mutex
	emailGWWaiterStop = make(chan struct{})
)

// emailGWWaiterStopChan returns the stop channel for the current generation.
func emailGWWaiterStopChan() <-chan struct{} {
	emailGWWaiterMu.Lock()
	defer emailGWWaiterMu.Unlock()
	return emailGWWaiterStop
}

// StopEmailGWWaiters cancels every waiter started before this call. A waiter
// that is cancelled returns without writing, and its run stays StatusRunning
// for RecoverEmailGWRuns. Production never calls this. Tests call it on cleanup
// so a leaked run cannot write into a later test's database.
func StopEmailGWWaiters() {
	emailGWWaiterMu.Lock()
	defer emailGWWaiterMu.Unlock()
	close(emailGWWaiterStop)
	emailGWWaiterStop = make(chan struct{})
}

// waitForEmailGWWindow sleeps until end, or returns false early if stop closes.
func waitForEmailGWWindow(end time.Time, stop <-chan struct{}) bool {
	wait := time.Until(end)
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-stop:
		return false
	}
}

func finishEmailGWRunAfterWindow(pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, outboundSender emailgwefficacy.OutboundSender, environment emailgwrun.Environment, exp emailgwefficacy.MailExpectation, observation emailgwefficacy.OriginDeliveryObservation, window emailgwefficacy.TimeWindow, runID string, stop <-chan struct{}) {
	if !waitForEmailGWWindow(window.End, stop) {
		return
	}
	ctx := context.Background()
	result := emailgwefficacy.VerifyMailExpectation(exp, observation, provider, window)
	resultJSON, err := json.Marshal(result)
	if err != nil {
		_ = db.UpdateEmailGWRunStatus(ctx, pool, runID, emailgwrun.StatusFailed, nil, err.Error(), time.Time{})
		continueEmailGWCampaignFromRun(ctx, pool, provider, target, outboundSender, environment, runID)
		return
	}
	status := statusForEmailGWResult(result)
	_ = db.UpdateEmailGWRunStatus(ctx, pool, runID, status, resultJSON, "", time.Now().UTC())
	continueEmailGWCampaignFromRun(ctx, pool, provider, target, outboundSender, environment, runID)
}

// RecoverEmailGWRuns resumes every row still at StatusRunning at
// process startup -- the durability gap a bare goroutine-per-run
// design would otherwise have if the process restarts mid-wait. A
// row whose WindowEnd has already passed is verified immediately
// (finishEmailGWRunAfterWindow's own time.Until is <= 0, so it never
// sleeps); a row still legitimately waiting gets a fresh goroutine
// that waits out the remaining time. Either way the original window
// boundaries are reused exactly as persisted, never extended, so the
// evidence check still reflects the window the run actually promised
// when it started.
func RecoverEmailGWRuns(ctx context.Context, pool *pgxpool.Pool, provider emailgwefficacy.MailEvidenceProvider, target emailgwefficacy.InjectionTarget, outboundSender emailgwefficacy.OutboundSender, environment emailgwrun.Environment) error {
	runs, err := db.ListRunningEmailGWRuns(ctx, pool)
	if err != nil {
		return fmt.Errorf("emailgwrun: recover: %w", err)
	}
	for _, run := range runs {
		exp, ok := emailgwefficacy.ExpectationByID(run.ScenarioID)
		if !ok || run.WindowEnd == nil {
			_ = db.UpdateEmailGWRunStatus(ctx, pool, run.ID, emailgwrun.StatusFailed, nil,
				"emailgwrun: recovery could not resolve this run's scenario id or window", time.Time{})
			continueEmailGWCampaignFromRun(ctx, pool, provider, target, outboundSender, environment, run.ID)
			continue
		}
		observation := emailgwefficacy.OriginDeliveryObservation{SenderPayloadHash: run.SenderPayloadHash}
		if run.InjectedAt != nil {
			observation.Timestamp = *run.InjectedAt
		}
		window := emailgwefficacy.TimeWindow{End: *run.WindowEnd}
		if run.WindowStart != nil {
			window.Start = *run.WindowStart
		}
		go finishEmailGWRunAfterWindow(pool, provider, target, outboundSender, environment, exp, observation, window, run.ID, emailGWWaiterStopChan())
	}
	return nil
}
