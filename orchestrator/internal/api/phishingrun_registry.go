package api

// Phishing scenario executor registry -- deliberately in package api,
// not internal/phishingrun, for the exact same reason
// ExecuteEmailGWRun lives in internal/api rather than internal/db (see
// emailgwrun_executor.go's own package comment): this file imports
// internal/phishbridge, which imports internal/emailgwefficacy, which
// imports internal/exercise -- and internal/exercise's own tests
// import internal/testutil, which imports internal/db. internal/db
// importing internal/phishingrun for its pure lifecycle types (Task 2)
// is fine; internal/db importing anything that pulls in phishbridge
// transitively is not -- it cycles. internal/phishingrun itself (see
// its own types.go) stays pure types only, importable from internal/db
// safely, exactly like internal/emailgwrun.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// PhishingRunExecutorEnv carries the external dependencies a
// scenario's own PhishingRunExecutor needs, injected rather than
// hardcoded so a future real adapter (e.g. an ITSM connector for
// ReportTicketProvider) can be swapped in without touching the
// registry itself.
type PhishingRunExecutorEnv struct {
	ReportTicketProvider phishbridge.ReportTicketEvidenceProvider
	// Pool is the same database pool ExecutePhishingRun itself already
	// has -- threaded through here for scenarios (like PH-ID-001) that
	// need to read real exercise evidence rather than an external
	// vendor provider. Always populated by TriggerPhishingRun from
	// h.db; unlike ReportTicketProvider, there is no "unconfigured
	// deployment" case for it.
	Pool *pgxpool.Pool
	// OAuthConsentLister is nil on a deployment with no Microsoft Graph
	// identity connector configured; PH-ID-002 then degrades to NotTested,
	// never a fabricated verdict. *phishidentity.Client satisfies it.
	OAuthConsentLister OAuthConsentGrantLister
	// DeviceCodeSignIns is nil on a deployment with no Microsoft Graph
	// identity connector configured; PH-ID-003 then degrades to NotTested.
	// *phishidentity.Client satisfies it.
	DeviceCodeSignIns DeviceCodeSignInLister
	// IdentityReader is nil on a deployment with no Microsoft Graph identity
	// connector configured; PH-ID-004 and PH-ID-005 then degrade to NotTested.
	// *phishidentity.Client satisfies it. Both heuristics are EXPERIMENTAL.
	IdentityReader IdentityHeuristicReader
}

// OAuthConsentGrantLister is the read-only Graph listing PH-ID-002 needs,
// narrowed to one method so tests can inject a fixture.
type OAuthConsentGrantLister interface {
	ListOAuthConsentGrants(ctx context.Context) ([]phishidentity.OAuthConsentGrant, error)
}

// DeviceCodeSignInLister is the read-only Graph sign-in read PH-ID-003 needs,
// narrowed to one method so tests can inject a fixture.
// IdentityHeuristicReader is the read-only Graph access PH-ID-004 and PH-ID-005
// need, narrowed so tests can inject a fixture. It has no write methods.
type IdentityHeuristicReader interface {
	MFADenialEventsForUser(ctx context.Context, userID string) ([]phishidentity.MFADenialEvent, error)
	RiskySignInsForUser(ctx context.Context, userID string) ([]phishidentity.RiskySignInEvent, error)
	SignInSessionsValidFromDateTime(ctx context.Context, userID string) (time.Time, error)
}

type DeviceCodeSignInLister interface {
	SignInsByAuthenticationProtocol(ctx context.Context, protocol string) ([]phishidentity.SignInEvent, error)
}

// PhishingRunExecutor runs one registered scenario for real and
// returns its phishval.Outcome. params carries whatever scenario-
// specific arguments that scenario's own executor needs (e.g.
// PH-DET-002's executionId/targetId) -- validated by the executor
// itself, not by the registry.
type PhishingRunExecutor func(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error)

// phishingRunExecutors is the one place that makes a catalog scenario
// executable. phishcatalog.Scenario.MappedImplementation is plain
// documentation text, not a callable reference -- a scenario absent
// from this map is not executable, regardless of what Coverage tier
// its catalog entry carries. Only PH-DET-002 is registered in this
// slice; expanding to the other adapter-tested scenarios is deliberate
// future work, not something to add speculatively here.
var phishingRunExecutors = map[string]PhishingRunExecutor{
	"PH-DET-002":  executePHDET002,
	"PH-ID-001":   executePHID001,
	"PH-IR-003":   executePHIR003,
	"PH-ID-002":   executePHID002,
	"PH-ID-003":   executePHID003,
	"PH-ID-004":   executePHID004,
	"PH-ID-005":   executePHID005,
	"PH-AUTH-002": emailGWReadbackExecutor("PH-AUTH-002"),
	"PH-AUTH-003": emailGWReadbackExecutor("PH-AUTH-003"),
	"PH-AUTH-004": emailGWReadbackExecutor("PH-AUTH-004"),
	"PH-AUTH-008": emailGWReadbackExecutor("PH-AUTH-008"),
	"PH-BEC-001":  emailGWReadbackExecutor("PH-BEC-001"),
	"PH-URL-001":  emailGWReadbackExecutor("PH-URL-001"),
	"PH-ATT-001":  emailGWReadbackExecutor("PH-ATT-001"),
	"PH-ATT-010":  emailGWReadbackExecutor("PH-ATT-010"),
	"PH-CHN-005":  emailGWReadbackExecutor("PH-CHN-005"),
	"PH-ATT-002":  emailGWReadbackExecutor("PH-ATT-002"),
	"PH-ATT-003":  emailGWReadbackExecutor("PH-ATT-003"),
	"PH-AUTH-007": emailGWReadbackExecutor("PH-AUTH-007"),
	"PH-BEC-006":  emailGWReadbackExecutor("PH-BEC-006"),
}

// LookupPhishingRunExecutor returns scenarioID's registered executor,
// or ok == false if it is not (yet) executable.
func LookupPhishingRunExecutor(scenarioID string) (PhishingRunExecutor, bool) {
	e, ok := phishingRunExecutors[scenarioID]
	return e, ok
}

// executePHDET002 runs PH-DET-002 (user-reported phishing / SOC
// triage) for real: checks whether a ticket was created for the
// report event named by params["executionId"]/params["targetId"].
// ExpectedTicketCreated is always true -- this is the catalog's own
// fixed Expectation (a ticket SHOULD be created), never a caller-
// selectable "known-good/known-bad" choice; that distinction only
// ever existed in this initiative's own tests.
func executePHDET002(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	executionID, _ := params["executionId"].(string)
	targetID, _ := params["targetId"].(string)
	if executionID == "" || targetID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-DET-002 requires non-empty executionId and targetId parameters")
	}

	exp := phishbridge.ReportTicketExpectation{
		ExecutionID: executionID, TargetID: targetID, ExpectedTicketCreated: true,
	}

	var verdict emailgwefficacy.VerdictDetail
	if env.ReportTicketProvider == nil {
		// No real ITSM connector is wired on this deployment
		// (Handler.WithPhishingRun was never called) -- this is not
		// "ran and found no evidence," it's "not configured yet," but
		// both degrade identically to NotTested per this initiative's
		// own rule: never fabricate a verdict from absent evidence, and
		// never panic on a nil-interface method call either.
		verdict = emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive, Reason: "phishingrun: no ReportTicketEvidenceProvider configured on this deployment"}
	} else {
		// PH-DET-002 has no real dwell window to wait out (unlike an
		// SMTP-dispatch scenario) -- it looks back over the last 24
		// hours for whatever ticketing evidence already exists rather
		// than waiting for new evidence to arrive.
		now := time.Now()
		window := emailgwefficacy.TimeWindow{Start: now.Add(-24 * time.Hour), End: now}
		verdict = phishbridge.VerifyReportTicketExpectation(exp, env.ReportTicketProvider, window)
	}
	obs := phishbridge.FromSingleDimensionResponseVerdict(verdict, "phishingrun-PH-DET-002")

	catalogExp, err := lookupPhishingCatalogExpectation("PH-DET-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// executePHID001 runs PH-ID-001 (credential-harvesting simulation):
// reads the real interaction evidence already recorded for the named
// exercise execution (exercise_evidence, FK-chained through
// exercise_executions/exercise_plans) and grades it against the
// catalog's own fixed Expectation.
//
// FromExerciseInteractionEvidence's own contract is that ListEvidence
// is authoritative for an execution that exists: zero evidence rows
// for a REAL execution is a genuine, evidenced InteractionNone (the
// target was tracked and nothing happened), not an unknown/NotTested
// case. That makes verifying the execution actually exists first
// load-bearing, not optional -- without it, a typo'd or stale
// executionId would silently produce a confident FAIL (expectation
// Clicked, observed None) for an execution that never ran, which is
// exactly the kind of fabricated verdict this initiative never
// allows. GetExecution's own not-found error surfaces as this run's
// error/StatusFailed instead.
func executePHID001(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	executionID, _ := params["executionId"].(string)
	if executionID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 requires a non-empty executionId parameter")
	}
	if env.Pool == nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 requires a database pool (deployment misconfiguration)")
	}

	store := exercise.NewStore(env.Pool)
	if _, err := store.GetExecution(ctx, executionID); err != nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 execution %q not found: %w", executionID, err)
	}

	events, err := store.ListEvidence(ctx, executionID)
	if err != nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 list evidence for %q: %w", executionID, err)
	}
	obs := phishbridge.FromExerciseInteractionEvidence(events)

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-001")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// executePHID002 runs PH-ID-002 (OAuth consent abuse): reads the tenant's
// current oauth2PermissionGrants via the injected lister and grades
// phishbridge.FromOAuthConsentGrants against the catalog's Enforcement=Blocked
// expectation. A lister error is not evidence either way, so it yields an
// empty Observation (NotTested), never a Pass from a failed read.
func executePHID002(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	var obs phishval.Observation
	if env.OAuthConsentLister != nil {
		grants, err := env.OAuthConsentLister.ListOAuthConsentGrants(ctx)
		if err == nil {
			obs = phishbridge.FromOAuthConsentGrants(grants, time.Now())
		}
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// executePHID003 runs PH-ID-003 (device-code phishing defense): reads the
// tenant's deviceCode sign-in attempts and grades whether a conditional-access
// policy on those attempts actually blocked one. It reads only the sign-in
// log's own per-attempt policy results, never the policy configuration list,
// so a policy that merely exists is never read as enforcement. A failed read
// or no connector is NotTested, never a fabricated verdict.
func executePHID003(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	var obs phishval.Observation
	if env.DeviceCodeSignIns != nil {
		signIns, err := env.DeviceCodeSignIns.SignInsByAuthenticationProtocol(ctx, "deviceCode")
		if err == nil {
			outcome, detail := phishidentity.EvaluateDeviceCodeEnforcement(signIns)
			obs = phishbridge.FromDeviceCodeEnforcement(outcome, detail)
		}
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-003")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// executePHIR003 runs PH-IR-003 (endpoint follow-through): grades the
// most recently dispatched EPP response action tagged with
// params["runId"] against the catalog's own fixed Expectation
// (Response: ResponseRemediated). action_requests.run_id is a
// free-text correlation tag (ListResponseActions' own `?runId=`
// query param uses the exact same column) -- unlike PH-ID-001's
// exercise_executions, there is no parent table to check existence
// against, so zero matching rows has only one honest reading: no
// response action evidence exists for this run, which
// phishbridge.FromEPPResponseAction's own empty Observation already
// degrades to NotTested, never a fabricated Fail.
func executePHIR003(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	actionRunID, _ := params["runId"].(string)
	if actionRunID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-IR-003 requires a non-empty runId parameter")
	}
	if env.Pool == nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-IR-003 requires a database pool (deployment misconfiguration)")
	}

	action, found, err := loadLatestActionRequest(ctx, env.Pool, actionRunID)
	if err != nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-IR-003 load action request for runId %q: %w", actionRunID, err)
	}
	var obs phishval.Observation
	if found {
		obs = phishbridge.FromEPPResponseAction(action)
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-IR-003")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// loadLatestActionRequest returns the most recently requested
// action_requests row tagged with actionRunID, mirroring
// ListResponseActions' own query and column set.
func loadLatestActionRequest(ctx context.Context, pool *pgxpool.Pool, actionRunID string) (actions.Action, bool, error) {
	var a actions.Action
	err := pool.QueryRow(ctx,
		`SELECT type, target_type, target_identifier, connector_id, status,
		        resolved_device_id, vendor_request_id, error, requested_by, reason, ticket_ref, run_id,
		        requested_at, dispatched_at, completed_at
		 FROM action_requests WHERE run_id=$1 ORDER BY requested_at DESC LIMIT 1`, actionRunID,
	).Scan(&a.Type, &a.Target.Type, &a.Target.Identifier, &a.ConnectorID, &a.Status,
		&a.ResolvedDeviceID, &a.VendorRequestID, &a.Error, &a.RequestedBy, &a.Reason, &a.TicketRef, &a.RunID,
		&a.RequestedAt, &a.DispatchedAt, &a.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return actions.Action{}, false, nil
	}
	if err != nil {
		return actions.Action{}, false, err
	}
	return a, true, nil
}

// lookupPhishingCatalogExpectation returns scenarioID's own
// phishval.Expectation from the real, current catalog -- never hand-
// duplicated here, so a future catalog edit (e.g. a changed Response
// outcome) can't silently drift out of sync with what this package
// evaluates against.
func lookupPhishingCatalogExpectation(scenarioID string) (phishval.Expectation, error) {
	catalog, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		return phishval.Expectation{}, fmt.Errorf("phishingrun: loading scenario catalog: %w", err)
	}
	for _, s := range catalog {
		if s.ID == scenarioID {
			return s.Expectation, nil
		}
	}
	return phishval.Expectation{}, fmt.Errorf("phishingrun: scenario %q not found in catalog", scenarioID)
}
