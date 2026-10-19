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
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishscope"
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
	// CalendarEventLure and CalendarEventAllow gate PH-CHN-004, the only
	// side-effecting scenario here. Both must be set, or it returns NotTested with
	// no Graph call. The allow-list names the only mailboxes it may use.
	CalendarEventLure  CalendarEventLureClient
	CalendarEventAllow CalendarEventAllowlist
	// IdentityScope is the installation's target allowlist for the identity
	// scenarios. IdentityScopeErr is set when the configured allowlist is malformed;
	// the scenarios then fail closed. A run may select targets only from IdentityScope.
	IdentityScope    phishscope.Scope
	IdentityScopeErr string
}

// OAuthConsentGrantLister is the read-only Graph listing PH-ID-002 needs,
// narrowed to one method so tests can inject a fixture.
type OAuthConsentGrantLister interface {
	ListOAuthConsentGrants(ctx context.Context) ([]phishidentity.OAuthConsentGrant, error)
	// ListOAuthConsentGrantsForClients is the same listing narrowed server-side to
	// the given application IDs with an OData $filter. PH-ID-002 uses only this.
	ListOAuthConsentGrantsForClients(ctx context.Context, clientIDs []string) ([]phishidentity.OAuthConsentGrant, error)
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
	// SignInsForUsersByProtocol is the same read narrowed server-side to the given
	// users, one filtered query per user. PH-ID-003 uses only this.
	SignInsForUsersByProtocol(ctx context.Context, protocol string, users []string) ([]phishidentity.SignInEvent, error)
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
	"PH-DET-002": executePHDET002,
	"PH-ID-001":  executePHID001,
	"PH-IR-003":  executePHIR003,
	"PH-ID-002":  executePHID002,
	"PH-ID-003":  executePHID003,
	"PH-ID-004":  executePHID004,
	"PH-ID-005":  executePHID005,
	"PH-EVA-002": executePHEVA002,
	// PH-CHN-004 is deliberately NOT registered. It creates and deletes a real
	// calendar event, so it stays out of executable discovery until its side-effect
	// review is complete. executePHCHN004 is kept, with its evidence, for that review.
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

// executePHID002 runs PH-ID-002 (OAuth consent abuse): reads the tenant's
// current oauth2PermissionGrants via the injected lister and grades
// phishbridge.FromOAuthConsentGrants against the catalog's Enforcement=Blocked
// expectation. A lister error is not evidence either way, so it yields an
// empty Observation (NotTested), never a Pass from a failed read.
func executePHID002(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	// Targets are checked against the installation's allowlist before any Graph call.
	clientIDs := requestedTargets(params, "clientIds")
	if err := refuseUnlessScoped(env.IdentityScope.ClientIDs, clientIDs); err != nil {
		return phishval.Outcome{}, err
	}
	var obs phishval.Observation
	if env.OAuthConsentLister != nil {
		grants, err := env.OAuthConsentLister.ListOAuthConsentGrantsForClients(ctx, clientIDs)
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
	// Targets are checked against the installation's allowlist before any Graph call.
	users := requestedTargets(params, "userIds")
	if err := refuseUnlessScoped(env.IdentityScope.Users, users); err != nil {
		return phishval.Outcome{}, err
	}
	var obs phishval.Observation
	if env.DeviceCodeSignIns != nil {
		signIns, err := env.DeviceCodeSignIns.SignInsForUsersByProtocol(ctx, "deviceCode", users)
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
