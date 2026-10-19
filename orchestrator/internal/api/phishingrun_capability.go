package api

import (
	"fmt"
	"os"

	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishscope"
)

// Capability says whether a phishing scenario can run on this installation, and
// why not. It is derived from the same environment the trigger handler builds, so
// the library's status and the trigger's refusal can never disagree.
//
// Availability is not authorization. The trigger still requires CanRunScenario,
// still validates parameters, and still refuses an unavailable scenario. The
// browser only displays what the server reports.
const (
	CapAvailable    = "available"    // registered, and every dependency is wired here
	CapExperimental = "experimental" // runnable here, but a best-effort heuristic
	CapUnavailable  = "unavailable"  // registered, but a required dependency is not wired
	CapCatalogOnly  = "catalog_only" // defined in the catalog; no executor is registered
)

const (
	reasonDatabaseNotConfigured             = "database_not_configured"
	reasonITSMConnectorNotConfig            = "itsm_connector_not_configured"
	reasonIdentityNotConfigured             = "identity_connector_not_configured"
	reasonCalendarNotConfigured             = "calendar_connector_not_configured"
	reasonNotRegistered                     = "not_registered"
	reasonIdentityAllowlistInvalid          = "identity_allowlist_invalid"
	reasonOAuthClientAllowlistNotConfigured = "oauth_client_allowlist_not_configured"
	reasonUserAllowlistNotConfigured        = "user_allowlist_not_configured"
	reasonGraphPermissionReviewPending      = "graph_permission_review_pending"
)

// PhishingCapability is one scenario's runtime state on this installation.
type PhishingCapability struct {
	Status string
	Reason string
}

// phishingDependency is one environment check a scenario needs before it can run.
type phishingDependency struct {
	reason string
	wired  func(PhishingRunExecutorEnv) bool
}

var (
	depDatabase = phishingDependency{reasonDatabaseNotConfigured, func(e PhishingRunExecutorEnv) bool { return e.Pool != nil }}
	depITSM     = phishingDependency{reasonITSMConnectorNotConfig, func(e PhishingRunExecutorEnv) bool { return e.ReportTicketProvider != nil }}
	depIdentity = phishingDependency{reasonIdentityNotConfigured, func(e PhishingRunExecutorEnv) bool {
		return e.OAuthConsentLister != nil || e.DeviceCodeSignIns != nil || e.IdentityReader != nil
	}}
	depIdentityAllowlist = phishingDependency{reasonIdentityAllowlistInvalid, func(e PhishingRunExecutorEnv) bool { return e.IdentityScopeErr == "" }}
	depOAuthScope        = phishingDependency{reasonOAuthClientAllowlistNotConfigured, func(e PhishingRunExecutorEnv) bool { return e.IdentityScope.ConfiguredClients() }}
	depUserScope         = phishingDependency{reasonUserAllowlistNotConfigured, func(e PhishingRunExecutorEnv) bool { return e.IdentityScope.ConfiguredUsers() }}
	depCalendar          = phishingDependency{reasonCalendarNotConfigured, func(e PhishingRunExecutorEnv) bool {
		return e.CalendarEventLure != nil && e.CalendarEventAllow.configured()
	}}
)

// phishingScenarioDeps declares each registered scenario's dependencies. Every
// registered scenario must have an entry (TestPhishingCapability_EveryRegisteredScenarioDeclared).
// The identity check accepts any identity client, so each scenario is checked
// against its own client in phishingCapabilityFor, below.
var phishingScenarioDeps = map[string][]phishingDependency{
	"PH-DET-002":  {depDatabase, depITSM},
	"PH-ID-001":   {depDatabase},
	"PH-ID-002":   {depDatabase, depIdentity, depIdentityAllowlist, depOAuthScope},
	"PH-ID-003":   {depDatabase, depIdentity, depIdentityAllowlist, depUserScope},
	"PH-ID-004":   {depDatabase, depIdentity, depIdentityAllowlist, depUserScope},
	"PH-ID-005":   {depDatabase, depIdentity, depIdentityAllowlist, depUserScope},
	"PH-IR-003":   {depDatabase},
	"PH-EVA-002":  {depDatabase},
	"PH-CHN-004":  {depDatabase, depCalendar},
	"PH-AUTH-002": {depDatabase},
	"PH-AUTH-003": {depDatabase},
	"PH-AUTH-004": {depDatabase},
	"PH-AUTH-007": {depDatabase},
	"PH-AUTH-008": {depDatabase},
	"PH-BEC-001":  {depDatabase},
	"PH-BEC-006":  {depDatabase},
	"PH-URL-001":  {depDatabase},
	"PH-ATT-001":  {depDatabase},
	"PH-ATT-002":  {depDatabase},
	"PH-ATT-003":  {depDatabase},
	"PH-ATT-010":  {depDatabase},
	"PH-CHN-005":  {depDatabase},
}

// phishingCapabilityFor derives one scenario's state from the environment. The
// identity and calendar checks are per scenario: PH-ID-002 needs its own
// consent lister, not just any identity client. That is why the generic
// identity check above is narrowed here.
func phishingCapabilityFor(env PhishingRunExecutorEnv, scenarioID string, experimental bool) PhishingCapability {
	if _, ok := LookupPhishingRunExecutor(scenarioID); !ok {
		return PhishingCapability{Status: CapCatalogOnly, Reason: reasonNotRegistered}
	}
	for _, dep := range phishingScenarioDeps[scenarioID] {
		if !dep.wired(scopedEnv(env, scenarioID)) {
			return PhishingCapability{Status: CapUnavailable, Reason: dep.reason}
		}
	}
	// Configuration never enables a scenario by itself. These scenarios also need
	// their Graph permission and filtered query reviewed. Until that review is
	// recorded here, they stay unavailable whatever is configured.
	if graphReviewPending[scenarioID] {
		return PhishingCapability{Status: CapUnavailable, Reason: reasonGraphPermissionReviewPending}
	}
	if experimental {
		return PhishingCapability{Status: CapExperimental}
	}
	return PhishingCapability{Status: CapAvailable}
}

// scopedEnv keeps only the client a scenario actually reads. An identity client
// wired for PH-ID-004 must not make PH-ID-002 runnable.
func scopedEnv(env PhishingRunExecutorEnv, scenarioID string) PhishingRunExecutorEnv {
	out := PhishingRunExecutorEnv{Pool: env.Pool, IdentityScope: env.IdentityScope, IdentityScopeErr: env.IdentityScopeErr}
	switch scenarioID {
	case "PH-DET-002":
		out.ReportTicketProvider = env.ReportTicketProvider
	case "PH-ID-002":
		out.OAuthConsentLister = env.OAuthConsentLister
	case "PH-ID-003":
		out.DeviceCodeSignIns = env.DeviceCodeSignIns
	case "PH-ID-004", "PH-ID-005":
		out.IdentityReader = env.IdentityReader
	case "PH-CHN-004":
		out.CalendarEventLure = env.CalendarEventLure
		out.CalendarEventAllow = env.CalendarEventAllow
	}
	return out
}

// phishingRunEnv is the single environment the trigger and the library both
// use. It holds only what this Handler actually wires. Identity, device-code, and
// calendar clients are not wired here yet, so those scenarios report unavailable.
func (h *Handler) phishingRunEnv() PhishingRunExecutorEnv {
	env := PhishingRunExecutorEnv{ReportTicketProvider: h.phishingReportTicketProvider, Pool: h.db}
	// The allowlist comes from the container environment, which changes only when
	// the container is recreated (install or upgrade), not on a live config edit.
	// A malformed value fails closed. The startup audit record is in
	// phishing_scope_audit.go.
	scope, err := phishscope.ParseScope(
		os.Getenv(EnvPhishIdentityTargetUsers), os.Getenv(EnvPhishOAuthSPObjectIDs))
	env.IdentityScope = scope
	if err != nil {
		env.IdentityScopeErr = err.Error()
	}
	return env
}

// Install-wide target allowlists, set by the admin in the setup configuration.
const (
	EnvPhishIdentityTargetUsers = "AUDSPECT_PHISH_IDENTITY_TARGET_USERS"
	EnvPhishOAuthSPObjectIDs    = "AUDSPECT_PHISH_OAUTH_SP_OBJECT_IDS"
)

// graphReviewPending lists scenarios whose Graph permission or filtered query has
// not been reviewed against Microsoft's reference. They stay unavailable until it
// is recorded here.
var graphReviewPending = map[string]bool{
	"PH-ID-002": true,
	"PH-ID-003": true,
	// PH-ID-005 reads a user property whose permission conflicts across sources.
	// It stays unavailable until a test-tenant token confirms the exact $select.
	"PH-ID-005": true,
}

// phishingScenarioCapability derives a catalog scenario's state from the same
// environment the trigger uses. It returns an error only when the catalog itself
// cannot be read.
func (h *Handler) phishingScenarioCapability(scenarioID string) (PhishingCapability, error) {
	cat, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		return PhishingCapability{}, fmt.Errorf("phishing catalog: %w", err)
	}
	sc, ok := phishcatalog.ByID(cat, scenarioID)
	if !ok {
		return PhishingCapability{Status: CapCatalogOnly, Reason: reasonNotRegistered}, nil
	}
	return phishingCapabilityFor(h.phishingRunEnv(), scenarioID, sc.Experimental), nil
}
