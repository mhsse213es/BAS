package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafmodsec"
)

// wafModsecLabURLEnv names the environment variable an operator sets to
// point the live exploit-prevention endpoint at a running
// lab/wafmodsec container (e.g. "http://localhost:8888"). Unset is the
// normal state in production and in this test suite -- the handler
// refuses cleanly rather than ever falling back to a fixture silently.
const wafModsecLabURLEnv = "WAF_MODSEC_LAB_URL"

func getenvWafModsecLabURL() string { return os.Getenv(wafModsecLabURLEnv) }

// wafModsecWeakenedLabURLEnv names the second environment variable the live
// policy-integrity endpoint needs -- that scenario's GAP-001 is a genuine
// two-leg baseline-vs-weakened comparison, so it requires a SECOND, real
// WAF instance (lab/wafmodsec/docker-compose.yml's "waf-weakened" service)
// alongside wafModsecLabURLEnv's baseline one. Same refusal discipline:
// unset means 503, never a silent single-leg fallback.
const wafModsecWeakenedLabURLEnv = "WAF_MODSEC_WEAKENED_LAB_URL"

func getenvWafModsecWeakenedLabURL() string { return os.Getenv(wafModsecWeakenedLabURLEnv) }

// wafModsecAuditLogPathEnv names the environment variable the live
// detection-telemetry endpoint needs: a real filesystem path to the
// baseline lab's ModSecurity audit log file (lab/wafmodsec/docker-
// compose.yml's MODSEC_AUDIT_LOG bind mount). That scenario's evidence
// comes from reading the WAF's own real audit trail, not another HTTP
// round trip, so it needs a path, not a second client. Same refusal
// discipline: unset means 503, never a silent fixture fallback.
const wafModsecAuditLogPathEnv = "WAF_MODSEC_AUDIT_LOG_PATH"

func getenvWafModsecAuditLogPath() string { return os.Getenv(wafModsecAuditLogPathEnv) }

// wafScenarioVectorResponse is one contributing vector's evaluated
// outcome in the JSON shape served by wafScenarioJSONHandler --
// camelCase field names per this package's existing JSON convention.
type wafScenarioVectorResponse struct {
	VectorID       string `json:"vectorId"`
	Severity       string `json:"severity"`
	Verdict        string `json:"verdict"`
	EvidenceSource string `json:"evidenceSource"`
	Reason         string `json:"reason"`
}

// wafScenarioResponse is the JSON shape served by
// wafScenarioJSONHandler, for any registered enterprise-scenario slug.
type wafScenarioResponse struct {
	ScenarioID        string                      `json:"scenarioId"`
	ScenarioName      string                      `json:"scenarioName"`
	Objective         string                      `json:"objective"`
	Outcome           string                      `json:"outcome"`
	Summary           string                      `json:"summary"`
	Assertions        []wafScenarioVectorResponse `json:"assertions"`
	UntestedVectorIDs []string                    `json:"untestedVectorIds"`
}

// wafScenarioJSONHandler returns a handler serving the enterprise
// scenario registered under slug in internal/wafassessment's scenario
// registry (via internal/reporting.BuildScenarioReport). Every new
// enterprise scenario is wired through this one shared handler,
// parameterized by slug at route-registration time -- no dedicated
// handler function is written per scenario. Its error branch is
// structurally unreachable for a slug that is actually registered:
// every seed loader uses hardcoded, already-tested, always-valid data
// -- documented here rather than left silently untested.
func (h *Handler) wafScenarioJSONHandler(slug string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rep, err := reporting.BuildScenarioReport(slug)
		if err != nil {
			http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
			return
		}
		assertions := make([]wafScenarioVectorResponse, 0, len(rep.Assertions))
		for _, a := range rep.Assertions {
			assertions = append(assertions, wafScenarioVectorResponse{
				VectorID:       a.VectorID,
				Severity:       a.Severity,
				Verdict:        a.Verdict,
				EvidenceSource: a.EvidenceSource,
				Reason:         a.Reason,
			})
		}
		respond(w, wafScenarioResponse{
			ScenarioID:        rep.ScenarioID,
			ScenarioName:      rep.ScenarioName,
			Objective:         rep.Objective,
			Outcome:           rep.Outcome,
			Summary:           rep.Summary,
			Assertions:        assertions,
			UntestedVectorIDs: rep.UntestedVectorIDs,
		})
	}
}

// wafScenarioHTMLHandler is wafScenarioJSONHandler's HTML counterpart,
// rendered via internal/reporting so it can never drift from the JSON
// response for the same slug.
func (h *Handler) wafScenarioHTMLHandler(slug string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rep, err := reporting.BuildScenarioReport(slug)
		if err != nil {
			http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
			return
		}
		writeBufferedReport(w, "text/html; charset=utf-8", "", "waf enterprise scenario html",
			func(out io.Writer) error { return reporting.WAFScenarioReportHTML(out, rep) })
	}
}

// liveScenarioRunner is the common shape of every internal/wafmodsec
// Run<Scenario>Live function -- RunExploitPreventionLive,
// RunHTTPProtocolIntegrityLive, RunRoutingCacheIntegrityLive,
// RunAPIProtectionLive, RunLegitimateTrafficLive all satisfy it today, and
// any future one will too, which is what lets wafScenarioLiveJSONHandler
// stay a single shared handler instead of one near-duplicate per scenario.
type liveScenarioRunner func(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error)

// wafScenarioLiveJSONHandler returns a handler serving run's scenario
// evaluated against a REAL, running ModSecurity + OWASP CRS lab
// (lab/wafmodsec) instead of the hand-authored fixture
// wafScenarioJSONHandler(slug) serves -- the live counterpart of that
// generic handler, parameterized by the scenario's Run<Scenario>Live
// function at route-registration time, same "no dedicated handler per
// scenario" discipline. Only the subset of each scenario's vectors its own
// Run<Scenario>Live actually drives live comes back with a real verdict;
// the rest come back in untestedVectorIds, exactly as
// wafassessment.EvaluateScenario renders any vector with no fixture. Every
// assertion this serves carries evidenceSource "live_execution", never
// "fixture" -- see wafassessment.VectorFixture.EvidenceSource.
//
// Returns 503 if wafModsecLabURLEnv is unset (no lab configured) and 502 if
// the configured lab is unreachable -- it never falls back to the
// fixture-backed result on either failure, which would silently relabel
// stale/absent evidence as current.
func (h *Handler) wafScenarioLiveJSONHandler(run liveScenarioRunner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		baseURL := getenvWafModsecLabURL()
		if baseURL == "" {
			http.Error(w, fmt.Sprintf("no live WAF lab configured: set %s to a running lab/wafmodsec URL (see lab/wafmodsec/README.md)", wafModsecLabURLEnv), http.StatusServiceUnavailable)
			return
		}
		client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
		scenario, result, err := run(r.Context(), client)
		if err != nil {
			http.Error(w, fmt.Sprintf("running live scenario against %s: %v", baseURL, err), http.StatusBadGateway)
			return
		}
		assertions := make([]wafScenarioVectorResponse, 0, len(result.Assertions))
		for _, a := range result.Assertions {
			assertions = append(assertions, wafScenarioVectorResponse{
				VectorID:       a.VectorID,
				Severity:       string(a.Severity),
				Verdict:        string(a.Verdict),
				EvidenceSource: string(a.EvidenceSource),
				Reason:         a.Reason,
			})
		}
		respond(w, wafScenarioResponse{
			ScenarioID:        scenario.ID,
			ScenarioName:      scenario.Name,
			Objective:         scenario.Objective,
			Outcome:           string(result.Outcome),
			Summary:           result.Summary,
			Assertions:        assertions,
			UntestedVectorIDs: result.UntestedVectorIDs,
		})
	}
}

// wafExploitPreventionLiveJSONHandler is a thin, already-shipped wrapper
// for RunExploitPreventionLive, kept so existing callers and tests written
// against this exact method name keep working unchanged. The other 4 live
// scenarios are wired directly through wafScenarioLiveJSONHandler in
// routes.go -- no per-scenario method is added for them.
func (h *Handler) wafExploitPreventionLiveJSONHandler(w http.ResponseWriter, r *http.Request) {
	h.wafScenarioLiveJSONHandler(wafmodsec.RunExploitPreventionLive)(w, r)
}

// wafPolicyIntegrityLiveJSONHandler serves the live policy-integrity
// scenario. It cannot use the shared wafScenarioLiveJSONHandler/
// liveScenarioRunner factory -- that factory builds exactly one
// *modsecwaf.Client, but RunPolicyIntegrityLive genuinely needs two (a
// baseline and a weakened WAF instance) to evaluate GAP-001's two-leg
// comparison -- so this is its own dedicated handler, same refusal
// discipline as the shared one: 503 if either URL is unset, 502 if either
// configured lab is unreachable, never a silent fallback.
func (h *Handler) wafPolicyIntegrityLiveJSONHandler(w http.ResponseWriter, r *http.Request) {
	baselineURL := getenvWafModsecLabURL()
	weakenedURL := getenvWafModsecWeakenedLabURL()
	if baselineURL == "" || weakenedURL == "" {
		http.Error(w, fmt.Sprintf("no live WAF lab configured: set both %s and %s to running lab/wafmodsec URLs (see lab/wafmodsec/README.md)", wafModsecLabURLEnv, wafModsecWeakenedLabURLEnv), http.StatusServiceUnavailable)
		return
	}
	baselineClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baselineURL})
	weakenedClient := modsecwaf.NewClient(modsecwaf.Config{BaseURL: weakenedURL})
	scenario, result, err := wafmodsec.RunPolicyIntegrityLive(r.Context(), baselineClient, weakenedClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("running live policy-integrity scenario against %s/%s: %v", baselineURL, weakenedURL, err), http.StatusBadGateway)
		return
	}
	assertions := make([]wafScenarioVectorResponse, 0, len(result.Assertions))
	for _, a := range result.Assertions {
		assertions = append(assertions, wafScenarioVectorResponse{
			VectorID:       a.VectorID,
			Severity:       string(a.Severity),
			Verdict:        string(a.Verdict),
			EvidenceSource: string(a.EvidenceSource),
			Reason:         a.Reason,
		})
	}
	respond(w, wafScenarioResponse{
		ScenarioID:        scenario.ID,
		ScenarioName:      scenario.Name,
		Objective:         scenario.Objective,
		Outcome:           string(result.Outcome),
		Summary:           result.Summary,
		Assertions:        assertions,
		UntestedVectorIDs: result.UntestedVectorIDs,
	})
}

// wafDetectionTelemetryLiveJSONHandler serves the live detection-
// telemetry scenario. It cannot use the shared wafScenarioLiveJSONHandler/
// liveScenarioRunner factory -- that factory builds a *modsecwaf.Client
// to make another HTTP round trip, but this scenario's evidence comes
// from reading the WAF's own real audit log file (see
// internal/wafmodsec/detectiontelemetry.go), so it needs both a client
// (to drive the one correlated probe) AND a filesystem path. Same
// refusal discipline: 503 if either is unset, 502 if the lab is
// unreachable or the audit log can't be read.
func (h *Handler) wafDetectionTelemetryLiveJSONHandler(w http.ResponseWriter, r *http.Request) {
	labURL := getenvWafModsecLabURL()
	auditLogPath := getenvWafModsecAuditLogPath()
	if labURL == "" || auditLogPath == "" {
		http.Error(w, fmt.Sprintf("no live WAF lab configured: set both %s and %s (see lab/wafmodsec/README.md)", wafModsecLabURLEnv, wafModsecAuditLogPathEnv), http.StatusServiceUnavailable)
		return
	}
	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: labURL})
	scenario, result, err := wafmodsec.RunDetectionTelemetryLive(r.Context(), client, auditLogPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("running live detection-telemetry scenario against %s: %v", labURL, err), http.StatusBadGateway)
		return
	}
	assertions := make([]wafScenarioVectorResponse, 0, len(result.Assertions))
	for _, a := range result.Assertions {
		assertions = append(assertions, wafScenarioVectorResponse{
			VectorID:       a.VectorID,
			Severity:       string(a.Severity),
			Verdict:        string(a.Verdict),
			EvidenceSource: string(a.EvidenceSource),
			Reason:         a.Reason,
		})
	}
	respond(w, wafScenarioResponse{
		ScenarioID:        scenario.ID,
		ScenarioName:      scenario.Name,
		Objective:         scenario.Objective,
		Outcome:           string(result.Outcome),
		Summary:           result.Summary,
		Assertions:        assertions,
		UntestedVectorIDs: result.UntestedVectorIDs,
	})
}

// GetWAFExploitPreventionScenario is a thin, already-shipped wrapper
// for the "exploit-prevention" slug, kept so existing callers and
// tests written against this exact method name keep working
// unchanged. New scenarios are wired directly through
// wafScenarioJSONHandler/wafScenarioHTMLHandler in routes.go -- no
// per-scenario method is added for them.
func (h *Handler) GetWAFExploitPreventionScenario(w http.ResponseWriter, r *http.Request) {
	h.wafScenarioJSONHandler("exploit-prevention")(w, r)
}

// GetWAFExploitPreventionScenarioHTML is GetWAFExploitPreventionScenario's
// HTML counterpart, kept for the same backward-compatibility reason.
func (h *Handler) GetWAFExploitPreventionScenarioHTML(w http.ResponseWriter, r *http.Request) {
	h.wafScenarioHTMLHandler("exploit-prevention")(w, r)
}
