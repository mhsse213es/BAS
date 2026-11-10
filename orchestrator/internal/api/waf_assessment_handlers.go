package api

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafmodsec"
)

// wafModsecLabURLEnv names the environment variable an operator sets to
// point the live exploit-prevention endpoint at a running
// lab/wafmodsec container (e.g. "http://localhost:8888"). Unset is the
// normal state in production and in this test suite -- the handler
// refuses cleanly rather than ever falling back to a fixture silently.
const wafModsecLabURLEnv = "WAF_MODSEC_LAB_URL"

func getenvWafModsecLabURL() string { return os.Getenv(wafModsecLabURLEnv) }

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

// wafExploitPreventionLiveJSONHandler serves the exploit-prevention
// scenario evaluated against a REAL, running ModSecurity + OWASP CRS lab
// (lab/wafmodsec) instead of the hand-authored fixture
// wafScenarioJSONHandler("exploit-prevention") serves. Only 3 of the
// scenario's 8 vectors (SQLI-001, XSS-001, PATHTRAV-001) are driven live --
// see internal/wafmodsec.ExploitPreventionLiveVectorIDs -- the other 5 come
// back in untestedVectorIds, exactly as wafassessment.EvaluateScenario
// renders any vector with no fixture. Every assertion this serves carries
// evidenceSource "live_execution", never "fixture" -- see
// wafassessment.VectorFixture.EvidenceSource.
//
// Returns 503 if wafModsecLabURLEnv is unset (no lab configured) and 502 if
// the configured lab is unreachable -- it never falls back to the
// fixture-backed result on either failure, which would silently relabel
// stale/absent evidence as current.
func (h *Handler) wafExploitPreventionLiveJSONHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := getenvWafModsecLabURL()
	if baseURL == "" {
		http.Error(w, fmt.Sprintf("no live WAF lab configured: set %s to a running lab/wafmodsec URL (see lab/wafmodsec/README.md)", wafModsecLabURLEnv), http.StatusServiceUnavailable)
		return
	}
	client := modsecwaf.NewClient(modsecwaf.Config{BaseURL: baseURL})
	scenario, result, err := wafmodsec.RunExploitPreventionLive(r.Context(), client)
	if err != nil {
		http.Error(w, fmt.Sprintf("running live exploit-prevention scenario against %s: %v", baseURL, err), http.StatusBadGateway)
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
