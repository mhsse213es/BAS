package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
)

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
