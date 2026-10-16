package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
)

// wafExploitPreventionVectorResponse is one contributing vector's
// evaluated outcome in the JSON shape served by
// GetWAFExploitPreventionScenario -- camelCase field names per this
// package's existing JSON convention.
type wafExploitPreventionVectorResponse struct {
	VectorID       string `json:"vectorId"`
	Severity       string `json:"severity"`
	Verdict        string `json:"verdict"`
	EvidenceSource string `json:"evidenceSource"`
	Reason         string `json:"reason"`
}

// wafExploitPreventionScenarioResponse is the JSON shape served by
// GetWAFExploitPreventionScenario.
type wafExploitPreventionScenarioResponse struct {
	Objective         string                               `json:"objective"`
	Outcome           string                               `json:"outcome"`
	Summary           string                               `json:"summary"`
	Assertions        []wafExploitPreventionVectorResponse `json:"assertions"`
	UntestedVectorIDs []string                             `json:"untestedVectorIds"`
}

// GetWAFExploitPreventionScenario returns Audspect's real, current
// "Exploit Prevention and Attack-Chain Validation" enterprise scenario
// evaluation (internal/reporting's BuildExploitPreventionScenarioReport,
// itself built from internal/wafassessment's seed scenario + seed
// fixtures). Its error branch is structurally unreachable today: every
// upstream seed function uses hardcoded, already-tested, always-valid
// data -- documented here rather than left silently untested.
func (h *Handler) GetWAFExploitPreventionScenario(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildExploitPreventionScenarioReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	assertions := make([]wafExploitPreventionVectorResponse, 0, len(rep.Assertions))
	for _, a := range rep.Assertions {
		assertions = append(assertions, wafExploitPreventionVectorResponse{
			VectorID:       a.VectorID,
			Severity:       a.Severity,
			Verdict:        a.Verdict,
			EvidenceSource: a.EvidenceSource,
			Reason:         a.Reason,
		})
	}
	respond(w, wafExploitPreventionScenarioResponse{
		Objective:         rep.Objective,
		Outcome:           rep.Outcome,
		Summary:           rep.Summary,
		Assertions:        assertions,
		UntestedVectorIDs: rep.UntestedVectorIDs,
	})
}

// GetWAFExploitPreventionScenarioHTML serves the same data as
// GetWAFExploitPreventionScenario, rendered as a styled HTML report
// (internal/reporting), so it can never drift from the JSON endpoint.
func (h *Handler) GetWAFExploitPreventionScenarioHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildExploitPreventionScenarioReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "waf exploit prevention scenario html",
		func(out io.Writer) error { return reporting.WAFExploitPreventionScenarioReportHTML(out, rep) })
}
