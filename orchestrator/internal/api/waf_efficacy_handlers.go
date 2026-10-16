package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/wafefficacy"
)

// wafCoverageResponse is the JSON shape served by GetWAFCoverage --
// the report's own Summary() text alongside every domain's status,
// straight from internal/wafefficacy. Read-only; computes nothing of
// its own.
type wafCoverageResponse struct {
	Summary string                       `json:"summary"`
	Domains []wafefficacy.DomainCoverage `json:"domains"`
}

// GetWAFCoverage returns Audspect's real, current WAF BAS Mastery
// coverage report (internal/wafefficacy's AudspectWAFCoverageReport).
// Its error branch is structurally unreachable today: the seed
// function's domain literal is hardcoded and always passes
// NewCoverageReport's validation, so no test forces this path --
// documented here rather than left silently untested, same as
// wafdetection's EvidenceInconclusive precedent.
func (h *Handler) GetWAFCoverage(w http.ResponseWriter, r *http.Request) {
	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading coverage report: %v", err), http.StatusInternalServerError)
		return
	}
	respond(w, wafCoverageResponse{Summary: report.Summary(), Domains: report.DomainsForDisplay()})
}

// GetWAFCoverageHTML serves the same data as GetWAFCoverage, rendered
// as a styled HTML report (internal/reporting), so it can never drift
// from the JSON endpoint.
func (h *Handler) GetWAFCoverageHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildWAFCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "waf coverage html",
		func(out io.Writer) error { return reporting.WAFCoverageReportHTML(out, rep) })
}
