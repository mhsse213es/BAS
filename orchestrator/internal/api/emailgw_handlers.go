package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/reporting"
)

// emailGWCoverageResponse is the JSON shape served by
// GetEmailGWCoverage -- the report's own Summary() text alongside
// every taxonomy area's status, straight from internal/emailgwefficacy.
type emailGWCoverageResponse struct {
	Summary string                         `json:"summary"`
	Areas   []emailgwefficacy.AreaCoverage `json:"areas"`
}

// GetEmailGWCoverage returns Audspect's real, current EmailGW
// coverage report (internal/emailgwefficacy's
// AudspectEmailGWCoverageReport). Read-only; computes nothing of its
// own -- it only renders data internal/emailgwefficacy already proved.
func (h *Handler) GetEmailGWCoverage(w http.ResponseWriter, r *http.Request) {
	report, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading coverage report: %v", err), http.StatusInternalServerError)
		return
	}
	respond(w, emailGWCoverageResponse{Summary: report.Summary(), Areas: report.Areas()})
}

// GetEmailGWCoverageHTML serves the same data as GetEmailGWCoverage,
// rendered as a styled HTML report (internal/reporting), so it can
// never drift from the JSON endpoint.
func (h *Handler) GetEmailGWCoverageHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildEmailGWCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "emailgw coverage html",
		func(out io.Writer) error { return reporting.EmailGWCoverageReportHTML(out, rep) })
}
