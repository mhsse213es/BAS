package api

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/reporting"
)

// adAssessment builds the AD coverage assessment report from the same
// admatrix.Report() the operator UI reads -- so the PDF/JSON exports can never
// drift from what the screen shows, and carry no report-local hardcoded counts.
func (h *Handler) adAssessment() reporting.ADAssessmentReport {
	return reporting.ADAssessmentReport{GeneratedAt: time.Now().UTC(), Report: admatrix.Report()}
}

// GetADAssessmentJSON serves the assessment as JSON (the secondary export).
func (h *Handler) GetADAssessmentJSON(w http.ResponseWriter, r *http.Request) {
	rep := h.adAssessment()
	writeBufferedReport(w, "application/json",
		fmt.Sprintf(`attachment; filename="%s"`, buildReportFilename("AD_Coverage_Assessment", "coverage", "json")),
		"ad assessment json",
		func(out io.Writer) error { return reporting.ADAssessmentReportJSON(out, rep) })
}

// GetADAssessmentHTML serves the styled HTML assessment report.
func (h *Handler) GetADAssessmentHTML(w http.ResponseWriter, r *http.Request) {
	rep := h.adAssessment()
	writeBufferedReport(w, "text/html; charset=utf-8", "", "ad assessment html",
		func(out io.Writer) error { return reporting.ADAssessmentReportHTML(out, rep) })
}

// GetADAssessmentPDF serves the assessment as PDF (the primary export), via the
// Chrome sidecar with an fpdf fallback when the sidecar is unavailable.
func (h *Handler) GetADAssessmentPDF(w http.ResponseWriter, r *http.Request) {
	rep := h.adAssessment()
	writeBufferedReport(w, "application/pdf",
		fmt.Sprintf(`inline; filename="%s"`, buildReportFilename("AD_Coverage_Assessment", "coverage", "pdf")),
		"ad assessment pdf",
		func(out io.Writer) error { return reporting.ADAssessmentReportPDF(r.Context(), out, rep) })
}
