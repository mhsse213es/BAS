package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
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

// EmailGWMetricsResponse reports both environments explicitly and
// separately in every response -- see ComputeEmailGWTimeBasedMetrics's
// own doc comment for why lab and customer are never combined into
// one number. Deliberately named Lab/Customer rather than a map so a
// caller can never accidentally index into the wrong bucket.
type EmailGWMetricsResponse struct {
	Lab      EmailGWTimeBasedMetrics `json:"lab"`
	Customer EmailGWTimeBasedMetrics `json:"customer"`
}

// GetEmailGWMetrics -- Workstream 1's time-based metrics (MTTD/MTTR)
// and sample-quality counts, computed fresh on every request over
// already-persisted email_gw_runs rows (same compute-on-read posture
// as GetEmailGWRunsSummary). limit/minSampleSize are both optional
// query params, same bounds style as GetEmailGWRunsSummary's own limit.
func (h *Handler) GetEmailGWMetrics(w http.ResponseWriter, r *http.Request) {
	limit := 5000
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 20000 {
		limit = l
	}
	minSampleSize := DefaultEmailGWMinimumSampleSize
	if m, err := strconv.Atoi(r.URL.Query().Get("minSampleSize")); err == nil && m > 0 {
		minSampleSize = m
	}
	runs, err := db.ListEmailGWRuns(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	respond(w, EmailGWMetricsResponse{
		Lab:      ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentLab, minSampleSize, now),
		Customer: ComputeEmailGWTimeBasedMetrics(runs, emailgwrun.EnvironmentCustomer, minSampleSize, now),
	})
}
