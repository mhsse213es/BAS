package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/webgwefficacy"
)

// webgwIndustryProfileSummary is one shipped WebGW industry profile's
// rendered summary. Describe and PrioritySummary are plain rendered
// strings from internal/webgwefficacy -- not re-parsed structured
// data, and never a computed verdict.
type webgwIndustryProfileSummary struct {
	Name            string `json:"name"`
	Describe        string `json:"describe"`
	PrioritySummary string `json:"prioritySummary"`
}

// GetWebGWIndustryProfiles returns every shipped WebGW industry
// profile's Describe() and PrioritySummary() against Audspect's real,
// current coverage report (internal/webgwefficacy's
// AudspectWebGWCoverageReport). Read-only; computes nothing of its
// own -- it only renders data internal/webgwefficacy already proved.
func (h *Handler) GetWebGWIndustryProfiles(w http.ResponseWriter, r *http.Request) {
	report, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading coverage report: %v", err), http.StatusInternalServerError)
		return
	}

	names := webgwefficacy.IndustryProfileNames()
	out := make([]webgwIndustryProfileSummary, 0, len(names))
	for _, name := range names {
		profile, ok, err := webgwefficacy.BuildIndustryProfile(name)
		if !ok {
			http.Error(w, fmt.Sprintf("profile %q not found", name), http.StatusInternalServerError)
			return
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("building profile %q: %v", name, err), http.StatusInternalServerError)
			return
		}
		out = append(out, webgwIndustryProfileSummary{
			Name:            name,
			Describe:        profile.Describe(),
			PrioritySummary: profile.PrioritySummary(report),
		})
	}
	respond(w, out)
}

// GetWebGWIndustryProfilesHTML serves the same data as
// GetWebGWIndustryProfiles, rendered as a styled HTML report
// (internal/reporting), so it can never drift from the JSON endpoint.
func (h *Handler) GetWebGWIndustryProfilesHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildWebGWIndustryProfileReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "webgw industry profiles html",
		func(out io.Writer) error { return reporting.WebGWIndustryProfileReportHTML(out, rep) })
}
