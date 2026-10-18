package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/reporting"
)

// phishingIndustryProfileSummary is one shipped Phishing BAS industry
// profile's rendered summary. Describe and PrioritySummary are plain
// rendered strings from internal/phishcatalog -- not re-parsed
// structured data, and never a computed verdict.
type phishingIndustryProfileSummary struct {
	Name            string `json:"name"`
	Describe        string `json:"describe"`
	PrioritySummary string `json:"prioritySummary"`
}

// GetPhishingIndustryProfiles returns every shipped Phishing BAS
// industry profile's Describe() and PrioritySummary() against
// Audspect's real, current scenario catalog
// (internal/phishcatalog.AudspectPhishingCatalog). Read-only; computes
// nothing of its own -- it only renders data internal/phishcatalog
// already proved.
func (h *Handler) GetPhishingIndustryProfiles(w http.ResponseWriter, r *http.Request) {
	scenarios, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading scenario catalog: %v", err), http.StatusInternalServerError)
		return
	}

	names := phishcatalog.IndustryProfileNames()
	out := make([]phishingIndustryProfileSummary, 0, len(names))
	for _, name := range names {
		profile, ok, err := phishcatalog.BuildIndustryProfile(name)
		if !ok {
			http.Error(w, fmt.Sprintf("profile %q not found", name), http.StatusInternalServerError)
			return
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("building profile %q: %v", name, err), http.StatusInternalServerError)
			return
		}
		out = append(out, phishingIndustryProfileSummary{
			Name:            name,
			Describe:        profile.Describe(),
			PrioritySummary: profile.PrioritySummary(scenarios),
		})
	}
	respond(w, out)
}

// GetPhishingIndustryProfilesHTML serves the same data as
// GetPhishingIndustryProfiles, rendered as a styled HTML report
// (internal/reporting), so it can never drift from the JSON endpoint.
func (h *Handler) GetPhishingIndustryProfilesHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildPhishingIndustryProfileReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "phishing industry profiles html",
		func(out io.Writer) error { return reporting.PhishingIndustryProfileReportHTML(out, rep) })
}
