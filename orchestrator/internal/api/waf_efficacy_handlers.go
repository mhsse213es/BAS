package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/wafefficacy"
	"github.com/audspect/bas/internal/wafprofile"
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

// wafIndustryProfileComplianceResponse is one compliance reference in
// the JSON shape served by GetWAFIndustryProfiles -- camelCase field
// names per this package's existing JSON convention.
type wafIndustryProfileComplianceResponse struct {
	Framework          string `json:"framework"`
	VerificationStatus string `json:"verificationStatus"`
	Note               string `json:"note"`
	SourceURL          string `json:"sourceUrl,omitempty"`
}

// wafIndustryProfileResponse is one shipped industry/regional
// profile in the JSON shape served by GetWAFIndustryProfiles.
type wafIndustryProfileResponse struct {
	ID                   string                                 `json:"id"`
	Name                 string                                 `json:"name"`
	Kind                 string                                 `json:"kind"`
	AttackVectorIDs      []string                               `json:"attackVectorIds"`
	ComplianceReferences []wafIndustryProfileComplianceResponse `json:"complianceReferences"`
	Rationale            string                                 `json:"rationale"`
}

// GetWAFIndustryProfiles returns Audspect's real, current 6 WAF
// industry/regional profiles (internal/wafprofile's
// AudspectWAFProfileCatalog), unmodified. Every ComplianceReference's
// VerificationStatus and Note render verbatim -- never summarized or
// dropped. Its error branch is structurally unreachable today -- see
// this handler's task note in the implementation plan -- documented
// here rather than left silently untested.
func (h *Handler) GetWAFIndustryProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := wafprofile.AudspectWAFProfileCatalog()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading profile catalog: %v", err), http.StatusInternalServerError)
		return
	}

	out := make([]wafIndustryProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		refs := make([]wafIndustryProfileComplianceResponse, 0, len(p.ComplianceReferences))
		for _, c := range p.ComplianceReferences {
			refs = append(refs, wafIndustryProfileComplianceResponse{
				Framework:          c.Framework,
				VerificationStatus: string(c.VerificationStatus),
				Note:               c.Note,
				SourceURL:          c.SourceURL,
			})
		}
		out = append(out, wafIndustryProfileResponse{
			ID:                   p.ID,
			Name:                 p.Name,
			Kind:                 string(p.Kind),
			AttackVectorIDs:      p.AttackVectorIDs,
			ComplianceReferences: refs,
			Rationale:            p.Rationale,
		})
	}
	respond(w, out)
}

// GetWAFIndustryProfilesHTML serves the same data as
// GetWAFIndustryProfiles, rendered as a styled HTML report
// (internal/reporting), so it can never drift from the JSON endpoint.
func (h *Handler) GetWAFIndustryProfilesHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildWAFIndustryProfileReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "waf industry profiles html",
		func(out io.Writer) error { return reporting.WAFIndustryProfileReportHTML(out, rep) })
}
