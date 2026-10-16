package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/audspect/bas/internal/avprofile"
	"github.com/audspect/bas/internal/reporting"
)

// avIndustryProfileComplianceResponse is one compliance reference in the
// JSON shape served by GetAVIndustryProfiles -- camelCase field names per
// this package's existing JSON convention.
type avIndustryProfileComplianceResponse struct {
	Framework          string `json:"framework"`
	VerificationStatus string `json:"verificationStatus"`
	Note               string `json:"note"`
	SourceURL          string `json:"sourceUrl,omitempty"`
}

// avIndustryProfileResponse is one shipped industry/regional profile in
// the JSON shape served by GetAVIndustryProfiles.
type avIndustryProfileResponse struct {
	ID                   string                                `json:"id"`
	Name                 string                                `json:"name"`
	Kind                 string                                `json:"kind"`
	VectorIDs            []string                              `json:"vectorIds"`
	ComplianceReferences []avIndustryProfileComplianceResponse `json:"complianceReferences"`
	Rationale            string                                `json:"rationale"`
}

// GetAVIndustryProfiles returns Audspect's real, current 7 AV/NGAV
// industry/regional profiles (internal/avprofile's
// AudspectAVProfileCatalog), unmodified. Every ComplianceReference's
// VerificationStatus and Note render verbatim -- never summarized or
// dropped. Its error branch is structurally unreachable today: the one
// seed loader uses hardcoded, already-tested, always-valid data --
// documented here rather than left silently untested.
func (h *Handler) GetAVIndustryProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := avprofile.AudspectAVProfileCatalog()
	if err != nil {
		http.Error(w, fmt.Sprintf("loading profile catalog: %v", err), http.StatusInternalServerError)
		return
	}

	out := make([]avIndustryProfileResponse, 0, len(profiles))
	for _, p := range profiles {
		refs := make([]avIndustryProfileComplianceResponse, 0, len(p.ComplianceReferences))
		for _, c := range p.ComplianceReferences {
			refs = append(refs, avIndustryProfileComplianceResponse{
				Framework:          c.Framework,
				VerificationStatus: string(c.VerificationStatus),
				Note:               c.Note,
				SourceURL:          c.SourceURL,
			})
		}
		out = append(out, avIndustryProfileResponse{
			ID:                   p.ID,
			Name:                 p.Name,
			Kind:                 string(p.Kind),
			VectorIDs:            p.VectorIDs,
			ComplianceReferences: refs,
			Rationale:            p.Rationale,
		})
	}
	respond(w, out)
}

// GetAVIndustryProfilesHTML serves the same data as
// GetAVIndustryProfiles, rendered as a styled HTML report
// (internal/reporting), so it can never drift from the JSON endpoint.
func (h *Handler) GetAVIndustryProfilesHTML(w http.ResponseWriter, r *http.Request) {
	rep, err := reporting.BuildAVIndustryProfileReport()
	if err != nil {
		http.Error(w, fmt.Sprintf("building report: %v", err), http.StatusInternalServerError)
		return
	}
	writeBufferedReport(w, "text/html; charset=utf-8", "", "av industry profiles html",
		func(out io.Writer) error { return reporting.AVIndustryProfileReportHTML(out, rep) })
}
