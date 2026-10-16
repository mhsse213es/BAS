package reporting

// WAF industry-profile report -- HTML only (no PDF; same
// deliberately lightweight first production-wiring pass as the WAF
// coverage report). This package only formats; it consumes
// internal/wafprofile's AudspectWAFProfileCatalog directly -- there is
// no separate internal/wafefficacy type for industry profiles, since
// wafprofile.Profile already is the shape (unlike WebGW, which layers
// a priority/weighting type over its coverage report). Every
// ComplianceReference field renders verbatim: this report can never
// show a compliance claim stronger than what wafprofile itself
// asserts.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/wafprofile"
)

// WAFIndustryProfileComplianceEntry is one compliance reference,
// carried into the report verbatim from internal/wafprofile.
type WAFIndustryProfileComplianceEntry struct {
	Framework          string
	VerificationStatus string
	Note               string
	SourceURL          string
}

// WAFIndustryProfileEntry is one shipped industry/regional profile,
// carried into the report verbatim from internal/wafprofile.
type WAFIndustryProfileEntry struct {
	ID                   string
	Name                 string
	Kind                 string
	AttackVectorIDs      []string
	ComplianceReferences []WAFIndustryProfileComplianceEntry
	Rationale            string
}

// WAFIndustryProfileReport is the canonical input to
// WAFIndustryProfileReportHTML. Build it with
// BuildWAFIndustryProfileReport.
type WAFIndustryProfileReport struct {
	GeneratedAt time.Time
	Profiles    []WAFIndustryProfileEntry
}

// BuildWAFIndustryProfileReport builds the report from wafprofile's
// real, current 6 industry/regional profiles -- the same data the
// /api/waf/industry-profiles JSON endpoint serves, so the HTML report
// can never drift from it.
func BuildWAFIndustryProfileReport() (WAFIndustryProfileReport, error) {
	profiles, err := wafprofile.AudspectWAFProfileCatalog()
	if err != nil {
		return WAFIndustryProfileReport{}, fmt.Errorf("loading WAF profile catalog: %w", err)
	}

	entries := make([]WAFIndustryProfileEntry, 0, len(profiles))
	for _, p := range profiles {
		refs := make([]WAFIndustryProfileComplianceEntry, 0, len(p.ComplianceReferences))
		for _, c := range p.ComplianceReferences {
			refs = append(refs, WAFIndustryProfileComplianceEntry{
				Framework:          c.Framework,
				VerificationStatus: string(c.VerificationStatus),
				Note:               c.Note,
				SourceURL:          c.SourceURL,
			})
		}
		entries = append(entries, WAFIndustryProfileEntry{
			ID:                   p.ID,
			Name:                 p.Name,
			Kind:                 string(p.Kind),
			AttackVectorIDs:      p.AttackVectorIDs,
			ComplianceReferences: refs,
			Rationale:            p.Rationale,
		})
	}

	return WAFIndustryProfileReport{
		GeneratedAt: time.Now().UTC(),
		Profiles:    entries,
	}, nil
}

var wafIndustryProfileReportTmpl = template.Must(template.New("waf-industry-profiles").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Industry Profiles</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:24px}
.profile{border:1px solid #e8edf4;border-radius:8px;padding:16px 20px;margin-bottom:16px}
.profile h2{font-size:1rem;font-weight:800;margin-bottom:8px}
.kind{font-size:.7rem;text-transform:uppercase;color:#6b7689;margin-bottom:8px}
.rationale{font-size:.85rem;margin-bottom:8px}
.vectors{font-size:.75rem;color:#3a4656;font-family:monospace;margin-bottom:8px}
.compliance{border-top:1px solid #f2f3f5;padding-top:8px;margin-top:8px}
.compliance-row{font-size:.75rem;margin-bottom:4px}
.compliance-status{font-weight:700;text-transform:uppercase;margin-right:6px}
</style>
</head>
<body>
<h1>WAF Industry Profiles</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
{{range .Profiles}}
<div class="profile">
  <h2>{{.ID}} -- {{.Name}}</h2>
  <div class="kind">{{.Kind}}</div>
  <div class="rationale">{{.Rationale}}</div>
  <div class="vectors">vectors: {{range $i, $v := .AttackVectorIDs}}{{if $i}}, {{end}}{{$v}}{{end}}</div>
  <div class="compliance">
  {{range .ComplianceReferences}}
    <div class="compliance-row"><span class="compliance-status">{{.VerificationStatus}}</span>{{.Framework}} -- {{.Note}}</div>
  {{end}}
  </div>
</div>
{{end}}
</body>
</html>
`))

// WAFIndustryProfileReportHTML renders the report as a plain styled
// HTML page. html/template auto-escapes every field, so a note or
// framework name can never inject markup into the page.
func WAFIndustryProfileReportHTML(w io.Writer, rep WAFIndustryProfileReport) error {
	return wafIndustryProfileReportTmpl.Execute(w, rep)
}
