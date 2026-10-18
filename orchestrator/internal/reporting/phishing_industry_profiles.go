package reporting

// Phishing BAS Mastery industry-profile report -- mirrors
// webgw_industry_profiles.go's own structure exactly, one level over
// internal/phishcatalog instead of internal/webgwefficacy. This
// package only formats; it consumes phishcatalog's
// IndustryProfileNames/BuildIndustryProfile/AudspectPhishingCatalog and
// knows nothing about how profiles or the catalog are built. Every
// field is a plain rendered string, auto-escaped by html/template --
// never a computed verdict of its own.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/phishcatalog"
)

// PhishingIndustryProfileEntry is one shipped phishing industry
// profile's rendered summary, carried verbatim from internal/phishcatalog.
type PhishingIndustryProfileEntry struct {
	Name            string
	Describe        string
	PrioritySummary string
}

// PhishingIndustryProfileReport is the canonical input to
// PhishingIndustryProfileReportHTML. Build it with
// BuildPhishingIndustryProfileReport.
type PhishingIndustryProfileReport struct {
	GeneratedAt time.Time
	Profiles    []PhishingIndustryProfileEntry
}

// BuildPhishingIndustryProfileReport builds the report from
// phishcatalog's real, current scenario catalog and every shipped
// industry profile -- the same data the /api/phishing/industry-profiles
// JSON endpoint serves, so the HTML report can never drift from it.
func BuildPhishingIndustryProfileReport() (PhishingIndustryProfileReport, error) {
	scenarios, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		return PhishingIndustryProfileReport{}, fmt.Errorf("loading scenario catalog: %w", err)
	}

	names := phishcatalog.IndustryProfileNames()
	entries := make([]PhishingIndustryProfileEntry, 0, len(names))
	for _, name := range names {
		profile, ok, err := phishcatalog.BuildIndustryProfile(name)
		if !ok {
			return PhishingIndustryProfileReport{}, fmt.Errorf("profile %q not found", name)
		}
		if err != nil {
			return PhishingIndustryProfileReport{}, fmt.Errorf("building profile %q: %w", name, err)
		}
		entries = append(entries, PhishingIndustryProfileEntry{
			Name:            name,
			Describe:        profile.Describe(),
			PrioritySummary: profile.PrioritySummary(scenarios),
		})
	}

	return PhishingIndustryProfileReport{
		GeneratedAt: time.Now().UTC(),
		Profiles:    entries,
	}, nil
}

var phishingIndustryProfileReportTmpl = template.Must(template.New("phishing-industry-profiles").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing BAS Industry Profiles</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:24px}
.profile{border:1px solid #e8edf4;border-radius:8px;padding:16px 20px;margin-bottom:16px}
.profile h2{font-size:1rem;font-weight:800;margin-bottom:8px}
.describe{font-size:.85rem;margin-bottom:8px}
.priority-summary{font-size:.8rem;color:#3a4656;font-family:monospace}
</style>
</head>
<body>
<h1>Phishing BAS Industry Profiles</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
{{range .Profiles}}
<div class="profile">
  <h2>{{.Name}}</h2>
  <div class="describe">{{.Describe}}</div>
  <div class="priority-summary">{{.PrioritySummary}}</div>
</div>
{{end}}
</body>
</html>
`))

// PhishingIndustryProfileReportHTML renders the report as a plain
// styled HTML page. html/template auto-escapes every field.
func PhishingIndustryProfileReportHTML(w io.Writer, rep PhishingIndustryProfileReport) error {
	return phishingIndustryProfileReportTmpl.Execute(w, rep)
}
