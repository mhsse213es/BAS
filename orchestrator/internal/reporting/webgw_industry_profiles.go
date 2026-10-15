package reporting

// WebGW industry-profile report -- HTML only (no PDF; unlike the AD
// assessment report, this has no Chrome-sidecar dependency yet, kept
// deliberately lightweight for a first production wiring pass). This
// package only formats; it consumes internal/webgwefficacy's
// IndustryProfileNames/BuildIndustryProfile/AudspectWebGWCoverageReport
// and knows nothing about how industry profiles or coverage data are
// built. Every field is a plain rendered string from webgwefficacy,
// auto-escaped by html/template -- never a computed verdict of its own.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/webgwefficacy"
)

// WebGWIndustryProfileEntry is one shipped industry profile's
// rendered summary, carried into the report verbatim from
// internal/webgwefficacy.
type WebGWIndustryProfileEntry struct {
	Name            string
	Describe        string
	PrioritySummary string
}

// WebGWIndustryProfileReport is the canonical input to
// WebGWIndustryProfileReportHTML. Build it with
// BuildWebGWIndustryProfileReport.
type WebGWIndustryProfileReport struct {
	GeneratedAt time.Time
	Profiles    []WebGWIndustryProfileEntry
}

// BuildWebGWIndustryProfileReport builds the report from
// webgwefficacy's real, current coverage report and every shipped
// industry profile -- the same data the /api/webgw/industry-profiles
// JSON endpoint serves, so the HTML report can never drift from it.
func BuildWebGWIndustryProfileReport() (WebGWIndustryProfileReport, error) {
	coverageReport, err := webgwefficacy.AudspectWebGWCoverageReport()
	if err != nil {
		return WebGWIndustryProfileReport{}, fmt.Errorf("loading coverage report: %w", err)
	}

	names := webgwefficacy.IndustryProfileNames()
	entries := make([]WebGWIndustryProfileEntry, 0, len(names))
	for _, name := range names {
		profile, ok, err := webgwefficacy.BuildIndustryProfile(name)
		if !ok {
			return WebGWIndustryProfileReport{}, fmt.Errorf("profile %q not found", name)
		}
		if err != nil {
			return WebGWIndustryProfileReport{}, fmt.Errorf("building profile %q: %w", name, err)
		}
		entries = append(entries, WebGWIndustryProfileEntry{
			Name:            name,
			Describe:        profile.Describe(),
			PrioritySummary: profile.PrioritySummary(coverageReport),
		})
	}

	return WebGWIndustryProfileReport{
		GeneratedAt: time.Now().UTC(),
		Profiles:    entries,
	}, nil
}

var webgwIndustryProfileReportTmpl = template.Must(template.New("webgw-industry-profiles").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebGW Industry Profiles</title>
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
<h1>WebGW Industry Profiles</h1>
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

// WebGWIndustryProfileReportHTML renders the report as a plain
// styled HTML page. html/template auto-escapes every field, so a
// profile's rendered text can never inject markup into the page.
func WebGWIndustryProfileReportHTML(w io.Writer, rep WebGWIndustryProfileReport) error {
	return webgwIndustryProfileReportTmpl.Execute(w, rep)
}
