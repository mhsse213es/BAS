package reporting

// EmailGW coverage report -- HTML only (no PDF; same deliberately
// lightweight first production-wiring pass as WebGW's own industry
// profile report). This package only formats; it consumes
// internal/emailgwefficacy's AudspectEmailGWCoverageReport and knows
// nothing about how coverage data is built. There is no industry-
// profile narrative here, unlike WebGW's report -- emailgwefficacy's
// own Phase 5 deliberately deferred industry profiles (see that
// package's architecture spec), so this report renders the coverage
// areas directly instead of a profile-filtered summary.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// EmailGWCoverageAreaEntry is one taxonomy area's status, carried
// into the report verbatim from internal/emailgwefficacy.
type EmailGWCoverageAreaEntry struct {
	AreaID          string
	AreaName        string
	Status          string
	ExclusionReason string
}

// EmailGWCoverageReport is the canonical input to
// EmailGWCoverageReportHTML. Build it with BuildEmailGWCoverageReport.
type EmailGWCoverageReport struct {
	GeneratedAt time.Time
	Summary     string
	Areas       []EmailGWCoverageAreaEntry
}

// BuildEmailGWCoverageReport builds the report from emailgwefficacy's
// real, current coverage report -- the same data the
// /api/emailgw/coverage JSON endpoint serves, so the HTML report can
// never drift from it.
func BuildEmailGWCoverageReport() (EmailGWCoverageReport, error) {
	report, err := emailgwefficacy.AudspectEmailGWCoverageReport()
	if err != nil {
		return EmailGWCoverageReport{}, fmt.Errorf("loading coverage report: %w", err)
	}

	areas := report.Areas()
	entries := make([]EmailGWCoverageAreaEntry, 0, len(areas))
	for _, a := range areas {
		entries = append(entries, EmailGWCoverageAreaEntry{
			AreaID:          a.AreaID,
			AreaName:        a.AreaName,
			Status:          string(a.Status),
			ExclusionReason: a.ExclusionReason,
		})
	}

	return EmailGWCoverageReport{
		GeneratedAt: time.Now().UTC(),
		Summary:     report.Summary(),
		Areas:       entries,
	}, nil
}

var emailGWCoverageReportTmpl = template.Must(template.New("emailgw-coverage").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EmailGW Coverage</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.summary{font-size:.85rem;color:#3a4656;font-family:monospace;margin-bottom:24px}
.area{border:1px solid #e8edf4;border-radius:8px;padding:12px 20px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:baseline}
.area h2{font-size:.95rem;font-weight:800;margin:0}
.status{font-size:.75rem;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px}
.status-covered{background:#e3f6e8;color:#1a7d3f}
.status-excluded{background:#fdeee0;color:#b35c00}
.status-not-covered{background:#f2f3f5;color:#5a6472}
.exclusion-reason{font-size:.75rem;color:#6b7689;margin-top:4px}
</style>
</head>
<body>
<h1>EmailGW Coverage</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
<div class="summary">{{.Summary}}</div>
{{range .Areas}}
<div class="area">
  <div>
    <h2>{{.AreaID}} -- {{.AreaName}}</h2>
    {{if .ExclusionReason}}<div class="exclusion-reason">{{.ExclusionReason}}</div>{{end}}
  </div>
  <span class="status status-{{.Status}}">{{.Status}}</span>
</div>
{{end}}
</body>
</html>
`))

// EmailGWCoverageReportHTML renders the report as a plain styled
// HTML page. html/template auto-escapes every field, so a status or
// exclusion reason can never inject markup into the page.
func EmailGWCoverageReportHTML(w io.Writer, rep EmailGWCoverageReport) error {
	return emailGWCoverageReportTmpl.Execute(w, rep)
}
