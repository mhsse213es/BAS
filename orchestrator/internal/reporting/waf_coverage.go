package reporting

// WAF coverage report -- HTML only (no PDF; same deliberately
// lightweight first production-wiring pass as EmailGW's and WebGW's
// own reports). This package only formats; it consumes
// internal/wafefficacy's AudspectWAFCoverageReport and knows nothing
// about how coverage data is built.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/wafefficacy"
)

// WAFCoverageDomainEntry is one domain's status, carried into the
// report verbatim from internal/wafefficacy.
type WAFCoverageDomainEntry struct {
	DomainID        string
	DomainName      string
	Status          string
	ExclusionReason string
}

// WAFCoverageReport is the canonical input to WAFCoverageReportHTML.
// Build it with BuildWAFCoverageReport.
type WAFCoverageReport struct {
	GeneratedAt time.Time
	Summary     string
	Domains     []WAFCoverageDomainEntry
}

// BuildWAFCoverageReport builds the report from wafefficacy's real,
// current coverage report -- the same data the /api/waf/coverage JSON
// endpoint serves, so the HTML report can never drift from it.
func BuildWAFCoverageReport() (WAFCoverageReport, error) {
	report, err := wafefficacy.AudspectWAFCoverageReport()
	if err != nil {
		return WAFCoverageReport{}, fmt.Errorf("loading WAF coverage report: %w", err)
	}

	domains := report.DomainsForDisplay()
	entries := make([]WAFCoverageDomainEntry, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, WAFCoverageDomainEntry{
			DomainID:        d.DomainID,
			DomainName:      d.DomainName,
			Status:          string(d.Status),
			ExclusionReason: d.ExclusionReason,
		})
	}

	return WAFCoverageReport{
		GeneratedAt: time.Now().UTC(),
		Summary:     report.Summary(),
		Domains:     entries,
	}, nil
}

var wafCoverageReportTmpl = template.Must(template.New("waf-coverage").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Coverage</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.summary{font-size:.85rem;color:#3a4656;font-family:monospace;margin-bottom:24px}
.domain{border:1px solid #e8edf4;border-radius:8px;padding:12px 20px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:baseline}
.domain h2{font-size:.95rem;font-weight:800;margin:0}
.status{font-size:.75rem;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px}
.status-covered{background:#e3f6e8;color:#1a7d3f}
.status-excluded{background:#fdeee0;color:#b35c00}
.status-not-covered{background:#f2f3f5;color:#5a6472}
.exclusion-reason{font-size:.75rem;color:#6b7689;margin-top:4px}
</style>
</head>
<body>
<h1>WAF Coverage</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
<div class="summary">{{.Summary}}</div>
{{range .Domains}}
<div class="domain">
  <div>
    <h2>{{.DomainID}} -- {{.DomainName}}</h2>
    {{if .ExclusionReason}}<div class="exclusion-reason">{{.ExclusionReason}}</div>{{end}}
  </div>
  <span class="status status-{{.Status}}">{{.Status}}</span>
</div>
{{end}}
</body>
</html>
`))

// WAFCoverageReportHTML renders the report as a plain styled HTML
// page. html/template auto-escapes every field, so a status or
// exclusion reason can never inject markup into the page.
func WAFCoverageReportHTML(w io.Writer, rep WAFCoverageReport) error {
	return wafCoverageReportTmpl.Execute(w, rep)
}
