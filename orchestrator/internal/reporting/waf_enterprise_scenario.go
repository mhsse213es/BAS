package reporting

// WAF exploit-prevention scenario report -- HTML only (no PDF, same
// deliberately lightweight first wiring pass as the WAF coverage
// report). This package only formats; it consumes
// internal/wafassessment's seed scenario, seed fixtures, and
// EvaluateScenario, and knows nothing about how the aggregation rule
// itself works.

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
)

// WAFExploitPreventionVectorEntry is one contributing vector's
// evaluated outcome, carried into the report verbatim from
// internal/wafassessment.
type WAFExploitPreventionVectorEntry struct {
	VectorID       string
	Severity       string
	Verdict        string
	EvidenceSource string
	Reason         string
}

// WAFExploitPreventionScenarioReport is the canonical input to
// WAFExploitPreventionScenarioReportHTML. Build it with
// BuildExploitPreventionScenarioReport.
type WAFExploitPreventionScenarioReport struct {
	GeneratedAt       time.Time
	Objective         string
	Outcome           string
	Summary           string
	Assertions        []WAFExploitPreventionVectorEntry
	UntestedVectorIDs []string
}

// BuildExploitPreventionScenarioReport builds the report from
// wafassessment's real, current seed scenario, seed fixtures, and the
// real wafcatalog -- the same data any future JSON endpoint would
// serve, so the HTML report can never drift from it.
func BuildExploitPreventionScenarioReport() (WAFExploitPreventionScenarioReport, error) {
	scenario, err := wafassessment.AudspectExploitPreventionScenario()
	if err != nil {
		return WAFExploitPreventionScenarioReport{}, fmt.Errorf("loading exploit-prevention scenario: %w", err)
	}
	fixtures, err := wafassessment.AudspectExploitPreventionFixtures()
	if err != nil {
		return WAFExploitPreventionScenarioReport{}, fmt.Errorf("loading exploit-prevention fixtures: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return WAFExploitPreventionScenarioReport{}, fmt.Errorf("loading attack catalog: %w", err)
	}
	result, err := wafassessment.EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return WAFExploitPreventionScenarioReport{}, fmt.Errorf("evaluating exploit-prevention scenario: %w", err)
	}

	entries := make([]WAFExploitPreventionVectorEntry, 0, len(result.Assertions))
	for _, a := range result.Assertions {
		entries = append(entries, WAFExploitPreventionVectorEntry{
			VectorID:       a.VectorID,
			Severity:       string(a.Severity),
			Verdict:        string(a.Verdict),
			EvidenceSource: string(a.EvidenceSource),
			Reason:         a.Reason,
		})
	}

	return WAFExploitPreventionScenarioReport{
		GeneratedAt:       time.Now().UTC(),
		Objective:         scenario.Objective,
		Outcome:           string(result.Outcome),
		Summary:           result.Summary,
		Assertions:        entries,
		UntestedVectorIDs: result.UntestedVectorIDs,
	}, nil
}

var wafExploitPreventionReportTmpl = template.Must(template.New("waf-exploit-prevention").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Exploit Prevention Scenario</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.objective{font-size:.9rem;margin-bottom:12px}
.outcome{display:inline-block;font-size:.85rem;font-weight:700;text-transform:uppercase;padding:4px 10px;border-radius:4px;margin-bottom:12px}
.outcome-pass{background:#e3f6e8;color:#1a7d3f}
.outcome-fail{background:#fdeaea;color:#b3261e}
.outcome-incomplete{background:#f2f3f5;color:#5a6472}
.summary{font-size:.8rem;color:#3a4656;font-family:monospace;margin-bottom:20px}
.vector{border:1px solid #e8edf4;border-radius:8px;padding:10px 16px;margin-bottom:8px;display:flex;justify-content:space-between}
.untested{color:#6b7689;font-size:.85rem;margin-top:16px}
.limitations{font-size:.75rem;color:#6b7689;margin-top:24px;border-top:1px solid #e8edf4;padding-top:12px}
</style>
</head>
<body>
<h1>Exploit Prevention and Attack-Chain Validation</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
<div class="objective">{{.Objective}}</div>
<div class="outcome outcome-{{.Outcome}}">{{.Outcome}}</div>
<div class="summary">{{.Summary}}</div>
{{range .Assertions}}
<div class="vector">
  <span>{{.VectorID}} ({{.Severity}})</span>
  <span>{{.Verdict}} -- {{.EvidenceSource}}</span>
</div>
{{end}}
{{if .UntestedVectorIDs}}
<div class="untested">Untested: {{range $i, $v := .UntestedVectorIDs}}{{if $i}}, {{end}}{{$v}}{{end}}</div>
{{end}}
<div class="limitations">
Limitations: every assertion above is fixture-validated, not a claim about a deployed WAF's live efficacy.
This is one of ten planned enterprise assessment scenarios; the other nine, and the enterprise-domain
grouping above them, are not yet built. Real HTTP execution against a deployed WAF is not yet built.
</div>
</body>
</html>
`))

// WAFExploitPreventionScenarioReportHTML renders the report as a
// plain styled HTML page. html/template auto-escapes every field, so
// a reason or vector ID can never inject markup into the page.
func WAFExploitPreventionScenarioReportHTML(w io.Writer, rep WAFExploitPreventionScenarioReport) error {
	return wafExploitPreventionReportTmpl.Execute(w, rep)
}
