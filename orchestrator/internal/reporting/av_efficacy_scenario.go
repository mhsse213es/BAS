package reporting

// AV/NGAV efficacy scenario report -- HTML only, mirroring
// waf_enterprise_scenario.go's deliberately lightweight first wiring pass.
// This package only formats; it consumes internal/avefficacy's scenario
// registry (EvaluateScenarioBySlug) and knows nothing about how any
// scenario's aggregation rule itself works. Unlike WAF's single Verdict
// field, each entry carries avefficacy's full independent-dimension
// outcome (Finding, Response, Telemetry, Configuration, DetectionLatency)
// so no aggregate score can conceal a verified prevention failure on any
// one dimension (av.txt §4).

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/avefficacy"
)

// AVScenarioVectorEntry is one contributing vector's evaluated outcome,
// carried into the report verbatim from internal/avefficacy.
type AVScenarioVectorEntry struct {
	VectorID       string
	Severity       string
	EvidenceSource string

	Finding           string
	FindingConfidence string
	FindingReason     string

	Response           string
	ResponseConfidence string
	ResponseReason     string

	Telemetry       string
	TelemetryReason string

	Configuration       string // "" when not applicable to this vector
	ConfigurationReason string

	DetectionLatency       string
	DetectionLatencyReason string
}

// AVScenarioReport is the canonical input to AVScenarioReportHTML. Build
// it with BuildAVScenarioReport.
type AVScenarioReport struct {
	ScenarioID        string
	ScenarioName      string
	GeneratedAt       time.Time
	Objective         string
	Outcome           string
	Summary           string
	VectorOutcomes    []AVScenarioVectorEntry
	UntestedVectorIDs []string
}

// BuildAVScenarioReport builds the report for the efficacy scenario
// registered under slug in internal/avefficacy's scenario registry -- the
// same data any JSON endpoint for that slug would serve, so the HTML
// report can never drift from it.
func BuildAVScenarioReport(slug string) (AVScenarioReport, error) {
	scenario, result, err := avefficacy.EvaluateScenarioBySlug(slug)
	if err != nil {
		return AVScenarioReport{}, fmt.Errorf("building report for scenario %q: %w", slug, err)
	}

	entries := make([]AVScenarioVectorEntry, 0, len(result.VectorOutcomes))
	for _, o := range result.VectorOutcomes {
		entries = append(entries, AVScenarioVectorEntry{
			VectorID:       o.VectorID,
			Severity:       string(o.Severity),
			EvidenceSource: string(o.EvidenceSource),

			Finding:           string(o.Finding),
			FindingConfidence: string(o.FindingConfidence),
			FindingReason:     o.FindingReason,

			Response:           string(o.Response),
			ResponseConfidence: string(o.ResponseConfidence),
			ResponseReason:     o.ResponseReason,

			Telemetry:       string(o.Telemetry),
			TelemetryReason: o.TelemetryReason,

			Configuration:       string(o.Configuration),
			ConfigurationReason: o.ConfigurationReason,

			DetectionLatency:       string(o.DetectionLatency),
			DetectionLatencyReason: o.DetectionLatencyReason,
		})
	}

	return AVScenarioReport{
		ScenarioID:        scenario.ID,
		ScenarioName:      scenario.Name,
		GeneratedAt:       time.Now().UTC(),
		Objective:         scenario.Objective,
		Outcome:           string(result.Outcome),
		Summary:           result.Summary,
		VectorOutcomes:    entries,
		UntestedVectorIDs: result.UntestedVectorIDs,
	}, nil
}

var avScenarioReportTmpl = template.Must(template.New("av-efficacy-scenario").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.ScenarioName}}</title>
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
.vector{border:1px solid #e8edf4;border-radius:8px;padding:10px 16px;margin-bottom:8px}
.vector-head{display:flex;justify-content:space-between;font-weight:700}
.dims{font-size:.8rem;color:#3a4656;margin-top:6px;display:grid;grid-template-columns:1fr 1fr;gap:4px}
.untested{color:#6b7689;font-size:.85rem;margin-top:16px}
.limitations{font-size:.75rem;color:#6b7689;margin-top:24px;border-top:1px solid #e8edf4;padding-top:12px}
</style>
</head>
<body>
<h1>{{.ScenarioName}}</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
<div class="objective">{{.Objective}}</div>
<div class="outcome outcome-{{.Outcome}}">{{.Outcome}}</div>
<div class="summary">{{.Summary}}</div>
{{range .VectorOutcomes}}
<div class="vector">
  <div class="vector-head">
    <span>{{.VectorID}} ({{.Severity}})</span>
    <span>{{.EvidenceSource}}</span>
  </div>
  <div class="dims">
    <span>Finding: {{.Finding}} ({{.FindingConfidence}}) -- {{.FindingReason}}</span>
    <span>Response: {{.Response}} -- {{.ResponseReason}}</span>
    <span>Telemetry: {{.Telemetry}} -- {{.TelemetryReason}}</span>
    <span>Configuration: {{if .Configuration}}{{.Configuration}} -- {{.ConfigurationReason}}{{else}}not applicable{{end}}</span>
    <span>Detection latency: {{.DetectionLatency}}{{if .DetectionLatencyReason}} -- {{.DetectionLatencyReason}}{{end}}</span>
  </div>
</div>
{{end}}
{{if .UntestedVectorIDs}}
<div class="untested">Untested: {{range $i, $v := .UntestedVectorIDs}}{{if $i}}, {{end}}{{$v}}{{end}}</div>
{{end}}
<div class="limitations">
Limitations: every outcome above is fixture-validated, not a claim about a deployed AV/NGAV product's live efficacy.
Each dimension (finding, response, telemetry, configuration, detection latency) is reported independently -- no
aggregate score here can conceal a verified prevention failure on any one dimension. Real agent-dispatched
execution against a live endpoint is not yet built for this scenario.
</div>
</body>
</html>
`))

// AVScenarioReportHTML renders rep as a plain styled HTML page.
// html/template auto-escapes every field, so a reason or vector ID can
// never inject markup into the page.
func AVScenarioReportHTML(w io.Writer, rep AVScenarioReport) error {
	return avScenarioReportTmpl.Execute(w, rep)
}
