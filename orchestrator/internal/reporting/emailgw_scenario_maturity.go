package reporting

// EmailGW scenario-maturity report -- HTML only, same deliberately
// lightweight production-wiring pass as emailgw_coverage.go. This
// package only formats; it consumes internal/emailgwefficacy's
// ScenarioMaturityEntry rows and knows nothing about how they were
// computed.
//
// Unlike EmailGWCoverageReport, there is NO zero-argument
// BuildEmailGWScenarioMaturityReport() here, and deliberately no
// /api/emailgw/scenario-maturity[.html] handler was added alongside
// this file. emailgwefficacy.BuildScenarioMaturityReport's own
// MaturityVerifiedThroughExecution claim is execution-derived, not a
// static fact: producing a genuine row requires actually running a
// scenario through the real httptest-backed Defender adapter (see
// internal/emailgwefficacy/maturity_live_test.go). Recomputing that on
// every HTTP request would mean re-executing scenarios on every page
// load for no customer benefit -- a different, and worse, kind of
// staleness risk than the hand-maintained-status problem the maturity
// model itself was built to avoid. This report therefore takes
// already-computed rows as an explicit input; the caller (today, only
// a test) is responsible for having produced them from a real run.
// Wiring a live, safe-to-call-per-request path for this report is an
// open, separate decision -- not made unilaterally here.

import (
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
)

// EmailGWScenarioMaturityRow is one EG-ID's status, carried into the
// report verbatim from internal/emailgwefficacy.
type EmailGWScenarioMaturityRow struct {
	ScenarioID string
	Name       string
	Maturity   string
}

// EmailGWScenarioMaturityReport is the canonical input to
// EmailGWScenarioMaturityReportHTML. Build it with
// BuildEmailGWScenarioMaturityReport, from rows the caller already
// computed via emailgwefficacy.BuildScenarioMaturityReport against
// real ScenarioExecutionRecords.
type EmailGWScenarioMaturityReport struct {
	GeneratedAt time.Time
	Rows        []EmailGWScenarioMaturityRow
}

// BuildEmailGWScenarioMaturityReport wraps already-computed maturity
// entries for rendering. It performs no computation and no evidence
// collection of its own -- see this file's own package-level comment
// for why there is no zero-argument variant.
func BuildEmailGWScenarioMaturityReport(entries []emailgwefficacy.ScenarioMaturityEntry, generatedAt time.Time) EmailGWScenarioMaturityReport {
	rows := make([]EmailGWScenarioMaturityRow, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, EmailGWScenarioMaturityRow{
			ScenarioID: e.ScenarioID,
			Name:       e.Name,
			Maturity:   string(e.Maturity),
		})
	}
	return EmailGWScenarioMaturityReport{GeneratedAt: generatedAt, Rows: rows}
}

var emailGWScenarioMaturityReportTmpl = template.Must(template.New("emailgw-scenario-maturity").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EmailGW Scenario Maturity</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.note{font-size:.78rem;color:#6b7689;margin-bottom:24px;max-width:640px}
.row{border:1px solid #e8edf4;border-radius:8px;padding:12px 20px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:baseline}
.row h2{font-size:.95rem;font-weight:800;margin:0}
.status{font-size:.75rem;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px;white-space:nowrap}
.status-verified-through-execution{background:#e3f6e8;color:#1a7d3f}
.status-executed-without-sufficient-evidence{background:#fdeee0;color:#b35c00}
.status-implemented-not-executable{background:#f2f3f5;color:#5a6472}
.status-not-implemented{background:#f2f3f5;color:#5a6472}
</style>
</head>
<body>
<h1>EmailGW Scenario Maturity</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}</div>
<div class="note">Verified through execution means proof through the real Defender adapter's HTTP/JSON code path (httptest-backed or a real tenant) -- it is not proof of effectiveness against an actual customer M365 tenant.</div>
{{range .Rows}}
<div class="row">
  <h2>{{.ScenarioID}}{{if .Name}} -- {{.Name}}{{end}}</h2>
  <span class="status status-{{.Maturity}}">{{.Maturity}}</span>
</div>
{{end}}
</body>
</html>
`))

// EmailGWScenarioMaturityReportHTML renders the report as a plain
// styled HTML page. html/template auto-escapes every field.
func EmailGWScenarioMaturityReportHTML(w io.Writer, rep EmailGWScenarioMaturityReport) error {
	return emailGWScenarioMaturityReportTmpl.Execute(w, rep)
}
