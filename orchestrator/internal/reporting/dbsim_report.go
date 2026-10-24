package reporting

// dbsim run report -- printable HTML for one stored dbsim_runs row. Like the
// phishing report it renders what was persisted and never recomputes a
// verdict. Unlike it, no dimension is dropped: pass, fail, not_expected,
// skipped and unverifiable all render as themselves. The report does not read
// or write any security score.

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dlpreport"
)

// SetDBSimReportHeaders sets the response headers for the printable report and
// for its error responses: HTML (or whatever the caller overrides), never
// cached, never sniffed.
func SetDBSimReportHeaders(h http.Header) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

// DBSimReportOptions carries what is not in the stored report itself.
type DBSimReportOptions struct {
	RunID       string
	GeneratedAt time.Time
}

type dbsimDimView struct {
	Name        string
	State       string
	Remediation string
}

type dbsimReportView struct {
	R           dbsim.StoredReport
	RunID       string
	Generated   string
	Dims        []dbsimDimView
	Summary     dbsim.Summary
	AlertSource bool // true when the alert source was unavailable
}

// BuildDBSimReport renders one stored report as HTML.
func BuildDBSimReport(r dbsim.StoredReport, opts DBSimReportOptions) (string, error) {
	gen := opts.GeneratedAt
	if gen.IsZero() {
		gen = time.Now().UTC()
	}
	// Remediation only for an established failure: the dimension is fail AND
	// the scenario result is a graded PASS/FAIL (never ERROR or SKIPPED).
	established := r.Result == dbsim.ResultPass || r.Result == dbsim.ResultFail
	mk := func(name, key string, g dbsim.DimensionGrade) dbsimDimView {
		v := dbsimDimView{Name: name, State: string(g)}
		if v.State == "" {
			v.State = "unverifiable"
		}
		if established && g == dbsim.DimFail {
			v.Remediation = DBSimRemediation(r.Scenario.ID, key)
		}
		return v
	}
	d := r.Dimensions
	view := dbsimReportView{
		R: r, RunID: opts.RunID, Generated: gen.UTC().Format("02 Jan 2006 15:04 UTC"),
		Dims: []dbsimDimView{
			mk("Prevention", "prevention", d.Prevention),
			mk("Detection", "detection", d.Detection),
			// Response is never tested by this product.
			{Name: "Response", State: "not tested"},
			mk("Classification", "classification", d.Classification),
			mk("Audit", "audit", d.Audit),
			mk("Policy", "policy", d.Policy),
		},
		Summary:     dbsim.Summarize([]dbsim.StoredReport{r}),
		AlertSource: r.Record.Telemetry == dlpreport.TelemetryUnverifiable,
	}
	var buf bytes.Buffer
	if err := dbsimReportTmpl.Execute(&buf, view); err != nil {
		return "", fmt.Errorf("reporting: render dbsim report: %w", err)
	}
	return buf.String(), nil
}

var dbsimReportTmpl = template.Must(template.New("dbsim-run").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Database Security Simulation - {{.R.Scenario.ID}}</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
h2{font-size:1.05rem;margin-top:24px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.result{display:inline-block;font-weight:700;padding:4px 10px;border-radius:4px;background:#f2f3f5;color:#3a4656}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border:1px solid #e8edf4;padding:6px 10px;text-align:left;vertical-align:top}
.state{font-weight:700}
.note{border:1px solid #e8edf4;border-radius:6px;padding:8px 12px;margin:8px 0;font-size:.85rem}
.warn{border-color:#b3261e;background:#fdeaea;color:#7a1a16}
.fix{font-size:.8rem;color:#3a4656}
.small{font-size:.75rem;color:#6b7689}
@media print{body{padding:12px}}
</style>
</head>
<body>
<h1>Database Security Simulation</h1>
<div class="generated">Generated {{.Generated}} -- run {{.RunID}} -- scenario {{.R.Scenario.ID}} (v{{.R.Scenario.Version}}), engine {{.R.Scenario.Engine}}</div>
<div class="result">{{.R.Result}}</div>
<p>{{.R.Reason}}</p>
<p><strong>Control objective:</strong> {{.R.Scenario.ControlObjective}}</p>
<p><strong>Action attempted:</strong> {{.R.Scenario.ActionAttempted}}</p>
<p class="small">This simulation does not contribute to the overall security score.</p>

<h2>Summary for this scenario</h2>
<table>
<tr><th>Prevention (blocked / assessable)</th><td>{{.Summary.PreventionBlocked}} / {{.Summary.PreventionAssessable}}</td></tr>
<tr><th>Detection (caught / assessable)</th><td>{{.Summary.DetectionCaught}} / {{.Summary.DetectionAssessable}}</td></tr>
<tr><th>Response</th><td>Not tested</td></tr>
<tr><th>Unable to assess</th><td>{{.Summary.UnableToAssess}}</td></tr>
</table>

<h2>Dimensions</h2>
<table>
<tr><th>Dimension</th><th>State</th><th>Remediation</th></tr>
{{range .Dims}}<tr><td>{{.Name}}</td><td class="state">{{.State}}</td><td class="fix">{{.Remediation}}</td></tr>
{{end}}</table>

{{if .AlertSource}}<div class="note warn">Telemetry could not be verified (see limitations). This is not a miss.</div>{{end}}

<h2>Record</h2>
<table>
<tr><th>Enforcement</th><td>{{.R.Record.Enforcement}}</td></tr>
<tr><th>Classification</th><td>{{.R.Record.Classification}}</td></tr>
<tr><th>Telemetry</th><td>{{.R.Record.Telemetry}}</td></tr>
<tr><th>Response</th><td>Not tested</td></tr>
<tr><th>Confidence</th><td>{{.R.Record.Confidence}}</td></tr>
<tr><th>Source</th><td>{{.R.Record.Provenance.SourceSystem}} / {{.R.Record.Provenance.CollectionMethod}}</td></tr>
<tr><th>Correlation ID</th><td>{{.R.Record.Provenance.CorrelationID}}</td></tr>
<tr><th>Integrity hash</th><td>{{.R.Record.Provenance.IntegrityHash}}</td></tr>
</table>

<h2>Evidence</h2>
<table>
<tr><th>Principal</th><td>{{.R.Evidence.Principal}}</td></tr>
<tr><th>Marker</th><td>{{.R.Evidence.Marker}}</td></tr>
<tr><th>Probe ran / denied / rows read</th><td>{{.R.Evidence.ProbeRan}} / {{.R.Evidence.Denied}} / {{.R.Evidence.RowsRead}}</td></tr>
<tr><th>Error class</th><td>{{.R.Evidence.ErrorClass}}</td></tr>
<tr><th>Cleanup</th><td>{{.R.Evidence.CleanupStatus}}</td></tr>
<tr><th>Alerts matched</th><td>{{.R.Evidence.Corr.Alerts}} ({{.R.Evidence.Corr.Match}})</td></tr>
</table>
{{range .R.Evidence.Notes}}<div class="note">{{.}}</div>
{{end}}
{{if .R.Evidence.Corr.AlertRefs}}<h2>Matched alerts</h2>
<table>
<tr><th>ID</th><th>Rule</th><th>Host</th><th>Excerpt</th></tr>
{{range .R.Evidence.Corr.AlertRefs}}<tr><td>{{.ID}}</td><td>{{.Rule}}</td><td>{{.Host}}</td><td>{{.Excerpt}}</td></tr>
{{end}}</table>{{end}}

<h2>Limitations</h2>
{{if .R.Record.Limitations}}<div class="note">{{.R.Record.Limitations}}</div>{{end}}
{{if .R.Evidence.Corr.Limitations}}<div class="note">{{.R.Evidence.Corr.Limitations}}</div>{{end}}
<p class="small">Remediation text is general guidance shown only for an established failure; verify against your own environment.</p>
</body>
</html>
`))
