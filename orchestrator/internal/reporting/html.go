package reporting

import (
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"
	"time"
)

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("02 Jan 2006, 15:04 UTC")
	},
	"fmtScore": func(f float64) string { return fmt.Sprintf("%.1f", f) },
	"pct":      func(f float64) string { return fmt.Sprintf("%.0f%%", f) },
	"riskColor": func(cls string) string {
		switch strings.ToLower(cls) {
		case "protected":
			return "#238636"
		case "low risk":
			return "#3fb950"
		case "medium risk":
			return "#d29922"
		case "high risk":
			return "#f85149"
		case "critical":
			return "#da3633"
		}
		return "#6e7681"
	},
	"sevColor": func(sev string) string {
		switch sev {
		case "Critical":
			return "#da3633"
		case "High":
			return "#f0883e"
		case "Medium":
			return "#d29922"
		}
		return "#6e7681"
	},
	"tacticColor": func(pct int) string {
		switch {
		case pct >= 80:
			return "#238636"
		case pct >= 50:
			return "#d29922"
		default:
			return "#da3633"
		}
	},
	"barWidth": func(f float64) int {
		v := int(math.Round(f))
		if v < 0 {
			return 0
		}
		if v > 100 {
			return 100
		}
		return v
	},
	"compColor": func(pct float64) string {
		switch {
		case pct >= 70:
			return "#238636"
		case pct >= 40:
			return "#d29922"
		default:
			return "#da3633"
		}
	},
	"upper": strings.ToUpper,
}).Parse(reportHTML))

// GenerateHTML writes a self-contained HTML report to w.
func GenerateHTML(w io.Writer, r *FullReport, compliance []ComplianceSummaryRow) error {
	data := struct {
		*FullReport
		Compliance []ComplianceSummaryRow
	}{r, compliance}
	return reportTmpl.Execute(w, data)
}

// ComplianceSummaryRow is one framework row in the compliance table.
type ComplianceSummaryRow struct {
	Framework     string
	TotalControls int
	Tested        int
	Passing       int
	Failing       int
	Untested      int
	CompliancePct float64
	CoveragePct   float64
}

// ── Template ──────────────────────────────────────────────────────────────────

const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BAS Security Assessment Report — {{.Agent.Hostname}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#1a1a2e;background:#fff;line-height:1.5}
a{color:#1a56db}
h1{font-size:1.4rem;color:#0b1420;border-bottom:2px solid #2f81f7;padding-bottom:6px;margin:28px 0 16px}
h2{font-size:1.05rem;color:#152338;margin:20px 0 10px}
h3{font-size:0.9rem;color:#152338;margin:14px 0 8px}
p{margin-bottom:8px}

/* Page layout */
.page{padding:32px 40px;max-width:960px;margin:0 auto}
@media print{
  .page{page-break-after:always;padding:24px 28px}
  .page:last-child{page-break-after:avoid}
  body{font-size:11px}
}

/* Cover */
.cover{display:flex;flex-direction:column;min-height:80vh;justify-content:center;border-bottom:3px solid #2f81f7}
.cover-logo{font-size:1.6rem;font-weight:900;color:#0b1420;letter-spacing:-0.04em;margin-bottom:32px}
.cover-logo span{color:#2f81f7}
.cover-title{font-size:2.2rem;font-weight:700;color:#0b1420;margin-bottom:8px}
.cover-sub{font-size:1rem;color:#6e7681;margin-bottom:32px}
.cover-table td{padding:6px 16px 6px 0;color:#444;font-size:0.88rem}
.cover-table td:first-child{font-weight:600;color:#0b1420;min-width:120px}
.confidential{display:inline-block;background:#fef3c7;color:#92400e;border:1px solid #f59e0b;
  padding:3px 10px;border-radius:3px;font-size:0.75rem;font-weight:700;margin-top:24px}

/* Risk badge */
.risk-badge{display:inline-flex;align-items:center;gap:12px;padding:12px 20px;
  border-radius:6px;font-size:1rem;font-weight:700;margin-bottom:20px;border:1.5px solid currentColor}

/* Score cards */
.score-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px}
.scard{border:1px solid #e5e7eb;border-radius:8px;padding:14px;background:#f9fafb}
.scard-label{font-size:0.75rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px}
.scard-value{font-size:1.6rem;font-weight:700;margin-bottom:8px}
.scard-bar{height:6px;background:#e5e7eb;border-radius:3px;overflow:hidden}
.scard-bar-fill{height:100%;border-radius:3px}

/* Tables */
table{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:0.82rem}
th{background:#0b1420;color:#fff;padding:8px 10px;text-align:left;font-weight:600;font-size:0.78rem}
td{padding:7px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}
tr:nth-child(even) td{background:#f9fafb}
tr:last-child td{border-bottom:none}

/* Severity dots */
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px;vertical-align:middle}

/* Tactic bar */
.tbar-wrap{width:100%;height:8px;background:#e5e7eb;border-radius:4px;overflow:hidden;display:inline-block;min-width:80px;vertical-align:middle}
.tbar-fill{height:100%;border-radius:4px}

/* Compliance table */
.comp-pct{font-weight:700}

/* Findings */
.remediation{background:#f9fafb;border-left:3px solid #2f81f7;padding:6px 10px;font-size:0.78rem;color:#444;margin-top:4px;border-radius:0 4px 4px 0}

/* Tools list */
.tool-tag{display:inline-block;background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe;
  padding:2px 8px;border-radius:12px;font-size:0.75rem;margin:3px}

/* Footer */
.footer{border-top:1px solid #e5e7eb;padding:16px 0;font-size:0.72rem;color:#9ca3af;
  display:flex;justify-content:space-between;margin-top:32px}
</style>
</head>
<body>

<!-- ═══ COVER PAGE ════════════════════════════════════════════════════════ -->
<div class="page">
<div class="cover">
  <div class="cover-logo">Aud<span>spect</span> BAS</div>
  <div class="cover-title">Security Assessment Report</div>
  <div class="cover-sub">Breach &amp; Attack Simulation — Endpoint Posture Report</div>
  <table class="cover-table">
    <tr><td>Agent</td><td><strong>{{.Agent.Hostname}}</strong> ({{.Agent.IPAddress}})</td></tr>
    <tr><td>OS / Username</td><td>{{.Agent.OSVersion}} &nbsp;·&nbsp; {{.Agent.Username}}</td></tr>
    <tr><td>Environment</td><td>{{.Agent.EnvLabel}}</td></tr>
    <tr><td>Assessment Date</td><td>{{fmtTime .Summary.LastRunAt}}</td></tr>
    <tr><td>Report Generated</td><td>{{fmtTime .GeneratedAt}}</td></tr>
    <tr><td>Total Runs</td><td>{{.Summary.TotalRuns}}</td></tr>
    <tr><td>Last Scenario</td><td>{{.Summary.LastScenarioName}}</td></tr>
  </table>
  <div class="confidential">⚠ CONFIDENTIAL — For authorized use only</div>
</div>
<div class="footer">
  <span>Audspect BAS Platform</span>
  <span>Classification: Confidential</span>
  <span>{{fmtTime .GeneratedAt}}</span>
</div>
</div>

<!-- ═══ 1. EXECUTIVE SUMMARY ════════════════════════════════════════════ -->
<div class="page">
<h1>1. Executive Summary</h1>

<div class="risk-badge" style="color:{{riskColor .Summary.Classification}};border-color:{{riskColor .Summary.Classification}};background:{{riskColor .Summary.Classification}}18">
  <span style="font-size:1.8rem">{{.Summary.RiskScore}}</span>
  <span>Risk Score / 100&emsp;—&emsp;{{.Summary.Classification}}</span>
</div>

<div class="score-row">
  <div class="scard">
    <div class="scard-label">Prevention Score</div>
    <div class="scard-value" style="color:#238636">{{fmtScore .Summary.PreventionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .Summary.PreventionScore}}%;background:#238636"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Severity-weighted pass rate</div>
  </div>
  <div class="scard">
    <div class="scard-label">Exposure Score</div>
    <div class="scard-value" style="color:{{riskColor .Summary.Classification}}">{{fmtScore .Summary.ExposureScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .Summary.ExposureScore}}%;background:#da3633"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Higher = worse. Tactic-weighted fail rate</div>
  </div>
  <div class="scard">
    <div class="scard-label">Tactic Coverage</div>
    <div class="scard-value" style="color:#2f81f7">{{fmtScore .Summary.KillChainCoverage}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .Summary.KillChainCoverage}}%;background:#2f81f7"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Breadth — of 14 ATT&amp;CK tactics tested</div>
  </div>
  <div class="scard">
    <div class="scard-label">Defense Rate</div>
    <div class="scard-value" style="color:#238636">{{fmtScore .Summary.CoverageScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .Summary.CoverageScore}}%;background:#238636"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Tactics fully blocked (zero failures)</div>
  </div>
  <div class="scard">
    <div class="scard-label">Kill-Chain Amplifier</div>
    <div class="scard-value" style="color:#d29922">{{fmtScore .Summary.KillChainAmplifier}}×</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .Summary.KillChainAmplifier}}%;background:#d29922"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Consecutive kill-chain phase multiplier</div>
  </div>
</div>

<table>
  <tr><th colspan="2">Assessment Statistics</th></tr>
  <tr><td>Total Techniques Tested</td><td><strong>{{.Summary.TotalTechniques}}</strong></td></tr>
  <tr><td>Techniques Passed</td><td style="color:#238636"><strong>{{.Summary.PassedTechniques}}</strong></td></tr>
  <tr><td>Techniques Failed</td><td style="color:#da3633"><strong>{{.Summary.FailedTechniques}}</strong></td></tr>
  <tr><td>Trend vs. Previous Run</td><td><strong>{{.Summary.Trend}}</strong></td></tr>
  <tr><td>Last Run At</td><td>{{fmtTime .Summary.LastRunAt}}</td></tr>
  <tr><td>Last Scenario</td><td>{{.Summary.LastScenarioName}}</td></tr>
  <tr><td>Total Runs on Record</td><td>{{.Summary.TotalRuns}}</td></tr>
</table>

<h2>Key Recommendations</h2>
<ol style="padding-left:20px;line-height:1.9">
{{range .Summary.Recommendations}}<li>{{.}}</li>{{end}}
</ol>

<div class="footer">
  <span>{{.Agent.Hostname}} — Executive Summary</span><span>Page 2</span>
</div>
</div>

<!-- ═══ 2. CRITICAL & HIGH FINDINGS ════════════════════════════════════ -->
<div class="page">
<h1>2. Critical &amp; High Findings</h1>
{{if .TopFindings}}
<p style="color:#6e7681;margin-bottom:14px">The following techniques succeeded against this endpoint — meaning the associated security controls did <strong>not</strong> prevent or detect the attack.</p>
<table>
  <thead><tr>
    <th>Severity</th><th>Technique</th><th>Tactic</th><th>Details &amp; Remediation</th>
  </tr></thead>
  <tbody>
  {{range .TopFindings}}
  <tr>
    <td><span class="dot" style="background:{{sevColor .Severity}}"></span>{{.Severity}}</td>
    <td><code>{{.TechniqueID}}</code><br>{{.TechniqueName}}</td>
    <td>{{.Tactic}}</td>
    <td>
      {{.Details}}
      {{if .Remediation}}<div class="remediation">{{.Remediation}}</div>{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#238636;font-weight:600">✓ No Critical or High severity failures in the latest run. Continue to validate with future assessments.</p>
{{end}}

<div class="footer">
  <span>{{.Agent.Hostname}} — Critical Findings</span><span>Page 3</span>
</div>
</div>

<!-- ═══ 3. ATT&CK TACTIC COVERAGE ══════════════════════════════════════ -->
<div class="page">
<h1>3. MITRE ATT&amp;CK Tactic Coverage</h1>
<p style="color:#6e7681;margin-bottom:14px">Tactic-level pass/fail breakdown from the latest scenario run. Tactics with no tested techniques are omitted.</p>
{{if .TacticHeatmap}}
<table>
  <thead><tr>
    <th>Tactic</th><th>Risk Weight</th><th>Passed</th><th>Failed</th><th>Total</th><th>Pass Rate</th><th style="min-width:120px">Coverage Bar</th>
  </tr></thead>
  <tbody>
  {{range .TacticHeatmap}}
  <tr>
    <td style="font-weight:600">{{.Tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .Weight}}"></span>{{.Weight}}</td>
    <td style="color:#238636">{{.Passed}}</td>
    <td style="color:{{if gt .Failed 0}}#da3633{{else}}#238636{{end}}">{{.Failed}}</td>
    <td>{{.Total}}</td>
    <td style="font-weight:700;color:{{tacticColor .PassPct}}">{{.PassPct}}%</td>
    <td>
      <div class="tbar-wrap">
        <div class="tbar-fill" style="width:{{.PassPct}}%;background:{{tacticColor .PassPct}}"></div>
      </div>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No tactic data available. Run a scenario with MITRE-mapped techniques.</p>
{{end}}

<div class="footer">
  <span>{{.Agent.Hostname}} — ATT&amp;CK Coverage</span><span>Page 4</span>
</div>
</div>

<!-- ═══ 4. COMPLIANCE STATUS ════════════════════════════════════════════ -->
<div class="page">
<h1>4. Regulatory Compliance Status</h1>
<p style="color:#6e7681;margin-bottom:14px">Compliance percentages are derived from BAS evidence. A control is <em>Passing</em> when all mapped techniques passed; <em>Failing</em> when at least one failed; <em>Untested</em> when no mapped techniques were included in the run.</p>
{{if .Compliance}}
<table>
  <thead><tr>
    <th>Framework</th><th>Total Controls</th><th>Tested</th><th>Passing</th><th>Failing</th><th>Untested</th><th>Compliance</th><th>Coverage</th>
  </tr></thead>
  <tbody>
  {{range .Compliance}}
  <tr>
    <td style="font-weight:600">{{.Framework}}</td>
    <td>{{.TotalControls}}</td>
    <td>{{.Tested}}</td>
    <td style="color:#238636">{{.Passing}}</td>
    <td style="color:{{if gt .Failing 0}}#da3633{{else}}#238636{{end}}">{{.Failing}}</td>
    <td style="color:#6e7681">{{.Untested}}</td>
    <td class="comp-pct" style="color:{{compColor .CompliancePct}}">{{pct .CompliancePct}}</td>
    <td style="color:#2f81f7">{{pct .CoveragePct}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">Compliance data unavailable.</p>
{{end}}

<div class="footer">
  <span>{{.Agent.Hostname}} — Compliance Status</span><span>Page 5</span>
</div>
</div>

<!-- ═══ 5. SECURITY CONTROLS INVENTORY ══════════════════════════════════ -->
<div class="page">
<h1>5. Detection Coverage by Tactic</h1>
{{if .DetectionCategories}}
<p style="color:#6e7681;margin-bottom:14px">Per-tactic verdict derived from this run's executed checks: <strong>PASS</strong> when every check in the tactic was prevented, <strong>FAIL</strong> when any check succeeded against the endpoint, <strong>UNKNOWN</strong> when the tactic was only skipped.</p>
<table>
  <thead><tr><th>Tactic</th><th>Verdict</th></tr></thead>
  <tbody>
  {{range .DetectionCategories}}
  <tr>
    <td>{{.Name}}</td>
    <td style="font-weight:600;color:{{if eq .Result "pass"}}#238636{{else if eq .Result "fail"}}#da3633{{else}}#6e7681{{end}}">{{upper .Result}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No tactic-level results were recorded for this run.</p>
{{end}}

<div class="footer">
  <span>{{.Agent.Hostname}} — Security Inventory</span><span>Page 6</span>
</div>
</div>

<!-- ═══ 6. SCENARIO RUN HISTORY ═════════════════════════════════════════ -->
<div class="page">
<h1>6. Scenario Run History</h1>
{{if .Runs}}
<table>
  <thead><tr>
    <th>Date</th><th>Scenario</th><th>Status</th><th>Risk Score</th><th>Classification</th><th>Prevention</th><th>Exposure</th><th>Tested</th><th>Failed</th>
  </tr></thead>
  <tbody>
  {{range .Runs}}
  <tr>
    <td style="white-space:nowrap">{{fmtTime .StartedAt}}</td>
    <td>{{.ScenarioName}}</td>
    <td>{{.Status}}</td>
    <td style="font-weight:700">{{.RiskScore}}</td>
    <td>{{.Classification}}</td>
    <td>{{fmtScore .PreventionScore}}%</td>
    <td>{{fmtScore .ExposureScore}}%</td>
    <td>{{.TotalTechniques}}</td>
    <td style="color:{{if gt .FailedTechniques 0}}#da3633{{else}}#238636{{end}}">{{.FailedTechniques}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No completed scenario runs found for this agent.</p>
{{end}}

<div class="footer">
  <span>{{.Agent.Hostname}} — Run History</span>
  <span>Generated {{fmtTime .GeneratedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>

</body>
</html>`
