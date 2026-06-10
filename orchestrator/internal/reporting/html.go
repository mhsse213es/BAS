package reporting

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"
	"time"
)

// The template resolves fields by their json-tag name, not their Go field name.
// The orchestrator is built with garble, which renames Go struct fields while
// preserving json tags (so API responses stay stable). html/template looks up
// fields by Go name via reflection, so rendering structs directly fails under
// obfuscation ("can't evaluate field Hostname …"). We therefore render from a
// json round-tripped map[string]any whose keys are the stable tag names. All
// numbers arrive as float64 and all times as RFC3339 strings — the funcs below
// are typed accordingly.
var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"fmtTime": func(v any) string {
		s, _ := v.(string)
		if s == "" {
			return "—"
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil || t.IsZero() {
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
	"tacticColor": func(pct float64) string {
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
//
// It renders from a json-tag-keyed map rather than the FullReport struct
// directly: under garble obfuscation the Go field names are renamed but the
// json tags are preserved, and html/template resolves fields by name via
// reflection. The json round-trip yields stable, tag-named keys the template
// can resolve regardless of obfuscation. Consequently every type reachable from
// here must carry json tags on the fields the template uses.
func GenerateHTML(w io.Writer, r *FullReport, compliance []ComplianceSummaryRow) error {
	payload := struct {
		*FullReport
		Compliance []ComplianceSummaryRow `json:"compliance"`
	}{r, compliance}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	return reportTmpl.Execute(w, data)
}

// ComplianceSummaryRow is one framework row in the compliance table. The json
// tags are load-bearing — see GenerateHTML (template renders by tag name).
type ComplianceSummaryRow struct {
	Framework     string  `json:"framework"`
	TotalControls int     `json:"totalControls"`
	Tested        int     `json:"tested"`
	Passing       int     `json:"passing"`
	Failing       int     `json:"failing"`
	Untested      int     `json:"untested"`
	CompliancePct float64 `json:"compliancePct"`
	CoveragePct   float64 `json:"coveragePct"`
}

// ── Template ──────────────────────────────────────────────────────────────────

const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BAS Security Assessment Report — {{.agent.hostname}}</title>
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
    <tr><td>Agent</td><td><strong>{{.agent.hostname}}</strong> ({{.agent.ipAddress}})</td></tr>
    <tr><td>OS / Username</td><td>{{.agent.osVersion}} &nbsp;·&nbsp; {{.agent.username}}</td></tr>
    <tr><td>Environment</td><td>{{.agent.envLabel}}</td></tr>
    <tr><td>Assessment Date</td><td>{{fmtTime .summary.lastRunAt}}</td></tr>
    <tr><td>Report Generated</td><td>{{fmtTime .generatedAt}}</td></tr>
    <tr><td>Total Runs</td><td>{{.summary.totalRuns}}</td></tr>
    <tr><td>Last Scenario</td><td>{{.summary.lastScenarioName}}</td></tr>
  </table>
  <div class="confidential">⚠ CONFIDENTIAL — For authorized use only</div>
</div>
<div class="footer">
  <span>Audspect BAS Platform</span>
  <span>Classification: Confidential</span>
  <span>{{fmtTime .generatedAt}}</span>
</div>
</div>

<!-- ═══ 1. EXECUTIVE SUMMARY ════════════════════════════════════════════ -->
<div class="page">
<h1>1. Executive Summary</h1>

<div class="risk-badge" style="color:{{riskColor .summary.classification}};border-color:{{riskColor .summary.classification}};background:{{riskColor .summary.classification}}18">
  <span style="font-size:1.8rem">{{.summary.riskScore}}</span>
  <span>Risk Score / 100&emsp;—&emsp;{{.summary.classification}}</span>
</div>

<div class="score-row">
  <div class="scard">
    <div class="scard-label">Prevention Score</div>
    <div class="scard-value" style="color:#238636">{{fmtScore .summary.preventionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.preventionScore}}%;background:#238636"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Severity-weighted pass rate</div>
  </div>
  <div class="scard">
    <div class="scard-label">Exposure Score</div>
    <div class="scard-value" style="color:{{riskColor .summary.classification}}">{{fmtScore .summary.exposureScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.exposureScore}}%;background:#da3633"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Higher = worse. Tactic-weighted fail rate</div>
  </div>
  <div class="scard">
    <div class="scard-label">Tactic Coverage</div>
    <div class="scard-value" style="color:#2f81f7">{{fmtScore .summary.killChainCoverage}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.killChainCoverage}}%;background:#2f81f7"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Breadth — of 14 ATT&amp;CK tactics tested</div>
  </div>
  <div class="scard">
    <div class="scard-label">Defense Rate</div>
    <div class="scard-value" style="color:#238636">{{fmtScore .summary.coverageScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.coverageScore}}%;background:#238636"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Tactics fully blocked (zero failures)</div>
  </div>
  <div class="scard">
    <div class="scard-label">Kill-Chain Amplifier</div>
    <div class="scard-value" style="color:#d29922">{{fmtScore .summary.killChainAmplifier}}×</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.killChainAmplifier}}%;background:#d29922"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Consecutive kill-chain phase multiplier</div>
  </div>
</div>

<table>
  <tr><th colspan="2">Assessment Statistics</th></tr>
  <tr><td>Total Techniques</td><td><strong>{{.summary.totalTechniques}}</strong></td></tr>
  <tr><td>Techniques Passed (prevented)</td><td style="color:#238636"><strong>{{.summary.passedTechniques}}</strong></td></tr>
  <tr><td>Techniques Failed (succeeded)</td><td style="color:#da3633"><strong>{{.summary.failedTechniques}}</strong></td></tr>
  <tr><td>Techniques Errored (excluded from scoring)</td><td style="color:#d29922"><strong>{{.summary.erroredTechniques}}</strong></td></tr>
  <tr><td>Techniques Skipped (excluded from scoring)</td><td style="color:#6e7681"><strong>{{.summary.skippedTechniques}}</strong></td></tr>
  <tr><td>Trend vs. Previous Run</td><td><strong>{{.summary.trend}}</strong></td></tr>
  <tr><td>Last Run At</td><td>{{fmtTime .summary.lastRunAt}}</td></tr>
  <tr><td>Last Scenario</td><td>{{.summary.lastScenarioName}}</td></tr>
  <tr><td>Total Runs on Record</td><td>{{.summary.totalRuns}}</td></tr>
</table>

<h2>Key Recommendations</h2>
<ol style="padding-left:20px;line-height:1.9">
{{range .summary.recommendations}}<li>{{.}}</li>{{end}}
</ol>

<div class="footer">
  <span>{{.agent.hostname}} — Executive Summary</span><span>Page 2</span>
</div>
</div>

<!-- ═══ 2. CRITICAL & HIGH FINDINGS ════════════════════════════════════ -->
<div class="page">
<h1>2. Critical &amp; High Findings</h1>
{{if .topFindings}}
<p style="color:#6e7681;margin-bottom:14px">The following techniques succeeded against this endpoint — meaning the associated security controls did <strong>not</strong> prevent or detect the attack.</p>
<table>
  <thead><tr>
    <th>Severity</th><th>Technique</th><th>Tactic</th><th>Details &amp; Remediation</th>
  </tr></thead>
  <tbody>
  {{range .topFindings}}
  <tr>
    <td><span class="dot" style="background:{{sevColor .severity}}"></span>{{.severity}}</td>
    <td><code>{{.techniqueId}}</code><br>{{.techniqueName}}</td>
    <td>{{.tactic}}</td>
    <td>
      {{.details}}
      {{if .remediation}}<div class="remediation">{{.remediation}}</div>{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#238636;font-weight:600">✓ No Critical or High severity failures in the latest run. Continue to validate with future assessments.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Critical Findings</span><span>Page 3</span>
</div>
</div>

<!-- ═══ 3. ATT&CK TACTIC COVERAGE ══════════════════════════════════════ -->
<div class="page">
<h1>3. MITRE ATT&amp;CK Tactic Coverage</h1>
<p style="color:#6e7681;margin-bottom:14px">Tactic-level pass/fail breakdown from the latest scenario run. Tactics with no tested techniques are omitted.</p>
{{if .tacticHeatmap}}
<table>
  <thead><tr>
    <th>Tactic</th><th>Risk Weight</th><th>Passed</th><th>Failed</th><th>Total</th><th>Pass Rate</th><th style="min-width:120px">Coverage Bar</th>
  </tr></thead>
  <tbody>
  {{range .tacticHeatmap}}
  <tr>
    <td style="font-weight:600">{{.tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .weight}}"></span>{{.weight}}</td>
    <td style="color:#238636">{{.passed}}</td>
    <td style="color:{{if gt .failed 0.0}}#da3633{{else}}#238636{{end}}">{{.failed}}</td>
    <td>{{.total}}</td>
    <td style="font-weight:700;color:{{tacticColor .passPct}}">{{.passPct}}%</td>
    <td>
      <div class="tbar-wrap">
        <div class="tbar-fill" style="width:{{.passPct}}%;background:{{tacticColor .passPct}}"></div>
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
  <span>{{.agent.hostname}} — ATT&amp;CK Coverage</span><span>Page 4</span>
</div>
</div>

<!-- ═══ 4. COMPLIANCE STATUS ════════════════════════════════════════════ -->
<div class="page">
<h1>4. Regulatory Compliance Status</h1>
<p style="color:#6e7681;margin-bottom:14px">Compliance percentages are derived from BAS evidence. A control is <em>Passing</em> when all mapped techniques passed; <em>Failing</em> when at least one failed; <em>Untested</em> when no mapped techniques were included in the run.</p>
{{if .compliance}}
<table>
  <thead><tr>
    <th>Framework</th><th>Total Controls</th><th>Tested</th><th>Passing</th><th>Failing</th><th>Untested</th><th>Compliance</th><th>Coverage</th>
  </tr></thead>
  <tbody>
  {{range .compliance}}
  <tr>
    <td style="font-weight:600">{{.framework}}</td>
    <td>{{.totalControls}}</td>
    <td>{{.tested}}</td>
    <td style="color:#238636">{{.passing}}</td>
    <td style="color:{{if gt .failing 0.0}}#da3633{{else}}#238636{{end}}">{{.failing}}</td>
    <td style="color:#6e7681">{{.untested}}</td>
    <td class="comp-pct" style="color:{{compColor .compliancePct}}">{{pct .compliancePct}}</td>
    <td style="color:#2f81f7">{{pct .coveragePct}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">Compliance data unavailable.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Compliance Status</span><span>Page 5</span>
</div>
</div>

<!-- ═══ 5. SECURITY CONTROLS INVENTORY ══════════════════════════════════ -->
<div class="page">
<h1>5. Detection Coverage by Tactic</h1>
{{if .detectionCategories}}
<p style="color:#6e7681;margin-bottom:14px">Per-tactic verdict derived from this run's executed checks: <strong>PASS</strong> when every check in the tactic was prevented, <strong>FAIL</strong> when any check succeeded against the endpoint, <strong>UNKNOWN</strong> when the tactic was only skipped.</p>
<table>
  <thead><tr><th>Tactic</th><th>Verdict</th></tr></thead>
  <tbody>
  {{range .detectionCategories}}
  <tr>
    <td>{{.name}}</td>
    <td style="font-weight:600;color:{{if eq .result "pass"}}#238636{{else if eq .result "fail"}}#da3633{{else}}#6e7681{{end}}">{{upper .result}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No tactic-level results were recorded for this run.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Security Inventory</span><span>Page 6</span>
</div>
</div>

<!-- ═══ 6. SCENARIO RUN HISTORY ═════════════════════════════════════════ -->
<div class="page">
<h1>6. Scenario Run History</h1>
{{if .runs}}
<table>
  <thead><tr>
    <th>Date</th><th>Scenario</th><th>Status</th><th>Risk Score</th><th>Classification</th><th>Prevention</th><th>Exposure</th><th>Tested</th><th>Failed</th>
  </tr></thead>
  <tbody>
  {{range .runs}}
  <tr>
    <td style="white-space:nowrap">{{fmtTime .startedAt}}</td>
    <td>{{.scenarioName}}</td>
    <td>{{.status}}</td>
    <td style="font-weight:700">{{.riskScore}}</td>
    <td>{{.classification}}</td>
    <td>{{fmtScore .preventionScore}}%</td>
    <td>{{fmtScore .exposureScore}}%</td>
    <td>{{.totalTechniques}}</td>
    <td style="color:{{if gt .failedTechniques 0.0}}#da3633{{else}}#238636{{end}}">{{.failedTechniques}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No completed scenario runs found for this agent.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Run History</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>

</body>
</html>`
