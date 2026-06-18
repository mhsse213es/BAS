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
	"upper":    strings.ToUpper,
	"add1":     func(i int) int { return i + 1 },
	"humanize": humanizeTactic,
	"join":     func(s []string) string { return strings.Join(s, ", ") },
	"mttd": func(msF float64) string {
		ms := int64(msF)
		if ms <= 0 {
			return "—"
		}
		s := ms / 1000
		if s < 60 {
			return fmt.Sprintf("%ds", s)
		}
		return fmt.Sprintf("%dm %02ds", s/60, s%60)
	},
	"exposureColor": func(level string) string {
		switch level {
		case "Low":
			return "#238636"
		case "Medium":
			return "#d29922"
		case "High":
			return "#f0883e"
		case "Critical":
			return "#da3633"
		}
		return "#6e7681"
	},
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
	Manual        int     `json:"manual"`
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
  <span style="margin-left:auto;padding:4px 12px;border-radius:4px;font-size:0.85rem;color:#fff;background:{{exposureColor .summary.exposureLevel}}">Exposure: {{.summary.exposureLevel}}</span>
</div>

<h2>Executive Conclusion</h2>
<p style="font-size:0.92rem;line-height:1.7">{{.executiveConclusion}}</p>

<div class="footer">
  <span>{{.agent.hostname}} — Executive Summary</span>
</div>
</div>

<!-- ═══ 2. ASSESSMENT SUMMARY ═══════════════════════════════════════════ -->
<div class="page">
<h1>2. Assessment Summary</h1>

<div class="score-row">
  <div class="scard">
    <div class="scard-label">Prevention Score</div>
    <div class="scard-value" style="color:#238636">{{fmtScore .summary.preventionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.preventionScore}}%;background:#238636"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Severity-weighted pass rate</div>
  </div>
  <div class="scard">
    <div class="scard-label">Detection Score</div>
    {{if .summary.detectionMeasured}}
    <div class="scard-value" style="color:#2f81f7">{{fmtScore .summary.detectionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.detectionScore}}%;background:#2f81f7"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Alerts raised on unprevented techniques</div>
    {{else}}
    <div class="scard-value" style="color:#6e7681">N/A</div>
    <div class="scard-bar"></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">No host telemetry — detection not measurable</div>
    {{end}}
  </div>
  <div class="scard">
    <div class="scard-label">Exposure Level</div>
    <div class="scard-value" style="color:{{exposureColor .summary.exposureLevel}}">{{.summary.exposureLevel}}</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.exposureScore}}%;background:{{exposureColor .summary.exposureLevel}}"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Derived from prevention effectiveness</div>
  </div>
  <div class="scard">
    <div class="scard-label">Penetration Ratio</div>
    <div class="scard-value" style="color:#da3633">{{.summary.penetrationFailed}}/{{.summary.penetrationTested}}</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{.summary.penetrationPct}}%;background:#da3633"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">{{.summary.penetrationPct}}% of executed techniques got through</div>
  </div>
  <div class="scard">
    <div class="scard-label">Trend vs. Previous</div>
    {{if .trendAnalysis.hasPrevious}}
    <div class="scard-value" style="color:{{if gt .trendAnalysis.deltaPrevention 0.0}}#238636{{else if lt .trendAnalysis.deltaPrevention 0.0}}#da3633{{else}}#6e7681{{end}}">
      {{if gt .trendAnalysis.deltaPrevention 0.0}}▲ +{{fmtScore .trendAnalysis.deltaPrevention}}{{else if lt .trendAnalysis.deltaPrevention 0.0}}▼ {{fmtScore .trendAnalysis.deltaPrevention}}{{else}}no change{{end}}
    </div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Prevention pts vs previous ({{fmtScore .trendAnalysis.previousPrevention}}% → {{fmtScore .trendAnalysis.currentPrevention}}%)</div>
    {{else}}
    <div class="scard-value" style="color:#6e7681">Baseline</div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">First scored assessment — no prior to compare</div>
    {{end}}
  </div>
</div>

<h3>Secondary Metrics</h3>
<table>
  <tr>
    <td>Tactic Coverage (breadth)</td><td><strong>{{fmtScore .summary.killChainCoverage}}%</strong> of 14 ATT&amp;CK tactics</td>
    <td>Defense Rate</td><td><strong>{{fmtScore .summary.coverageScore}}%</strong> tactics fully blocked</td>
  </tr>
  <tr>
    <td>Kill-Chain Amplifier</td><td><strong>{{fmtScore .summary.killChainAmplifier}}×</strong></td>
    <td>Mean Time-to-Detect</td><td><strong>{{mttd .summary.mttdMs}}</strong></td>
  </tr>
</table>

<h3>Simulation Reliability</h3>
<p style="color:#6e7681;margin-bottom:8px">A high environmental-error rate lowers confidence in the result — it means the BAS could not execute techniques, <strong>not</strong> that the endpoint blocked them. ERROR and SKIPPED are excluded from all scores.</p>
<table>
  <tr><td>Attempted</td><td><strong>{{.reliability.attempted}}</strong></td>
      <td>Valid (scored)</td><td style="color:#238636"><strong>{{.reliability.valid}}</strong></td></tr>
  <tr><td>Environmental Errors</td><td style="color:#d29922"><strong>{{.reliability.errored}}</strong></td>
      <td>Skipped</td><td style="color:#6e7681"><strong>{{.reliability.skipped}}</strong></td></tr>
  <tr><td>Result Confidence</td><td colspan="3"><strong style="color:{{if eq .reliability.confidence "High"}}#238636{{else if eq .reliability.confidence "Medium"}}#d29922{{else}}#da3633{{end}}">{{.reliability.confidence}}</strong></td></tr>
</table>

<div class="footer">
  <span>{{.agent.hostname}} — Assessment Summary</span>
</div>
</div>

<!-- ═══ 3. TOP RISK DRIVERS ═════════════════════════════════════════════ -->
<div class="page">
<h1>3. Top Risk Drivers</h1>
<p style="color:#6e7681;margin-bottom:14px">The techniques whose failures account for the most lost prevention points (severity-weighted, the same weighting as the headline score). "Score points" is how much of the 100-point scale each technique's failures <em>account for</em> — not a guaranteed gain from any single fix.</p>
{{if .topRiskDrivers}}
<table>
  <thead><tr><th>#</th><th>Technique</th><th>Tactic</th><th>Severity</th><th>Failures</th><th>Score Points</th></tr></thead>
  <tbody>
  {{range $i, $d := .topRiskDrivers}}
  <tr>
    <td>{{add1 $i}}</td>
    <td>{{if $d.techniqueId}}<code>{{$d.techniqueId}}</code> {{end}}{{$d.name}}</td>
    <td>{{humanize $d.tactic}}</td>
    <td><span class="dot" style="background:{{sevColor $d.severity}}"></span>{{$d.severity}}</td>
    <td>{{$d.failures}}</td>
    <td style="font-weight:700;color:#da3633">{{fmtScore $d.scorePoints}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#238636;font-weight:600">✓ No techniques penetrated this endpoint — there are no risk drivers to rank.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Top Risk Drivers</span>
</div>
</div>

<!-- ═══ 4. RISK SUMMARY ═════════════════════════════════════════════════ -->
<div class="page">
<h1>4. Risk Summary</h1>
<p style="color:#6e7681;margin-bottom:14px">Business-objective risk derived from the per-tactic outcome: <strong>High</strong> when most tested techniques in the objective went unprevented, <strong>Medium</strong> when some did, <strong>Low</strong> when all were blocked. Objectives with no executed techniques are omitted.</p>
{{if .objectiveRisks}}
<table>
  <thead><tr><th>Business Objective</th><th>ATT&amp;CK Tactic</th><th>Risk</th><th>Tested</th><th>Unprevented</th></tr></thead>
  <tbody>
  {{range .objectiveRisks}}
  <tr>
    <td style="font-weight:600">{{.objective}}</td>
    <td>{{humanize .tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .risk}}"></span>{{.risk}}</td>
    <td>{{.tested}}</td>
    <td style="color:{{if gt .failed 0.0}}#da3633{{else}}#238636{{end}}">{{.failed}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No objective-level results were recorded for this run.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Risk Summary</span>
</div>
</div>

<!-- ═══ 5. ASSET CONTEXT ════════════════════════════════════════════════ -->
<div class="page">
<h1>5. Asset Context</h1>
<table>
  <tr><td>Hostname</td><td><strong>{{.agent.hostname}}</strong></td></tr>
  <tr><td>IP Address</td><td>{{.agent.ipAddress}}</td></tr>
  <tr><td>Operating System</td><td>{{.agent.osVersion}}</td></tr>
  <tr><td>Logged-in User</td><td>{{.agent.username}}</td></tr>
  <tr><td>Environment</td><td>{{.agent.envLabel}}</td></tr>
  <tr><td>Agent Status</td><td>{{.agent.status}}</td></tr>
  <tr><td>Last Update</td><td>{{fmtTime .agent.lastUpdate}}</td></tr>
</table>
{{if .securityTools}}
<h3>Reported Security Tooling</h3>
<div>{{range .securityTools}}<span class="tool-tag">{{.}}</span>{{end}}</div>
{{end}}
{{if .reverted}}
<h3>Post-Run Cleanup (changes rolled back)</h3>
<ul style="padding-left:20px;color:#6e7681;font-size:0.82rem">{{range .reverted}}<li>{{.}}</li>{{end}}</ul>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Asset Context</span>
</div>
</div>

<!-- ═══ 6. ATTACK PATH ANALYSIS ═════════════════════════════════════════ -->
<div class="page">
<h1>6. Attack Path Analysis</h1>
<p style="color:#6e7681;margin-bottom:14px">The chain of kill-chain phases this endpoint's gaps actually permit — built strictly from observed unprevented techniques, ordered by ATT&amp;CK phase. No hypothetical or inferred steps.</p>
{{if .attackPath.steps}}
<table>
  <thead><tr><th>Phase</th><th>Unprevented Techniques</th></tr></thead>
  <tbody>
  {{range .attackPath.steps}}
  <tr>
    <td style="font-weight:600;white-space:nowrap">{{humanize .tactic}}</td>
    <td>{{range .techniques}}<div>{{.}}</div>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#238636;font-weight:600">✓ No unprevented techniques formed a traversable attack path this run.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Attack Path</span>
</div>
</div>

<!-- ═══ 7. TACTIC SUMMARY ═══════════════════════════════════════════════ -->
<div class="page">
<h1>7. MITRE ATT&amp;CK Tactic Summary</h1>
<p style="color:#6e7681;margin-bottom:14px">Per-tactic coverage (techniques tested), prevention rate, detection rate, and mean time-to-detect. MTTD shows "—" when detection latency was not measured. Tactics with no tested techniques are omitted.</p>
{{if .tacticHeatmap}}
<table>
  <thead><tr>
    <th>Tactic</th><th>Weight</th><th>Coverage</th><th>Prevented</th><th>Detected</th><th>MTTD</th><th style="min-width:110px">Prevention</th>
  </tr></thead>
  <tbody>
  {{range .tacticHeatmap}}
  <tr>
    <td style="font-weight:600">{{humanize .tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .weight}}"></span>{{.weight}}</td>
    <td>{{.total}} tested</td>
    <td style="font-weight:700;color:{{tacticColor .passPct}}">{{.passPct}}%</td>
    <td>{{if gt .failed 0.0}}{{.detectedPct}}% <span style="color:#6e7681">({{.detected}}/{{.failed}})</span>{{else}}—{{end}}</td>
    <td>{{mttd .mttdMs}}</td>
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
  <span>{{.agent.hostname}} — Tactic Summary</span>
</div>
</div>

<!-- ═══ 8. ASSESSMENT INSIGHTS ══════════════════════════════════════════ -->
<div class="page">
<h1>8. Assessment Insights</h1>
{{if .insights.hasData}}
<div class="score-row">
  {{if .insights.most}}
  <div class="scard" style="border-left:3px solid #238636">
    <div class="scard-label">Most Protected</div>
    <div class="scard-value" style="color:#238636;font-size:1.2rem">{{humanize .insights.most.tactic}}</div>
    <div style="font-size:0.8rem;color:#6e7681">{{.insights.most.passPct}}% prevented across {{.insights.most.tested}} techniques</div>
  </div>
  {{end}}
  {{if .insights.least}}
  <div class="scard" style="border-left:3px solid #da3633">
    <div class="scard-label">Least Protected</div>
    <div class="scard-value" style="color:#da3633;font-size:1.2rem">{{humanize .insights.least.tactic}}</div>
    <div style="font-size:0.8rem;color:#6e7681">{{.insights.least.passPct}}% prevented across {{.insights.least.tested}} techniques</div>
  </div>
  {{end}}
</div>
{{if .insights.telemetryNote}}<p style="color:#92400e;background:#fef3c7;border:1px solid #f59e0b;border-radius:4px;padding:8px 12px;font-size:0.82rem">{{.insights.telemetryNote}}</p>{{end}}
{{else}}
<p style="color:#6e7681">Not enough tactic data to derive insights.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Insights</span>
</div>
</div>

<!-- ═══ 9. ACTION PLAN ══════════════════════════════════════════════════ -->
<div class="page">
<h1>9. Action Plan</h1>
<p style="color:#6e7681;margin-bottom:14px">Remediations ordered by the prevention-score points their failures account for. The points quantify current exposure attributable to each tactic — they are not a promised score gain, since a single control may not resolve every underlying finding.</p>
{{if .actionPlan}}
<table>
  <thead><tr><th>Priority</th><th>Tactic / Objective</th><th>Accounts For</th><th>Failures</th><th>Recommended Action</th></tr></thead>
  <tbody>
  {{range $i, $a := .actionPlan}}
  <tr>
    <td style="font-weight:700">{{add1 $i}}</td>
    <td style="font-weight:600">{{humanize $a.tactic}}{{if $a.objective}}<br><span style="font-size:0.74rem;color:#6e7681">{{$a.objective}}</span>{{end}}</td>
    <td style="font-weight:700;color:#da3633">{{fmtScore $a.scorePoints}} pts</td>
    <td>{{$a.failures}}</td>
    <td style="font-size:0.82rem">{{$a.recommendation}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#238636;font-weight:600">✓ No failing tactics — no remediation actions required from this assessment.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Action Plan</span>
</div>
</div>

<!-- ═══ 10. COMPLIANCE STATUS ═══════════════════════════════════════════ -->
<div class="page">
<h1>10. Regulatory Compliance Status</h1>
<p style="color:#6e7681;margin-bottom:14px">Compliance percentages are derived from BAS evidence over the <em>BAS-testable</em> control subset. A control is <em>Passing</em> when all mapped techniques passed; <em>Failing</em> when at least one failed; <em>Untested</em> when no mapped techniques were included in the run. <em>Manual</em> controls are governance/process requirements (board policy, asset inventory, risk-assessment cadence, IR/DR planning, data residency) that cannot be validated by simulation and require manual attestation — they are excluded from the Compliance and Coverage percentages.</p>
{{if .compliance}}
<table>
  <thead><tr>
    <th>Framework</th><th>Total Controls</th><th>Manual</th><th>Tested</th><th>Passing</th><th>Failing</th><th>Untested</th><th>Compliance</th><th>Coverage</th>
  </tr></thead>
  <tbody>
  {{range .compliance}}
  <tr>
    <td style="font-weight:600">{{.framework}}</td>
    <td>{{.totalControls}}</td>
    <td style="color:#6e7681">{{.manual}}</td>
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
  <span>{{.agent.hostname}} — Compliance Status</span>
</div>
</div>

<!-- ═══ 11. SCENARIO RUN HISTORY ════════════════════════════════════════ -->
<div class="page">
<h1>11. Scenario Run History</h1>
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
</div>
</div>

<!-- ═══ 12. TECHNICAL FINDINGS ══════════════════════════════════════════ -->
<div class="page">
<h1>12. Technical Findings</h1>
{{if .topFindings}}
<p style="color:#6e7681;margin-bottom:14px">Critical and High severity techniques that succeeded against this endpoint — the associated security controls did <strong>not</strong> prevent the attack. De-duplicated by technique.</p>
<table>
  <thead><tr>
    <th>Severity</th><th>Technique</th><th>Tactic</th><th>Details &amp; Remediation</th>
  </tr></thead>
  <tbody>
  {{range .topFindings}}
  <tr>
    <td><span class="dot" style="background:{{sevColor .severity}}"></span>{{.severity}}</td>
    <td><code>{{.techniqueId}}</code><br>{{.techniqueName}}</td>
    <td>{{humanize .tactic}}</td>
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
  <span>{{.agent.hostname}} — Technical Findings</span>
</div>
</div>

<!-- ═══ 13. TECHNICAL APPENDIX — GLOSSARY ═══════════════════════════════ -->
<div class="page">
<h1>13. Technical Appendix — ATT&amp;CK Glossary</h1>
<p style="color:#6e7681;margin-bottom:14px">Authoritative MITRE ATT&amp;CK reference for every technique exercised in this assessment. Sourced from the bundled ATT&amp;CK enterprise data.</p>
{{if .glossary}}
{{range .glossary}}
<div style="margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #e5e7eb">
  <h3 style="margin:0 0 4px"><code>{{.techniqueId}}</code> — {{.name}} <span style="font-weight:400;color:#6e7681;font-size:0.8rem">({{humanize .tactic}})</span></h3>
  {{if .description}}<p style="font-size:0.82rem;color:#444">{{.description}}</p>{{end}}
  {{if .detection}}<p style="font-size:0.8rem;color:#444"><strong>Detection:</strong> {{.detection}}</p>{{end}}
  {{if .dataSources}}<p style="font-size:0.78rem;color:#6e7681"><strong>Data sources:</strong> {{join .dataSources}}</p>{{end}}
  {{if .mitigations}}<p style="font-size:0.78rem;color:#6e7681"><strong>Mitigations:</strong> {{join .mitigations}}</p>{{end}}
  {{if .url}}<p style="font-size:0.78rem"><a href="{{.url}}">{{.url}}</a></p>{{end}}
</div>
{{end}}
{{else}}
<p style="color:#6e7681">No ATT&amp;CK-mapped techniques were exercised in this assessment.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Technical Appendix</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>

</body>
</html>`
