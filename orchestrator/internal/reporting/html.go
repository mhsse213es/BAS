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
			return "#0d9488"
		case "low risk":
			return "#0d9488"
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
			return "#0d9488"
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
			return "#0d9488"
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
			return "#0d9488"
		case "Medium":
			return "#d29922"
		case "High":
			return "#f0883e"
		case "Critical":
			return "#da3633"
		}
		return "#6e7681"
	},
	// detVerdictColor maps a detection verdict to a CSS color.
	"detVerdictColor": func(v string) string {
		switch v {
		case "prevented":
			return "#0d9488" // green — EDR/AV blocked before execution
		case "detected":
			return "#2f81f7" // blue — executed, EDR alert raised
		case "undetected":
			return "#da3633" // red — executed, no alert
		}
		return "#6e7681" // grey — no detection data
	},
	// detVerdictLabel maps a detection verdict to a display label.
	"detVerdictLabel": func(v string) string {
		switch v {
		case "prevented":
			return "PREVENTED"
		case "detected":
			return "DETECTED"
		case "undetected":
			return "UNDETECTED"
		}
		return "NO DATA"
	},
	// cleanupVerdictColor maps a cleanup verdict to a CSS color.
	"cleanupVerdictColor": func(v string) string {
		switch v {
		case "reverted":
			return "#0d9488" // green — cleanup command succeeded
		case "partial":
			return "#d29922" // amber — non-zero exit, artifacts may remain
		case "leaked":
			return "#da3633" // red — cleanup timed out or failed to start
		}
		return "#6e7681" // grey — no cleanup defined
	},
	// cleanupVerdictLabel maps a cleanup verdict to a display label.
	"cleanupVerdictLabel": func(v string) string {
		switch v {
		case "reverted":
			return "REVERTED"
		case "partial":
			return "PARTIAL"
		case "leaked":
			return "LEAKED"
		}
		return "—"
	},
	// execVerdictColor maps an execution verdict to a CSS color.
	"execVerdictColor": func(v string) string {
		switch v {
		case "pass", "blocked":
			return "#0d9488"
		case "fail":
			return "#da3633"
		case "error":
			return "#d29922"
		}
		return "#6e7681"
	},
	// pctFrac formats a 0..1 fraction as a whole-percent string (e.g. 0.72→"72%").
	"pctFrac": func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	// pctOf returns the integer percentage of numerator/denominator (0 when denom=0).
	"pctOf": func(num, denom float64) int {
		if denom == 0 {
			return 0
		}
		v := int(num * 100 / denom)
		if v > 100 {
			return 100
		}
		return v
	},
	// scoreColor colors an attack-path-style score where HIGHER is better.
	"scoreColor": func(f float64) string {
		switch {
		case f >= 80:
			return "#0d9488"
		case f >= 60:
			return "#d29922"
		case f >= 40:
			return "#f0883e"
		default:
			return "#da3633"
		}
	},
	// noise helpers — alert fatigue section in Detection Validation page.
	"noiseTotal": func(f float64) string { return fmt.Sprintf("%.0f", f) },
	"noiseHigh":  func(f float64) int { return int(f) },
	"noiseRound": func(f float64) string { return fmt.Sprintf("%.0f", f) },
	"noiseColor": func(f float64) string {
		switch {
		case f >= 75:
			return "#da3633"
		case f >= 40:
			return "#d29922"
		default:
			return "#0d9488"
		}
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
:root{
  --ink:#1b2433; --muted:#6b7689; --faint:#9aa5b5;
  --navy:#0b1420; --line:#e7eaf0; --line2:#eef1f6; --panel:#f7f9fc;
  --accent:#2563eb; --teal:#0d9488;
}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:12.5px;color:var(--ink);background:#fff;line-height:1.6;
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--accent);text-decoration:none}
h1{font-size:1.32rem;font-weight:700;color:var(--navy);letter-spacing:-0.015em;line-height:1.2;
  margin:0 0 18px;padding-left:12px;border-left:3px solid var(--teal)}
h2{font-size:1rem;font-weight:650;color:var(--navy);letter-spacing:-0.01em;margin:22px 0 10px}
h3{font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);margin:18px 0 9px}
p{margin-bottom:9px}
em{color:var(--muted);font-style:normal}
code{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:0.85em;color:var(--navy);background:var(--panel);padding:1px 5px;border-radius:4px}
strong{font-weight:650}

/* Page layout */
.page{padding:42px 48px;max-width:900px;margin:0 auto}
@media print{
  .page{page-break-after:always;padding:30px 32px}
  .page:last-child{page-break-after:avoid}
  body{font-size:10.5px}
  /* Clean page breaks — never split a row, card, or glossary entry; keep a
     heading with the content that follows it; repeat table headers on overflow. */
  tr,.scard,.gloss-item{page-break-inside:avoid;break-inside:avoid}
  thead{display:table-header-group}
  h1,h2,h3{page-break-after:avoid;break-after:avoid}
  .footer{page-break-inside:avoid}
}

/* Cover */
.cover{min-height:90vh;display:flex;flex-direction:column}
.cover-band{background:var(--navy);margin:-42px -48px 0;padding:36px 48px 30px;border-bottom:3px solid var(--teal)}
.cover-logo{font-size:1.2rem;font-weight:800;color:#fff;letter-spacing:-0.02em}
.cover-logo span{color:var(--teal)}
.cover-kicker{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.16em;color:#8aa0b8;margin-top:5px}
.cover-mid{flex:1;display:flex;flex-direction:column;justify-content:center;padding:46px 0}
.cover-title{font-size:2.4rem;font-weight:750;color:var(--navy);letter-spacing:-0.03em;line-height:1.04;margin-bottom:10px}
.cover-sub{font-size:1.02rem;color:var(--muted);margin-bottom:30px}
.cover-meta{border-top:1px solid var(--line)}
.cover-meta .crow{display:flex;padding:11px 2px;border-bottom:1px solid var(--line);font-size:0.86rem}
.cover-meta .crow .k{width:170px;color:var(--muted);font-weight:600}
.cover-meta .crow .v{flex:1;color:var(--ink);font-weight:500}
.confidential{align-self:flex-start;display:inline-flex;align-items:center;gap:7px;
  background:#fff6e6;color:#92610a;border:1px solid #f0c674;padding:6px 13px;border-radius:20px;
  font-size:0.72rem;font-weight:700;letter-spacing:0.03em;margin-top:28px}

/* Risk badge */
.risk-badge{display:inline-flex;align-items:center;gap:14px;padding:14px 22px;border-radius:10px;
  font-weight:600;margin-bottom:22px;border:1px solid var(--line);background:var(--panel)}

/* Score cards */
.score-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:22px}
.scard{border:1px solid var(--line);border-radius:12px;padding:15px 16px;background:#fff;box-shadow:0 1px 2px rgba(16,24,40,0.04)}
.scard-label{font-size:0.66rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);font-weight:700;margin-bottom:8px}
.scard-value{font-size:1.6rem;font-weight:750;letter-spacing:-0.02em;line-height:1;margin-bottom:10px}
.scard-bar{height:5px;background:var(--line);border-radius:3px;overflow:hidden}
.scard-bar-fill{height:100%;border-radius:3px}

/* Tables */
table{width:100%;border-collapse:collapse;margin:6px 0 16px;font-size:0.82rem}
thead th{background:var(--panel);color:var(--muted);text-transform:uppercase;font-size:0.66rem;
  letter-spacing:0.05em;font-weight:700;text-align:left;padding:9px 12px;border-bottom:1.5px solid var(--line)}
td{padding:9px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:nth-child(even) td{background:#fbfcfe}

/* Severity dots */
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}

/* Tactic bar */
.tbar-wrap{width:100%;height:7px;background:var(--line);border-radius:4px;overflow:hidden;display:inline-block;min-width:80px;vertical-align:middle}
.tbar-fill{height:100%;border-radius:4px}

/* Compliance table */
.comp-pct{font-weight:700}

/* Findings */
.remediation{background:var(--panel);border-left:3px solid var(--teal);padding:8px 12px;font-size:0.78rem;color:var(--muted);margin-top:6px;border-radius:0 6px 6px 0;line-height:1.55}

/* Tools list */
.tool-tag{display:inline-block;background:#eef4ff;color:#2353c4;border:1px solid #cfe0ff;
  padding:3px 10px;border-radius:20px;font-size:0.72rem;margin:2px 3px 2px 0}

/* Footer */
.footer{border-top:1px solid var(--line);padding:13px 0 0;font-size:0.7rem;color:var(--faint);
  display:flex;justify-content:space-between;margin-top:34px}
</style>
</head>
<body>

<!-- ═══ COVER PAGE ════════════════════════════════════════════════════════ -->
<div class="page">
<div class="cover">
  <div class="cover-band">
    <div class="cover-logo">Aud<span>spect</span> BAS</div>
    <div class="cover-kicker">Breach &amp; Attack Simulation Platform</div>
  </div>
  <div class="cover-mid">
    <div class="cover-title">Security Assessment Report</div>
    {{if .scope}}
    <div class="cover-sub">{{.scope.subtitle}}</div>
    <div class="cover-meta">
      <div class="crow"><div class="k">Campaign</div><div class="v"><strong>{{.scope.title}}</strong></div></div>
      <div class="crow"><div class="k">Scenario</div><div class="v">{{.scope.scenario}}</div></div>
      <div class="crow"><div class="k">Endpoints</div><div class="v">{{.scope.agentCount}} agent(s) &nbsp;·&nbsp; {{.scope.runCount}} run(s)</div></div>
      <div class="crow"><div class="k">Assessment Date</div><div class="v">{{fmtTime .summary.lastRunAt}}</div></div>
      <div class="crow"><div class="k">Report Generated</div><div class="v">{{fmtTime .generatedAt}}</div></div>
    </div>
    {{else}}
    <div class="cover-sub">Endpoint Posture Report</div>
    <div class="cover-meta">
      <div class="crow"><div class="k">Agent</div><div class="v"><strong>{{.agent.hostname}}</strong> ({{.agent.ipAddress}})</div></div>
      <div class="crow"><div class="k">OS / Username</div><div class="v">{{.agent.osVersion}} &nbsp;·&nbsp; {{.agent.username}}</div></div>
      <div class="crow"><div class="k">Environment</div><div class="v">{{.agent.envLabel}}</div></div>
      <div class="crow"><div class="k">Assessment Date</div><div class="v">{{fmtTime .summary.lastRunAt}}</div></div>
      <div class="crow"><div class="k">Report Generated</div><div class="v">{{fmtTime .generatedAt}}</div></div>
      <div class="crow"><div class="k">Last Scenario</div><div class="v">{{.summary.lastScenarioName}} &nbsp;·&nbsp; {{.summary.totalRuns}} run(s) on record</div></div>
    </div>
    {{end}}
    <div class="confidential">⚠ CONFIDENTIAL — For authorized use only</div>
  </div>
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

<!-- 4 KPI cards — give CISOs the numbers at a glance before the prose -->
<div class="score-row" style="margin-bottom:16px">
  <div class="scard">
    <div class="scard-label">Prevention Score</div>
    <div class="scard-value" style="color:#0d9488">{{fmtScore .summary.preventionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.preventionScore}}%;background:#0d9488"></div></div>
  </div>
  {{if .summary.detectionMeasured}}
  <div class="scard">
    <div class="scard-label">Detection Score</div>
    <div class="scard-value" style="color:#2f81f7">{{fmtScore .summary.detectionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.detectionScore}}%;background:#2f81f7"></div></div>
  </div>
  {{else}}
  <div class="scard">
    <div class="scard-label">Detection Score</div>
    <div class="scard-value" style="color:#6e7681">N/A</div>
    <div class="scard-bar"></div>
  </div>
  {{end}}
  {{if .coverageBreakdown.hasData}}
  <div class="scard" style="border-left:3px solid #da3633">
    <div class="scard-label">Techniques Missed</div>
    <div class="scard-value" style="color:#da3633">{{.coverageBreakdown.missed}}<span style="font-size:0.9rem;color:#6e7681"> / {{.coverageBreakdown.attempted}}</span></div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.exposureScore}}%;background:#da3633"></div></div>
  </div>
  <div class="scard" style="border-left:3px solid #0d9488">
    <div class="scard-label">Techniques Prevented</div>
    <div class="scard-value" style="color:#0d9488">{{.coverageBreakdown.prevented}}<span style="font-size:0.9rem;color:#6e7681"> / {{.coverageBreakdown.attempted}}</span></div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{.coverageBreakdown.preventionRate}}%;background:#0d9488"></div></div>
  </div>
  {{else}}
  <div class="scard">
    <div class="scard-label">Exposure Score</div>
    <div class="scard-value" style="color:{{exposureColor .summary.exposureLevel}}">{{fmtScore .summary.exposureScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.exposureScore}}%;background:{{exposureColor .summary.exposureLevel}}"></div></div>
  </div>
  <div class="scard">
    <div class="scard-label">Penetration Ratio</div>
    <div class="scard-value" style="color:#da3633">{{.summary.penetrationFailed}}/{{.summary.penetrationTested}}</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{.summary.penetrationPct}}%;background:#da3633"></div></div>
  </div>
  {{end}}
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
    <div class="scard-value" style="color:#0d9488">{{fmtScore .summary.preventionScore}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.preventionScore}}%;background:#0d9488"></div></div>
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
  {{with .summary.attackPathScore}}
  <div class="scard" style="border-left:3px solid {{scoreColor .}}">
    <div class="scard-label">Attack Path Score</div>
    <div class="scard-value" style="color:{{scoreColor .}}">{{.}}<span style="font-size:0.9rem;color:#6e7681">/100</span></div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .}}%;background:{{scoreColor .}}"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">{{$.summary.attackPathBand}} risk · lateral movement exposure</div>
  </div>
  {{end}}
  <div class="scard">
    <div class="scard-label">Trend vs. Previous</div>
    {{if .trendAnalysis.hasPrevious}}
    <div class="scard-value" style="color:{{if gt .trendAnalysis.deltaPrevention 0.0}}#0d9488{{else if lt .trendAnalysis.deltaPrevention 0.0}}#da3633{{else}}#6e7681{{end}}">
      {{if gt .trendAnalysis.deltaPrevention 0.0}}▲ +{{fmtScore .trendAnalysis.deltaPrevention}}{{else if lt .trendAnalysis.deltaPrevention 0.0}}▼ {{fmtScore .trendAnalysis.deltaPrevention}}{{else}}no change{{end}}
    </div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Prevention pts vs previous ({{fmtScore .trendAnalysis.previousPrevention}}% → {{fmtScore .trendAnalysis.currentPrevention}}%)</div>
    {{else}}
    <div class="scard-value" style="color:#6e7681">Baseline</div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">First scored assessment — no prior to compare</div>
    {{end}}
  </div>
</div>

<div class="score-row" style="margin-top:20px;margin-bottom:20px">
  <div class="scard" style="flex:1;min-width:100%;border-left:4px solid {{if eq .attackSurfaceSLAStatus "critical-sla"}}#da3633{{else if eq .attackSurfaceSLAStatus "over-sla"}}#d29922{{else}}#0d9488{{end}};background:#f7f9fc;padding:12px 16px;border-radius:6px;display:block">
    <div class="scard-label" style="font-size:0.72rem;text-transform:uppercase;color:var(--muted);margin-bottom:4px">Attack Surface Age</div>
    <div class="scard-value" style="font-size:1.15rem;font-weight:700;color:var(--navy)">Exposed weakness present for {{.attackSurfaceAge}} days</div>
    <div style="font-size:0.75rem;color:var(--muted);margin-top:4px">
      {{if .oldestFindingID}}
      Oldest finding: <strong>{{.oldestFindingID}}</strong> ({{.oldestFindingName}}) · Severity: <strong style="color:{{sevColor .oldestFindingSeverity}}">{{.oldestFindingSeverity}}</strong> · Status: <span style="text-transform:uppercase;font-weight:bold;color:{{if eq .attackSurfaceSLAStatus "critical-sla"}}#da3633{{else if eq .attackSurfaceSLAStatus "over-sla"}}#d29922{{else}}#0d9488{{end}}">{{.attackSurfaceSLAStatus}}</span>
      {{else}}
      No open findings or weaknesses detected on this agent.
      {{end}}
    </div>
  </div>
</div>

{{if .perfCpuBefore}}
<div class="score-row" style="margin-top:20px;margin-bottom:20px">
  <div class="scard" style="flex:1;min-width:100%;border-left:4px solid #0d9488;background:#f7f9fc;padding:12px 16px;border-radius:6px;display:block">
    <div class="scard-label" style="font-size:0.72rem;text-transform:uppercase;color:var(--muted);margin-bottom:6px">Endpoint Stability Check</div>
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
      <div style="flex:1;min-width:180px">
        <div style="font-size:0.7rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.03em;margin-bottom:4px">Before Running</div>
        <div style="font-size:0.8rem;color:var(--navy)">
          CPU: <strong>{{printf "%.1f" .perfCpuBefore}}%</strong> &middot;
          RAM: <strong>{{printf "%.1f" .perfRamBefore}} GB</strong> &middot;
          Disk: <strong>{{printf "%.1f" .perfDiskBefore}}%</strong>
        </div>
      </div>
      <div style="flex:1;min-width:180px">
        <div style="font-size:0.7rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:0.03em;margin-bottom:4px">After Running</div>
        <div style="font-size:0.8rem;color:var(--navy)">
          CPU: <strong>{{printf "%.1f" .perfCpuAfter}}%</strong> &middot;
          RAM: <strong>{{printf "%.1f" .perfRamAfter}} GB</strong> &middot;
          Disk: <strong>{{printf "%.1f" .perfDiskAfter}}%</strong>
        </div>
      </div>
      <div style="text-align:right;min-width:150px">
        <div class="scard-label" style="font-size:0.6rem;text-transform:uppercase;color:var(--muted);margin-bottom:2px">Health Impact</div>
        <div style="font-size:1.15rem;font-weight:700;color:#0d9488">Negligible</div>
      </div>
    </div>
  </div>
</div>
{{end}}

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
      <td>Valid (scored)</td><td style="color:#0d9488"><strong>{{.reliability.valid}}</strong></td></tr>
  <tr><td>Environmental Errors</td><td style="color:#d29922"><strong>{{.reliability.errored}}</strong></td>
      <td>Skipped</td><td style="color:#6e7681"><strong>{{.reliability.skipped}}</strong></td></tr>
  <tr><td>Result Confidence</td><td colspan="3"><strong style="color:{{if eq .reliability.confidence "High"}}#0d9488{{else if eq .reliability.confidence "Medium"}}#d29922{{else}}#da3633{{end}}">{{.reliability.confidence}}</strong></td></tr>
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
<p style="color:#0d9488;font-weight:600">✓ No techniques penetrated this endpoint — there are no risk drivers to rank.</p>
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
    <td style="color:{{if gt .failed 0.0}}#da3633{{else}}#0d9488{{end}}">{{.failed}}</td>
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
{{if .scope}}
<table>
  <tr><td>Campaign</td><td><strong>{{.scope.title}}</strong></td></tr>
  <tr><td>Scenario</td><td>{{.scope.scenario}}</td></tr>
  <tr><td>Endpoints Assessed</td><td>{{.scope.agentCount}}</td></tr>
  <tr><td>Runs Aggregated</td><td>{{.scope.runCount}}</td></tr>
</table>
<h3>Per-Agent Breakdown</h3>
<table>
  <thead><tr><th>Endpoint</th><th>Status</th><th>Prevention</th><th>Tested</th><th>Failed</th></tr></thead>
  <tbody>
  {{range .campaignAgents}}
  <tr>
    <td style="font-weight:600">{{.hostname}}</td>
    <td>{{.status}}</td>
    <td style="font-weight:700;color:{{tacticColor .preventionScore}}">{{fmtScore .preventionScore}}%</td>
    <td>{{.tested}}</td>
    <td style="color:{{if gt .failed 0.0}}#da3633{{else}}#0d9488{{end}}">{{.failed}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<table>
  <tr><td>Hostname</td><td><strong>{{.agent.hostname}}</strong></td></tr>
  <tr><td>IP Address</td><td>{{.agent.ipAddress}}</td></tr>
  <tr><td>Operating System</td><td>{{.agent.osVersion}}</td></tr>
  <tr><td>Logged-in User</td><td>{{.agent.username}}</td></tr>
  <tr><td>Environment</td><td>{{.agent.envLabel}}</td></tr>
  <tr><td>Agent Status</td><td>{{.agent.status}}</td></tr>
  <tr><td>Last Update</td><td>{{fmtTime .agent.lastUpdate}}</td></tr>
</table>
{{end}}
{{if .securityTools}}
<h3>Reported Security Tooling</h3>
<div>{{range .securityTools}}<span class="tool-tag">{{.}}</span>{{end}}</div>
{{end}}
{{if .cleanupFailed}}
<div style="background-color:#fff8f8;border-left:4px solid #da3633;border-radius:4px;padding:12px;margin:16px 0;font-size:0.82rem;line-height:1.4">
  <div style="color:#da3633;font-weight:bold;margin-bottom:4px">Warning: Cleanup failed</div>
  <div style="color:#1e293b">Out of the executed techniques, <strong>{{.cleanupFailedCount}}</strong> failed to clean up successfully. Residual simulation artifacts (files or registry entries) may remain on the endpoint. SOC/security teams should review the logs and technique details below to perform manual remediation.</div>
</div>
{{end}}

{{if .reverted}}
<h3>Post-Run Cleanup (changes rolled back)</h3>
<ul style="padding-left:20px;color:#6e7681;font-size:0.82rem">{{range .reverted}}<li>{{.}}</li>{{end}}</ul>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Asset Context</span>
</div>
</div>

<!-- ═══ 6. KILL-CHAIN PATH ══════════════════════════════════════════════ -->
<div class="page">
<h1>6. Kill-Chain Path</h1>
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
<p style="color:#0d9488;font-weight:600">✓ No unprevented techniques formed a traversable kill-chain path this run.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Kill-Chain Path</span>
</div>
</div>

<!-- ═══ 7. ATTACK PATH VALIDATION ═══════════════════════════════════════ -->
<div class="page">
<h1>7. Attack Path Validation</h1>
<p style="color:#6e7681;margin-bottom:14px">Lateral-movement reachability mapped as a graph of hosts, users and groups. Recon/relationship analysis only — no exploitation, no propagation. It answers what ART and Caldera cannot: if a host is compromised, how far can an attacker move and can they reach Domain Admin or a crown jewel?</p>
{{with .attackPathValidation}}
<div class="score-row">
  <div class="scard" style="border-left:3px solid {{scoreColor .attackPathScore}}">
    <div class="scard-label">Attack Path Score</div>
    <div class="scard-value" style="color:{{scoreColor .attackPathScore}}">{{.attackPathScore}}<span style="font-size:0.9rem;color:#6e7681">/100</span></div>
    <div style="font-size:0.8rem;color:{{exposureColor .band}};font-weight:600">{{.band}} risk · higher is safer</div>
  </div>
  <div class="scard">
    <div class="scard-label">Lateral Movement</div>
    <div class="scard-value" style="color:{{exposureColor .lateralMovementBand}};font-size:1.2rem">{{.lateralMovementBand}}</div>
    <div style="font-size:0.8rem;color:#6e7681">avg {{fmtScore .avgBlastRadius}} · max {{.maxBlastRadius}} hosts per entry</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if .domainCompromise}}#da3633{{else}}#0d9488{{end}}">
    <div class="scard-label">Domain Compromise</div>
    <div class="scard-value" style="color:{{if .domainCompromise}}#da3633{{else}}#0d9488{{end}};font-size:1.2rem">{{if .domainCompromise}}Reachable{{else}}Not Reachable{{end}}</div>
    <div style="font-size:0.8rem;color:#6e7681">{{if .domainCompromise}}a host can reach Domain Admin / Tier-0{{else}}no path to Domain Admin found{{end}}</div>
  </div>
</div>
<p style="color:#6e7681;font-size:0.82rem;margin:6px 0 14px">Graph scope: {{.hosts}} hosts · {{.users}} users · {{.groups}} groups · {{.edges}} relationship edges.</p>

{{if .domainCompromise}}{{if .shortestDomainAdminPath}}
<h3>Representative Path to Domain Admin</h3>
<p style="color:#6e7681;font-size:0.82rem">Worst-case shortest path from the highest-blast-radius entry host. Difficulty: <strong style="color:{{exposureColor .shortestDomainAdminDifficulty}}">{{.shortestDomainAdminDifficulty}}</strong>.</p>
<table>
  <thead><tr><th>Step</th><th>From</th><th>Via</th><th>To</th></tr></thead>
  <tbody>
  {{range $i, $e := .shortestDomainAdminPath}}
  <tr><td>{{add1 $i}}</td><td style="font-weight:600">{{$e.from}}</td><td>{{upper $e.kind}}</td><td style="font-weight:600">{{$e.to}}</td></tr>
  {{end}}
  </tbody>
</table>
{{end}}{{end}}

{{if .crownJewels}}
<h3>Crown-Jewel Exposure</h3>
<table>
  <thead><tr><th>Asset</th><th>Tag</th><th>Reachable</th><th>Entry Hosts</th><th>Min Hops</th></tr></thead>
  <tbody>
  {{range .crownJewels}}
  <tr>
    <td style="font-weight:600">{{.node}}</td>
    <td>{{.tag}}</td>
    <td style="font-weight:700;color:{{if .reachable}}#da3633{{else}}#0d9488{{end}}">{{if .reachable}}Yes{{else}}No{{end}}</td>
    <td>{{if .reachable}}{{.entryHosts}}{{else}}—{{end}}</td>
    <td>{{if .reachable}}{{.minHops}}{{else}}—{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{if .chokePoints}}
<h3>Attack Choke Points</h3>
<p style="color:#6e7681;font-size:0.82rem">Nodes most attacker paths funnel through. Remediating one can eliminate many paths at once.</p>
<table>
  <thead><tr><th>Node</th><th>On Paths</th><th>Path Coverage</th></tr></thead>
  <tbody>
  {{range .chokePoints}}
  <tr><td style="font-weight:600">{{.label}}</td><td>{{.onPaths}}</td><td style="font-weight:700;color:#d29922">{{pctFrac .coverage}}</td></tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{if .segmentationViolations}}
<h3>Segmentation Violations</h3>
<p style="color:#6e7681;font-size:0.82rem">Lateral-movement reachability that crosses a network-segment boundary — flat-network exposure that should be filtered.</p>
<table>
  <thead><tr><th>From</th><th>Segment</th><th>Via</th><th>To</th><th>Segment</th></tr></thead>
  <tbody>
  {{range .segmentationViolations}}
  <tr><td style="font-weight:600">{{.from}}</td><td>{{.fromSegment}}</td><td>{{upper .kind}}</td><td style="font-weight:600">{{.to}}</td><td>{{.toSegment}}</td></tr>
  {{end}}
  </tbody>
</table>
{{end}}
{{else}}
<p style="color:#6e7681">No attack-path data has been collected yet. Enable the <code>attackpath.collect</code> task on enrolled agents to map lateral-movement reachability, blast radius, segmentation, and crown-jewel exposure across the fleet.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Attack Path Validation</span>
</div>
</div>

<!-- ═══ 8. TACTIC SUMMARY ═══════════════════════════════════════════════ -->
<div class="page">
<h1>8. MITRE ATT&amp;CK Tactic Summary</h1>
<p style="color:#6e7681;margin-bottom:14px">Per-tactic coverage (techniques tested), prevention rate, detection rate, and mean time-to-detect. MTTD shows "—" when detection latency was not measured. Tactics with no tested techniques are omitted.</p>
{{if .tacticHeatmap}}
<table>
  <thead><tr>
    <th>Tactic</th><th>Weight</th><th>Coverage</th><th>Prevented</th><th>Detected</th><th>MTTD</th><th style="min-width:110px">Prevented / Detected / Missed</th>
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
      {{/* stacked 3-part bar: prevented (green) | detected-only (amber) | missed (red) */}}
      <div class="tbar-wrap" style="height:9px;position:relative">
        <div style="position:absolute;left:0;top:0;height:100%;width:{{.passPct}}%;background:#0d9488;border-radius:4px 0 0 4px"></div>
        <div style="position:absolute;left:{{.passPct}}%;top:0;height:100%;width:{{.detectedPct}}%;background:#d29922"></div>
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

<!-- ═══ 9. ASSESSMENT INSIGHTS ══════════════════════════════════════════ -->
<div class="page">
<h1>9. Assessment Insights</h1>
{{if .insights.hasData}}
<div class="score-row">
  {{if .insights.most}}
  <div class="scard" style="border-left:3px solid #0d9488">
    <div class="scard-label">Most Protected</div>
    <div class="scard-value" style="color:#0d9488;font-size:1.2rem">{{humanize .insights.most.tactic}}</div>
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

<!-- ═══ 10. ACTION PLAN ═════════════════════════════════════════════════ -->
<div class="page">
<h1>10. Action Plan</h1>
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
<p style="color:#0d9488;font-weight:600">✓ No failing tactics — no remediation actions required from this assessment.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Action Plan</span>
</div>
</div>

<!-- ═══ 11. COMPLIANCE STATUS ═══════════════════════════════════════════ -->
<div class="page">
<h1>11. Regulatory Compliance Status</h1>
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
    <td style="color:#0d9488">{{.passing}}</td>
    <td style="color:{{if gt .failing 0.0}}#da3633{{else}}#0d9488{{end}}">{{.failing}}</td>
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

<!-- ═══ 12. SCENARIO RUN HISTORY ════════════════════════════════════════ -->
<div class="page">
<h1>12. Scenario Run History</h1>
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
    <td style="color:{{if gt .failedTechniques 0.0}}#da3633{{else}}#0d9488{{end}}">{{.failedTechniques}}</td>
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

<!-- ═══ 13. TECHNICAL FINDINGS ══════════════════════════════════════════ -->
<div class="page">
<h1>13. Technical Findings</h1>
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
<p style="color:#0d9488;font-weight:600">✓ No Critical or High severity failures in the latest run. Continue to validate with future assessments.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Technical Findings</span>
</div>
</div>

<!-- ═══ 14. DETECTION VALIDATION ════════════════════════════════════════ -->
<div class="page">
<h1>14. Detection Validation</h1>
<p style="color:#6e7681;margin-bottom:14px">Per-technique outcome from the post-run EDR/alert sweep. <strong>PREVENTED</strong> = control blocked execution before it could run. <strong>DETECTED</strong> = technique executed and the security control raised an alert (detection source shown). <strong>UNDETECTED</strong> = technique executed with no alert — the security gap an attacker would exploit silently. Techniques where the agent has not yet submitted detection telemetry show "NO DATA".</p>

<h3 style="margin-top:16px;margin-bottom:8px">Detection Source Ranking</h3>
<p style="color:#6e7681;font-size:0.85rem;margin-bottom:12px">Ranking of security products based on total detection count (most often) and speed (first to detect/lowest minimum MTTD).</p>
<table style="width:100%;margin-bottom:20px;max-width:600px">
  <thead>
    <tr>
      <th style="text-align:left">Rank</th>
      <th style="text-align:left">Product</th>
      <th style="text-align:right">Detections</th>
      <th style="text-align:right">Min Time-to-Detect</th>
      <th style="text-align:right">Avg Time-to-Detect</th>
    </tr>
  </thead>
  <tbody>
    {{range $i, $ds := .detectionSources}}
    <tr>
      <td><strong>#{{add1 $i}}</strong></td>
      <td><strong>{{$ds.product}}</strong></td>
      <td style="text-align:right;font-weight:bold;color:#0d9488">{{$ds.detections}}</td>
      <td style="text-align:right">{{if $ds.minMttdMs}}{{mttd $ds.minMttdMs}}{{else}}—{{end}}</td>
      <td style="text-align:right;color:#6e7681">{{if $ds.avgMttdMs}}{{mttd $ds.avgMttdMs}}{{else}}—{{end}}</td>
    </tr>
    {{end}}
  </tbody>
</table>

{{if .techniqueMatrix}}
<table>
  <thead><tr>
    <th>Technique</th><th>Tactic</th><th>Sev</th><th>Execution</th><th>Detection</th><th>Alert Source</th><th>Event&nbsp;ID</th><th>Threat&nbsp;/&nbsp;Process</th><th>MTTD</th><th>Cleanup</th><th>Blocking Control</th>
  </tr></thead>
  <tbody>
  {{range .techniqueMatrix}}
  <tr>
    <td><code style="font-size:0.78rem">{{.techniqueId}}</code><br><span style="font-size:0.8rem">{{.techniqueName}}</span></td>
    <td style="font-size:0.8rem;color:#6e7681">{{humanize .tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .severity}}"></span>{{.severity}}</td>
    <td><span style="font-size:0.78rem;font-weight:600;color:{{execVerdictColor .execVerdict}}">{{upper .execVerdict}}</span></td>
    <td>
      {{if .detectionVerdict}}
      <span style="font-size:0.78rem;font-weight:700;color:{{detVerdictColor .detectionVerdict}}">{{detVerdictLabel .detectionVerdict}}</span>
      {{if eq .confidence "high"}}<span style="font-size:0.68rem;color:#6e7681;margin-left:4px">high conf</span>{{end}}
      {{else}}
      <span style="font-size:0.78rem;color:#6e7681">NO DATA</span>
      {{end}}
    </td>
    <td style="font-size:0.75rem;color:#6e7681;max-width:140px;word-break:break-all">{{.alertProvider}}{{if and .alertProvider .alertChannel}}<br>{{end}}{{.alertChannel}}</td>
    <td style="font-size:0.78rem;text-align:center">{{if .alertEventId}}{{.alertEventId}}{{else}}—{{end}}</td>
    <td style="font-size:0.75rem;max-width:160px;word-break:break-all">
      {{if .alertThreatName}}<strong>{{.alertThreatName}}</strong>{{if .alertCommandLine}}<br>{{end}}{{end}}
      {{if .alertCommandLine}}<span style="color:#6e7681">{{.alertCommandLine}}</span>{{end}}
    </td>
    <td style="font-size:0.78rem;white-space:nowrap">{{if .mttdMs}}{{mttd .mttdMs}}{{else}}—{{end}}</td>
    <td style="font-size:0.78rem;font-weight:600;white-space:nowrap;color:{{cleanupVerdictColor .cleanupVerdict}}">{{cleanupVerdictLabel .cleanupVerdict}}</td>
    <td style="font-size:0.75rem;max-width:160px">
      {{if .controlName}}<strong>{{.controlName}}</strong>{{if .controlRuleId}}<br><code style="font-size:0.65rem;color:#6e7681">{{.controlRuleId}}</code>{{end}}{{else}}—{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#6e7681">No technique results available for this run.</p>
{{end}}

<!-- Alert Fatigue & Noise Analysis -->
{{if .alertsTotal}}
{{$total := .alertsTotal}}
{{$high  := .alertsHighFidelity}}
{{$noise := .noiseScore}}
<h3 style="margin-top:24px;margin-bottom:8px">Alert Fatigue &amp; Noise Analysis</h3>
<div style="display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;border-radius:6px;border:1px solid var(--line);background:var(--surface)">
  <div>
    <div style="font-size:0.88rem;font-weight:600;margin-bottom:4px">
      Simulation generated <strong>{{noiseTotal $total}}</strong> alerts
      {{if gt (noiseHigh $high) 0}} (<strong>{{noiseHigh $high}}</strong> high-fidelity){{end}}.
    </div>
    <div style="font-size:0.78rem;color:#6e7681">SOC teams care about alert fatigue. High noise ratios degrade investigation SLA and increase analyst burnout risk.</div>
  </div>
  <div style="text-align:center;min-width:90px;flex-shrink:0">
    <div style="font-size:0.65rem;color:#6e7681;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Noise Score</div>
    <div style="font-size:1.6rem;font-weight:700;color:{{noiseColor $noise}}">{{noiseRound $noise}}%</div>
    <div style="font-size:0.65rem;color:#6e7681">low &lt;40% · med &lt;75%</div>
  </div>
</div>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Detection Validation</span>
</div>
</div>

<!-- ═══ 15. COVERAGE ANALYTICS ══════════════════════════════════════════ -->
<div class="page">
<h1>15. Coverage Analytics</h1>
<p style="color:#6e7681;margin-bottom:14px">
  3-bucket breakdown of every technique executed in this assessment.
  <strong style="color:#0d9488">Prevented</strong> — a control blocked execution (PASS/BLOCKED).
  <strong style="color:#d29922">Detected Only</strong> — execution succeeded but an EDR or SIEM alert fired (FAIL + detection).
  <strong style="color:#da3633">Missed</strong> — execution succeeded with no detection signal (highest risk, immediate remediation priority).
  ERROR and SKIPPED results are excluded.
</p>

{{if .coverageBreakdown.hasData}}

<!-- KPI row -->
<div class="score-row" style="grid-template-columns:repeat(4,1fr);margin-bottom:18px">
  <div class="scard">
    <div class="scard-label">Techniques Attempted</div>
    <div class="scard-value">{{.coverageBreakdown.attempted}}</div>
    <div class="scard-bar"></div>
  </div>
  <div class="scard" style="border-left:3px solid #0d9488">
    <div class="scard-label">Prevented</div>
    <div class="scard-value" style="color:#0d9488">{{.coverageBreakdown.prevented}}</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{.coverageBreakdown.preventionRate}}%;background:#0d9488"></div></div>
  </div>
  <div class="scard" style="border-left:3px solid #d29922">
    <div class="scard-label">Detected Only</div>
    <div class="scard-value" style="color:#d29922">{{.coverageBreakdown.detectedOnly}}</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{.coverageBreakdown.detectionCoverage}}%;background:#d29922"></div></div>
  </div>
  <div class="scard" style="border-left:3px solid #da3633">
    <div class="scard-label">Missed (Blind Spots)</div>
    <div class="scard-value" style="color:#da3633">{{.coverageBreakdown.missed}}</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{barWidth .summary.exposureScore}}%;background:#da3633"></div></div>
  </div>
</div>

<!-- Rate bars -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px">
  <div>
    <div style="display:flex;justify-content:space-between;font-size:0.74rem;margin-bottom:4px">
      <span style="color:#6e7681;font-weight:600">Prevention Rate</span>
      <strong style="color:#0d9488">{{.coverageBreakdown.preventionRate}}%</strong>
    </div>
    <div style="height:8px;background:var(--line);border-radius:4px;overflow:hidden">
      <div style="height:100%;width:{{.coverageBreakdown.preventionRate}}%;background:#0d9488;border-radius:4px"></div>
    </div>
  </div>
  <div>
    <div style="display:flex;justify-content:space-between;font-size:0.74rem;margin-bottom:4px">
      <span style="color:#6e7681;font-weight:600">Detection Coverage (prevented + detected)</span>
      <strong style="color:#d29922">{{.coverageBreakdown.detectionCoverage}}%</strong>
    </div>
    <div style="height:8px;background:var(--line);border-radius:4px;overflow:hidden">
      <div style="height:100%;width:{{.coverageBreakdown.detectionCoverage}}%;background:#d29922;border-radius:4px"></div>
    </div>
  </div>
</div>

<!-- Per-tactic 3-bucket table -->
{{if .coverageBreakdown.byTactic}}
<h3 style="margin-bottom:6px">By Tactic</h3>
<table>
  <thead><tr>
    <th>Tactic</th>
    <th style="text-align:center;color:#0d9488">Prevented</th>
    <th style="text-align:center;color:#d29922">Detected Only</th>
    <th style="text-align:center;color:#da3633">Missed</th>
    <th style="min-width:130px">Breakdown</th>
  </tr></thead>
  <tbody>
  {{range .coverageBreakdown.byTactic}}
  <tr>
    <td style="font-weight:600">{{humanize .tactic}}</td>
    <td style="text-align:center;color:#0d9488;font-weight:700">{{.prevented}}</td>
    <td style="text-align:center;color:#d29922;font-weight:700">{{.detectedOnly}}</td>
    <td style="text-align:center;{{if gt .missed 0}}color:#da3633;font-weight:700{{else}}color:#6e7681{{end}}">{{.missed}}</td>
    <td>
      <div class="tbar-wrap" style="height:9px;position:relative">
        {{if gt .attempted 0}}
        <div style="position:absolute;left:0;top:0;height:100%;width:{{pctOf .prevented .attempted}}%;background:#0d9488;border-radius:4px 0 0 4px"></div>
        <div style="position:absolute;left:{{pctOf .prevented .attempted}}%;top:0;height:100%;width:{{pctOf .detectedOnly .attempted}}%;background:#d29922"></div>
        {{end}}
      </div>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<!-- Top action items: missed + detectedOnly techniques -->
{{if .coverageBreakdown.missedTechniques}}
<h3 style="margin-bottom:6px;margin-top:18px">Remediation Priority — Gaps to Close</h3>
<p style="color:#6e7681;font-size:0.82rem;margin-bottom:8px">Techniques that reached the endpoint undetected (●) or were detected but not prevented (◐). Sorted by risk — missed first.</p>
<table>
  <thead><tr>
    <th style="width:110px">Technique ID</th>
    <th>Name</th>
    <th>Tactic</th>
    <th>Severity</th>
    <th>Gap</th>
  </tr></thead>
  <tbody>
  {{range .coverageBreakdown.missedTechniques}}
  <tr>
    <td style="font-family:monospace;font-size:0.8rem;font-weight:700;
      {{if eq .detectionVerdict "undetected"}}color:#da3633{{else}}color:#d29922{{end}}">
      {{if eq .detectionVerdict "undetected"}}●{{else}}◐{{end}} {{.techniqueId}}
    </td>
    <td style="font-weight:600">{{.techniqueName}}</td>
    <td>{{humanize .tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .severity}}"></span>{{.severity}}</td>
    <td style="font-size:0.78rem;color:#6e7681">
      {{if eq .detectionVerdict "undetected"}}No prevention, no detection alert{{else}}Detected by EDR/SIEM — not blocked{{end}}
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{else}}
<p style="color:#6e7681">No technique execution data available. Run a scenario to populate coverage analytics.</p>
{{end}}

<div class="footer">
  <span>{{.agent.hostname}} — Coverage Analytics</span>
</div>
</div>

<!-- ═══ 16. TECHNICAL APPENDIX — GLOSSARY ═══════════════════════════════ -->
<div class="page">
<h1>16. Technical Appendix — ATT&amp;CK Glossary</h1>
<p style="color:#6e7681;margin-bottom:14px">Authoritative MITRE ATT&amp;CK reference for every technique exercised in this assessment. Sourced from the bundled ATT&amp;CK enterprise data.</p>
{{if .glossary}}
{{range .glossary}}
<div class="gloss-item" style="margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #e5e7eb">
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
  <span>{{.agent.hostname}} — ATT&amp;CK Glossary</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>

</body>
</html>`
