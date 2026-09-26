package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"

	"github.com/audspect/bas/internal/compliance"
)

// RenderComplianceHTML writes a self-contained, styled, per-control regulatory
// compliance report for a single framework. Unlike the framework-summary table
// embedded in the full assessment report (html.go Section 14), this deliverable
// renders the auditor-facing detail that was previously reachable only as CSV/
// JSON: per-domain rollups and a per-control status table with the mapped-
// technique evidence behind each pass/fail verdict.
//
// The report is intentionally standalone (its own cover, header/footer and
// styling) so it can be handed to an auditor on its own, and its markup mirrors
// the main report's visual language (Segoe UI, the same palette, A4 print
// geometry, CONFIDENTIAL classification) so a Chrome-rendered PDF matches the
// rest of the product.
func RenderComplianceHTML(w io.Writer, cr *compliance.ComplianceReport, generatedBy string) error {
	if cr == nil {
		return fmt.Errorf("compliance report is nil")
	}
	tmpl, err := complianceTmpl()
	if err != nil {
		return err
	}
	// Tamper-evidence (P0-2): attest over the report's canonical JSON — the
	// stable underlying data, not the rendered HTML (which embeds the digest
	// and would otherwise be self-referential). A verifier can fetch the same
	// report as format=json and recompute this digest.
	canonical, _ := json.Marshal(cr)
	att := Attest(canonical, generatedBy)

	// Controls are grouped by domain in template order; the mapper already
	// emits Domains and Controls, so no re-derivation is needed here.
	data := struct {
		*compliance.ComplianceReport
		ScopeLabel  string
		Attestation Attestation
	}{cr, complianceScopeLabel(cr), att}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// RenderCompliancePDF renders the per-control compliance report to PDF via the
// headless-Chromium sidecar (pixel-identical to RenderComplianceHTML). It
// returns an error when the sidecar is unconfigured or unreachable; callers
// should fall back to serving the HTML form so the operator always gets a
// document. There is deliberately no fpdf fallback here — this is a new
// deliverable with no legacy fpdf renderer to maintain, and the whole point of
// P0 was to stop maintaining two divergent render paths.
func RenderCompliancePDF(ctx context.Context, w io.Writer, cr *compliance.ComplianceReport, generatedBy string) error {
	var html bytes.Buffer
	if err := RenderComplianceHTML(&html, cr, generatedBy); err != nil {
		return err
	}
	pdf, err := htmlToPDF(ctx, html.Bytes())
	if err != nil {
		return fmt.Errorf("compliance PDF via chrome sidecar unavailable: %w", err)
	}
	if len(pdf) == 0 {
		return fmt.Errorf("compliance PDF render produced no output")
	}
	_, err = w.Write(pdf)
	return err
}

// complianceScopeLabel describes what the report was scored against, for the
// cover and headers.
func complianceScopeLabel(cr *compliance.ComplianceReport) string {
	switch {
	case cr.ScenarioName != "":
		return cr.ScenarioName
	case cr.RunID != "":
		return "Run " + cr.RunID
	case cr.AgentID != "":
		return cr.AgentID
	default:
		return "Aggregated validation history"
	}
}

// ── template helpers ────────────────────────────────────────────────────────

// complianceArc returns the SVG stroke-dasharray ("filled gap") for a donut of
// the given radius representing pct (0..100).
func complianceArc(pct, radius float64) string {
	c := 2 * math.Pi * radius
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := c * pct / 100
	return fmt.Sprintf("%.2f %.2f", filled, c)
}

func complianceColor(pct float64) string {
	switch {
	case pct >= 90:
		return "#0d9488" // teal — strong
	case pct >= 70:
		return "#2563eb" // blue — adequate
	case pct >= 50:
		return "#b45309" // amber — weak
	default:
		return "#da3633" // red — critical
	}
}

func complianceStatusBG(status string) string {
	switch strings.ToLower(status) {
	case "pass":
		return "#ecfdf5"
	case "fail":
		return "#fef2f2"
	case "manual":
		return "#fffbeb"
	default: // untested
		return "#f3f4f6"
	}
}

func complianceStatusFG(status string) string {
	switch strings.ToLower(status) {
	case "pass":
		return "#0d9488"
	case "fail":
		return "#da3633"
	case "manual":
		return "#b45309"
	default: // untested
		return "#6b7689"
	}
}

func complianceStatusLabel(status string) string {
	switch strings.ToLower(status) {
	case "pass":
		return "PASSING"
	case "fail":
		return "FAILING"
	case "manual":
		return "MANUAL ATTESTATION"
	case "untested":
		return "UNTESTED"
	default:
		return strings.ToUpper(status)
	}
}

func complianceResultColor(result string) string {
	r := strings.ToLower(result)
	switch {
	case strings.Contains(r, "pass") || strings.Contains(r, "prevent") || strings.Contains(r, "block"):
		return "#0d9488"
	case strings.Contains(r, "fail") || strings.Contains(r, "evad") || strings.Contains(r, "detect"):
		return "#da3633"
	default:
		return "#6b7689"
	}
}

func compliancePct(f float64) string { return fmt.Sprintf("%.1f%%", f) }

var _complianceTmpl *template.Template

func complianceTmpl() (*template.Template, error) {
	if _complianceTmpl != nil {
		return _complianceTmpl, nil
	}
	t, err := template.New("compliance").Funcs(template.FuncMap{
		"pct":         compliancePct,
		"arc":         complianceArc,
		"compColor":   complianceColor,
		"statusBG":    complianceStatusBG,
		"statusFG":    complianceStatusFG,
		"statusLabel": complianceStatusLabel,
		"resultColor": complianceResultColor,
		"add1":        func(i int) int { return i + 1 },
		"upper":       strings.ToUpper,
	}).Parse(complianceReportHTML)
	if err != nil {
		return nil, err
	}
	_complianceTmpl = t
	return t, nil
}

const complianceReportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Regulatory Compliance Report — {{.Framework.Name}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:13px}
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;
  color:#1a2332;background:#fff;line-height:1.55;font-variant-numeric:tabular-nums;
  -webkit-font-smoothing:antialiased}
:root{--navy:#0b1420;--ink:#1a2332;--accent:#2563eb;--teal:#0d9488;--danger:#da3633;
  --muted:#6b7689;--line:#e8edf4;--surface:#f7f9fc}
.page{width:210mm;min-height:297mm;margin:0 auto;background:#fff;position:relative;
  page-break-after:always;break-after:page;overflow:hidden}
.page:last-child{page-break-after:avoid;break-after:avoid}
.inner{padding:20mm 18mm}
@media screen{body{background:#c8d0da;padding:24px 0}
  .page{box-shadow:0 6px 32px rgba(0,0,0,.22);margin:0 auto 28px;border-radius:2px}
  .page,.page .inner{min-height:0}}
@media print{body{background:#fff;padding:0}.page,.page .inner{min-height:0}}

/* cover */
.cover{background:linear-gradient(135deg,#0b1420 0%,#132234 60%,#183049 100%);color:#fff;
  min-height:297mm;display:flex;flex-direction:column;padding:26mm 20mm}
@media print{.cover{min-height:0;height:297mm}}
.cover-logo{font-size:1.5rem;font-weight:800;letter-spacing:.5px}
.cover-logo span{color:#38bdf8}
.cover-cat{margin-top:auto;font-size:.8rem;letter-spacing:3px;color:#7dd3fc;text-transform:uppercase}
.cover-title{font-size:2.5rem;font-weight:800;line-height:1.15;margin:6px 0 4px}
.cover-sub{font-size:1.05rem;color:#cbd5e1;font-weight:600}
.cover-meta{margin-top:26px;display:grid;grid-template-columns:1fr 1fr;gap:10px 28px;max-width:520px}
.cover-meta div{font-size:.82rem;color:#94a3b8}
.cover-meta b{display:block;color:#e2e8f0;font-size:.95rem;font-weight:600;margin-top:2px}
.cover-ring{margin-top:30px;display:flex;align-items:center;gap:20px}
.cover-ring .lbl{font-size:.82rem;color:#94a3b8;text-transform:uppercase;letter-spacing:1px}
.cover-ring .lbl b{display:block;color:#fff;font-size:1.05rem;font-weight:700;margin-top:3px}
.cover-conf{position:absolute;bottom:16mm;left:20mm;font-size:.72rem;letter-spacing:2px;
  color:#f87171;border:1px solid #7f1d1d;border-radius:3px;padding:4px 10px;text-transform:uppercase}
.cover-attest{margin-top:26px;border-top:1px solid #1e293b;padding-top:12px;max-width:560px;
  font-size:.68rem;color:#94a3b8;line-height:1.5}
.cover-attest b{color:#cbd5e1;font-weight:600}
.cover-attest .mono{font-family:"Cascadia Code","Consolas",monospace;color:#7dd3fc;word-break:break-all}
.attest-box{border:1px solid var(--line);border-radius:6px;background:var(--surface);
  padding:12px 14px;margin-top:16px;font-size:.74rem;color:var(--muted);line-height:1.6}
.attest-box b{color:var(--ink)}
.attest-box .mono{font-family:"Cascadia Code","Consolas",monospace;color:#0b5;word-break:break-all;color:var(--navy)}

/* header / footer */
.ph{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--navy);
  padding-bottom:8px;margin-bottom:16px}
.ph-logo{font-size:.95rem;font-weight:800;color:var(--navy)}
.ph-logo span{color:var(--accent)}
.ph-title{font-size:.8rem;color:var(--muted);font-weight:600}
.ph-class{font-size:.66rem;letter-spacing:1.5px;color:var(--danger);border:1px solid #fca5a5;
  border-radius:3px;padding:2px 7px;text-transform:uppercase}
.pf{position:absolute;bottom:12mm;left:18mm;right:18mm;display:flex;justify-content:space-between;
  font-size:.68rem;color:var(--muted);border-top:1px solid var(--line);padding-top:6px}

.stag{font-size:.68rem;letter-spacing:2px;color:var(--accent);text-transform:uppercase;font-weight:700}
.stitle{font-size:1.5rem;font-weight:800;color:var(--navy);margin:2px 0 10px}
.intro{color:var(--muted);font-size:.84rem;margin-bottom:16px;max-width:170mm}
.intro em{color:var(--ink);font-style:normal;font-weight:600}

/* summary cards */
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.card{border:1px solid var(--line);border-radius:6px;padding:12px 14px;background:var(--surface)}
.card .n{font-size:1.7rem;font-weight:800;line-height:1}
.card .k{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:5px}

table{width:100%;border-collapse:collapse;margin:6px 0 14px;font-size:.8rem}
th{background:var(--navy);color:#fff;text-align:left;padding:7px 9px;font-size:.72rem;
  text-transform:uppercase;letter-spacing:.4px;font-weight:600}
td{padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
tr:nth-child(even) td{background:#fafbfd}
.pill{display:inline-block;font-size:.66rem;font-weight:700;letter-spacing:.4px;
  padding:2px 8px;border-radius:10px;white-space:nowrap}
.bar{height:7px;border-radius:4px;background:#eef1f6;overflow:hidden;min-width:80px}
.bar>span{display:block;height:100%}

/* per-control blocks */
.dom{font-size:1rem;font-weight:700;color:var(--navy);margin:18px 0 6px;padding-bottom:4px;
  border-bottom:1px solid var(--line)}
.ctrl{border:1px solid var(--line);border-radius:6px;margin-bottom:10px;overflow:hidden;
  page-break-inside:avoid;break-inside:avoid}
.ctrl-h{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;
  padding:9px 12px;background:var(--surface)}
.ctrl-id{font-weight:800;color:var(--navy);font-size:.82rem}
.ctrl-name{font-size:.82rem;color:var(--ink);font-weight:600}
.ctrl-meta{font-size:.7rem;color:var(--muted);margin-top:2px}
.ev{width:100%;font-size:.76rem}
.ev th{background:#eef2f8;color:var(--navy)}
.ev td{border-bottom:1px solid #f0f3f8}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:.72rem;color:var(--muted);margin:6px 0 14px}
.legend span{display:inline-flex;align-items:center;gap:5px}
.dot{width:10px;height:10px;border-radius:3px;display:inline-block}
.none{color:var(--muted);font-size:.8rem;padding:6px 0}
</style>
</head>
<body>

<!-- ═══ COVER ═══ -->
<div class="page">
<div class="cover">
  <div class="cover-logo">Aud<span>spect</span> BAS</div>
  <div style="margin-top:auto">
    <div class="cover-cat">Regulatory Compliance Report</div>
    <div class="cover-title">{{.Framework.Name}}</div>
    <div class="cover-sub">{{.Framework.Version}}{{if .Framework.Regulator}} &middot; {{.Framework.Regulator}}{{end}}</div>
    <div class="cover-meta">
      <div>Scope<b>{{.ScopeLabel}}</b></div>
      <div>Endpoint / Agent<b>{{if .AgentID}}{{.AgentID}}{{else}}Fleet aggregate{{end}}</b></div>
      <div>Generated<b>{{.GeneratedAt.Format "02 Jan 2006, 15:04 UTC"}}</b></div>
      <div>Framework Controls<b>{{.Summary.TotalControls}} ({{.Summary.TestableControls}} testable)</b></div>
    </div>
    <div class="cover-ring">
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="52" fill="none" stroke="#1e293b" stroke-width="12"/>
        <circle cx="60" cy="60" r="52" fill="none" stroke="{{compColor .Summary.CompliancePercent}}"
          stroke-width="12" stroke-linecap="round"
          stroke-dasharray="{{arc .Summary.CompliancePercent 52}}"
          transform="rotate(-90 60 60)"/>
        <text x="60" y="58" text-anchor="middle" fill="#fff" font-size="22" font-weight="800">{{pct .Summary.CompliancePercent}}</text>
        <text x="60" y="76" text-anchor="middle" fill="#94a3b8" font-size="9" letter-spacing="1">COMPLIANCE</text>
      </svg>
      <div>
        <div class="lbl">Control Coverage<b>{{pct .Summary.CoveragePercent}}</b></div>
        <div class="lbl" style="margin-top:12px">Passing / Tested<b>{{.Summary.PassingControls}} / {{.Summary.TestedControls}}</b></div>
      </div>
    </div>
    <div class="cover-attest">
      <b>Tamper-evidence &mdash; {{.Attestation.Algorithm}}</b><br>
      Digest (SHA-256): <span class="mono">{{.Attestation.ContentSHA256}}</span><br>
      Tool {{.Attestation.ToolVersion}} &middot; Generated {{.Attestation.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}{{if .Attestation.GeneratedBy}} &middot; by {{.Attestation.GeneratedBy}}{{end}}
      {{if .Attestation.Signature}}<br>Signature: <span class="mono">{{.Attestation.Signature}}</span>{{end}}
    </div>
  </div>
  <div class="cover-conf">Confidential</div>
</div>
</div>

<!-- ═══ SUMMARY + DOMAINS ═══ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-logo">Aud<span>spect</span> BAS</div>
  <div class="ph-title">{{.Framework.Name}} — Compliance</div>
  <div class="ph-class">Confidential</div>
</div>

<div class="stag">Compliance Overview</div>
<div class="stitle">{{.Framework.Name}}</div>
<p class="intro">Compliance is scored from breach-and-attack-simulation evidence over the <em>BAS-testable</em> control subset. A control is <em>Passing</em> when every mapped ATT&CK technique passed, <em>Failing</em> when at least one failed, and <em>Untested</em> when no mapped technique was included in the assessed run(s). <em>Manual</em> controls are governance/process requirements that cannot be validated by simulation and are excluded from both percentages — they require manual attestation.</p>

<div class="cards">
  <div class="card"><div class="n" style="color:{{compColor .Summary.CompliancePercent}}">{{pct .Summary.CompliancePercent}}</div><div class="k">Compliance (passing / tested)</div></div>
  <div class="card"><div class="n" style="color:{{compColor .Summary.CoveragePercent}}">{{pct .Summary.CoveragePercent}}</div><div class="k">Coverage (tested / testable)</div></div>
  <div class="card"><div class="n" style="color:var(--teal)">{{.Summary.PassingControls}}</div><div class="k">Passing controls</div></div>
  <div class="card"><div class="n" style="color:var(--danger)">{{.Summary.FailingControls}}</div><div class="k">Failing controls</div></div>
  <div class="card"><div class="n">{{.Summary.TotalControls}}</div><div class="k">Total controls</div></div>
  <div class="card"><div class="n">{{.Summary.TestableControls}}</div><div class="k">Testable</div></div>
  <div class="card"><div class="n" style="color:var(--muted)">{{.Summary.UntestedControls}}</div><div class="k">Untested</div></div>
  <div class="card"><div class="n" style="color:#b45309">{{.Summary.ManualControls}}</div><div class="k">Manual attestation</div></div>
</div>

{{if .Narrative}}<p class="intro" style="max-width:none;color:var(--ink)">{{.Narrative}}</p>{{end}}

<div class="legend">
  <span><i class="dot" style="background:#0d9488"></i>Passing</span>
  <span><i class="dot" style="background:#da3633"></i>Failing</span>
  <span><i class="dot" style="background:#6b7689"></i>Untested</span>
  <span><i class="dot" style="background:#b45309"></i>Manual attestation</span>
</div>

{{if .Domains}}
<div class="dom">Domain Breakdown</div>
<table>
  <thead><tr><th>Domain</th><th>Controls</th><th>Passing</th><th>Failing</th><th>Untested</th><th>Manual</th><th style="width:150px">Compliance</th></tr></thead>
  <tbody>
  {{range .Domains}}
  <tr>
    <td style="font-weight:600">{{.Name}}</td>
    <td>{{.Total}}</td>
    <td style="color:var(--teal)">{{.Passing}}</td>
    <td style="color:{{if gt .Failing 0}}var(--danger){{else}}var(--muted){{end}}">{{.Failing}}</td>
    <td style="color:var(--muted)">{{.Untested}}</td>
    <td style="color:var(--muted)">{{.Manual}}</td>
    <td>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="bar"><span style="width:{{pct .CompliancePct}};background:{{compColor .CompliancePct}}"></span></div>
        <b style="color:{{compColor .CompliancePct}};font-size:.76rem">{{pct .CompliancePct}}</b>
      </div>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<div class="pf"><span>{{.Framework.Name}} — Compliance Overview</span><span>Audspect BAS &middot; Confidential</span></div>
</div>
</div>

<!-- ═══ PER-CONTROL DETAIL ═══ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-logo">Aud<span>spect</span> BAS</div>
  <div class="ph-title">{{.Framework.Name}} — Control Detail</div>
  <div class="ph-class">Confidential</div>
</div>
<div class="stag">Control-by-Control Evidence</div>
<div class="stitle">Control Detail &amp; Evidence</div>
<p class="intro">Every framework control with its BAS verdict and the mapped ATT&CK-technique evidence behind it. Manual controls are listed for completeness and marked for attestation.</p>

{{if .Controls}}
{{range .Controls}}
<div class="ctrl">
  <div class="ctrl-h">
    <div>
      <span class="ctrl-id">{{.ID}}</span> &nbsp; <span class="ctrl-name">{{.Name}}</span>
      <div class="ctrl-meta">{{if .Domain}}{{.Domain}}{{end}}{{if .Category}} &middot; {{.Category}}{{end}}
        {{if .Testable}} &middot; Tested {{.Tested}} &middot; Passed {{.Passed}} &middot; Failed {{.Failed}}{{end}}</div>
    </div>
    <span class="pill" style="background:{{statusBG .Status}};color:{{statusFG .Status}}">{{statusLabel .Status}}</span>
  </div>
  {{if .Evidence}}
  <table class="ev">
    <thead><tr><th style="width:90px">Technique</th><th>Name</th><th style="width:90px">Result</th><th>Details / Remediation</th></tr></thead>
    <tbody>
    {{range .Evidence}}
    <tr>
      <td style="font-family:monospace;font-weight:600">{{.TechniqueID}}</td>
      <td>{{.TechniqueName}}</td>
      <td style="font-weight:700;color:{{resultColor .Result}}">{{upper .Result}}</td>
      <td>{{if .Details}}{{.Details}}{{end}}{{if .Remediation}}<div style="color:var(--muted);margin-top:3px"><b style="color:var(--ink)">Remediation:</b> {{.Remediation}}</div>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else if eq .Status "manual"}}
  <div style="padding:8px 12px;font-size:.78rem;color:#b45309">Requires manual attestation — governance/process control, not simulation-validatable.</div>
  {{else}}
  <div style="padding:8px 12px;font-size:.78rem;color:var(--muted)">No mapped technique was included in the assessed run(s).</div>
  {{end}}
</div>
{{end}}
{{else}}
<p class="none">No controls resolved for this framework.</p>
{{end}}

<div class="attest-box">
  <b>Report authenticity.</b> This report carries a {{.Attestation.Algorithm}} attestation over its canonical data.
  Digest (SHA-256): <span class="mono">{{.Attestation.ContentSHA256}}</span>.
  {{if .Attestation.Signature}}The signature binds this digest to the generating Audspect deployment, its tool version ({{.Attestation.ToolVersion}}){{if .Attestation.GeneratedBy}}, and the operator who produced it{{end}}; only that deployment can reproduce a valid signature.{{else}}Report signing is not configured on this deployment, so the digest detects modification but is not authenticated.{{end}}
  To verify, request the same report as JSON (<span class="mono">format=json</span>) and recompute the SHA-256 of its canonical bytes.
</div>

<div class="pf"><span>{{.Framework.Name}} — Control Detail</span><span>Audspect BAS &middot; Confidential</span></div>
</div>
</div>

</body>
</html>`
