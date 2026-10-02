package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
)

// RenderBoardOnePager writes a single-page executive/board security scorecard.
//
// Where the full report is a multi-page technical/purple-team document, this is
// the one page a CISO puts in front of a board: overall posture, the trend,
// the handful of KPIs that matter, per-framework compliance, the top risks and
// the top recommended actions — all above the fold on one A4 page. It reuses
// the same FullReport the engine already builds (no new data derivation) and
// carries the P0-2 tamper-evidence attestation in its footer.
func RenderBoardOnePager(w io.Writer, r *FullReport, compliance []ComplianceSummaryRow, generatedBy string) error {
	if r == nil {
		return fmt.Errorf("report is nil")
	}
	tmpl, err := boardTmpl()
	if err != nil {
		return err
	}

	// Attest over the canonical data (report + compliance rows), matching the
	// compliance report's approach so a verifier can recompute from JSON.
	canonical, _ := json.Marshal(struct {
		Report     *FullReport            `json:"report"`
		Compliance []ComplianceSummaryRow `json:"compliance"`
	}{r, compliance})
	att := Attest(canonical, generatedBy)

	scope := r.Agent.Hostname
	if r.Scope != nil && r.Scope.Title != "" {
		scope = r.Scope.Title
	}
	if scope == "" {
		scope = r.Agent.AgentID
	}

	// Cap the lists so the page never overflows a single sheet.
	drivers := r.TopRiskDrivers
	if len(drivers) > 3 {
		drivers = drivers[:3]
	}
	actions := r.ActionPlan
	if len(actions) > 3 {
		actions = actions[:3]
	}
	comp := compliance
	if len(comp) > 6 {
		comp = comp[:6]
	}

	data := struct {
		*FullReport
		Compliance  []ComplianceSummaryRow
		Drivers     []RiskDriver
		Actions     []ActionItem
		ScopeLabel  string
		SparkPoints string
		Attestation Attestation
		Brand       brandView
	}{r, comp, drivers, actions, scope, boardSparkline(r.TrendAnalysis), att, brandingView()}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// RenderBoardOnePagerPDF renders the one-pager to PDF via the Chrome sidecar.
// Returns an error when the sidecar is unavailable so the caller can fall back
// to HTML (same posture as the compliance report).
func RenderBoardOnePagerPDF(ctx context.Context, w io.Writer, r *FullReport, compliance []ComplianceSummaryRow, generatedBy string) error {
	var html bytes.Buffer
	if err := RenderBoardOnePager(&html, r, compliance, generatedBy); err != nil {
		return err
	}
	pdf, err := htmlToPDF(ctx, html.Bytes())
	if err != nil {
		return fmt.Errorf("board one-pager PDF via chrome sidecar unavailable: %w", err)
	}
	if len(pdf) == 0 {
		return fmt.Errorf("board one-pager render produced no output")
	}
	_, err = w.Write(pdf)
	return err
}

// boardSparkline builds an SVG polyline "points" attribute from the prevention
// history (oldest→newest), scaled into a 200×40 viewBox. Empty when <2 points.
func boardSparkline(t TrendSummary) string {
	if len(t.History) < 2 {
		return ""
	}
	const w, h = 200.0, 40.0
	n := len(t.History)
	var b strings.Builder
	for i, p := range t.History {
		x := float64(i) / float64(n-1) * w
		// PreventionScore is 0..100; invert so higher score sits higher on screen.
		y := h - (p.PreventionScore/100.0)*h
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

// riskScoreColor: higher risk score is worse (0=good .. 100=critical). Accepts
// int, *int (AttackPathScore) or float64 so one helper serves every risk metric.
func riskScoreColor(v any) string {
	score := 0
	switch t := v.(type) {
	case int:
		score = t
	case *int:
		if t != nil {
			score = *t
		}
	case int64:
		score = int(t)
	case float64:
		score = int(t)
	}
	switch {
	case score >= 75:
		return "#c00000"
	case score >= 50:
		return "#ed7d31"
	case score >= 25:
		return "#b45309"
	default:
		return "#0d9488"
	}
}

// preventionColor: higher prevention is better.
func preventionColor(pct float64) string {
	switch {
	case pct >= 80:
		return "#0d9488"
	case pct >= 60:
		return "#2563eb"
	case pct >= 40:
		return "#b45309"
	default:
		return "#c00000"
	}
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "#c00000"
	case "high":
		return "#ed7d31"
	case "medium":
		return "#b45309"
	default:
		return "#6b7689"
	}
}

func trendArrow(delta float64) template.HTML {
	switch {
	case delta > 0.05:
		return template.HTML(fmt.Sprintf(`<span style="color:#0d9488">&#9650; +%.1f pts</span>`, delta))
	case delta < -0.05:
		return template.HTML(fmt.Sprintf(`<span style="color:#c00000">&#9660; %.1f pts</span>`, delta))
	default:
		return template.HTML(`<span style="color:#6b7689">&#9644; no change</span>`)
	}
}

var _boardTmpl *template.Template

func boardTmpl() (*template.Template, error) {
	if _boardTmpl != nil {
		return _boardTmpl, nil
	}
	t, err := template.New("board").Funcs(template.FuncMap{
		"pct":        compliancePct,
		"compColor":  complianceColor,
		"riskColor":  riskScoreColor,
		"prevColor":  preventionColor,
		"sevColor":   severityColor,
		"trendArrow": trendArrow,
		"riskLabel": func(c string) string {
			// classify() returns "Medium Risk"/"High Risk"/"Low Risk" (with the
			// suffix) but "Critical" (without), so a bare "<c> Risk" doubled it.
			// Normalize: strip any trailing " Risk", then append once.
			c = strings.TrimSpace(c)
			if c == "" {
				return "Unknown Risk"
			}
			c = strings.TrimSuffix(c, " Risk")
			return c + " Risk"
		},
		"add1": func(i int) int { return i + 1 },
		"fmtF": func(v any) string {
			switch t := v.(type) {
			case float64:
				return fmt.Sprintf("%.0f", t)
			case int:
				return fmt.Sprintf("%d", t)
			case int64:
				return fmt.Sprintf("%d", t)
			default:
				return fmt.Sprintf("%v", t)
			}
		},
	}).Parse(boardReportHTML)
	if err != nil {
		return nil, err
	}
	_boardTmpl = t
	return t, nil
}

const boardReportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Executive Security Scorecard — {{.ScopeLabel}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:12px}
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff}
:root{--navy:#0b1420;--ink:#1a2332;--accent:#2563eb;--teal:#0d9488;--danger:#c00000;--muted:#6b7689;--line:#e2e8f0;--surface:#f7f9fc}
.page{width:210mm;height:297mm;margin:0 auto;background:#fff;position:relative;overflow:hidden;
  display:flex;flex-direction:column;padding:12mm 12mm 10mm}
@media screen{body{background:#c8d0da;padding:20px 0}.page{box-shadow:0 6px 32px rgba(0,0,0,.22);margin:0 auto;border-radius:2px}}

.hdr{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:2.5px solid var(--navy);padding-bottom:8px}
.hdr .logo{font-size:1.15rem;font-weight:800;color:var(--navy)}
.hdr .logo span{color:var(--accent)}
.hdr .t{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;font-weight:700;margin-top:2px}
.hdr .r{text-align:right;font-size:.72rem;color:var(--muted)}
.hdr .r b{display:block;color:var(--ink);font-size:.9rem}
.hdr .class{color:var(--danger);border:1px solid #fca5a5;border-radius:3px;padding:1px 6px;font-size:.6rem;letter-spacing:1.5px;text-transform:uppercase;display:inline-block;margin-top:3px}

.title{font-size:1.7rem;font-weight:800;color:var(--navy);margin:12px 0 2px}
.subtitle{font-size:.82rem;color:var(--muted);margin-bottom:12px}

/* hero */
.hero{display:flex;gap:14px;margin-bottom:12px}
.hero .risk{flex:0 0 200px;border-radius:8px;color:#fff;padding:14px 16px;display:flex;flex-direction:column;justify-content:center}
.hero .risk .n{font-size:3.2rem;font-weight:800;line-height:1}
.hero .risk .c{font-size:1rem;font-weight:700;margin-top:2px}
.hero .risk .s{font-size:.72rem;opacity:.85;margin-top:6px}
.hero .kpis{flex:1;display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:10px 12px;background:var(--surface)}
.kpi .n{font-size:1.7rem;font-weight:800;line-height:1}
.kpi .k{font-size:.66rem;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-top:5px}

.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:12px}
.card{border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card h3{font-size:.78rem;text-transform:uppercase;letter-spacing:.6px;color:var(--navy);margin-bottom:9px;
  border-bottom:1px solid var(--line);padding-bottom:5px}
.row{display:flex;align-items:center;gap:8px;margin-bottom:7px;font-size:.8rem}
.bar{flex:1;height:7px;border-radius:4px;background:#eef1f6;overflow:hidden}
.bar>span{display:block;height:100%}
.fw{flex:0 0 118px;font-weight:600;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pctv{flex:0 0 44px;text-align:right;font-weight:700}

.risklist .item,.actlist .item{display:flex;gap:8px;margin-bottom:8px;font-size:.8rem;line-height:1.35}
.risklist .rank,.actlist .rank{flex:0 0 18px;height:18px;border-radius:50%;background:var(--navy);color:#fff;
  font-size:.66rem;font-weight:700;display:flex;align-items:center;justify-content:center;margin-top:1px}
.risklist .sev{font-size:.6rem;font-weight:700;padding:1px 5px;border-radius:8px;color:#fff;text-transform:uppercase;white-space:nowrap}

.trend{display:flex;align-items:center;gap:16px;border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin-bottom:12px}
.trend .lbl{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.trend .lbl b{display:block;color:var(--ink);font-size:1.1rem;font-weight:800;margin-top:2px}

.foot{margin-top:auto;border-top:1px solid var(--line);padding-top:8px;font-size:.62rem;color:var(--muted);line-height:1.5}
.foot .mono{font-family:"Cascadia Code","Consolas",monospace;color:var(--navy);word-break:break-all}
.none{color:var(--muted);font-size:.78rem}
</style>
<style>:root{--accent:{{.Brand.AccentCSS}}}</style>
</head>
<body>
<div class="page">

  <div class="hdr">
    <div>
      <div class="logo">{{.Brand.LogoHTML}}</div>
      <div class="t">Executive Security Scorecard</div>
    </div>
    <div class="r">
      Subject<b>{{.ScopeLabel}}</b>
      {{if .Summary.LastRunAt}}<div style="margin-top:3px">As of {{.Summary.LastRunAt.Format "02 Jan 2006"}}</div>{{end}}
      <span class="class">Confidential</span>
    </div>
  </div>

  <div class="title">Security Posture at a Glance</div>
  <div class="subtitle">{{if .Scope}}{{.Scope.Subtitle}}{{else}}Continuous breach &amp; attack simulation — {{.Summary.LastScenarioName}}{{end}}</div>

  <!-- hero: risk score + KPIs -->
  <div class="hero">
    <div class="risk" style="background:{{riskColor .Summary.RiskScore}}">
      <div class="n">{{.Summary.RiskScore}}</div>
      <div class="c">{{riskLabel .Summary.Classification}}</div>
      <div class="s">Exposure: {{.Summary.ExposureLevel}} &middot; {{.Summary.TotalTechniques}} techniques tested</div>
    </div>
    <div class="kpis">
      <div class="kpi"><div class="n" style="color:{{prevColor .Summary.PreventionScore}}">{{fmtF .Summary.PreventionScore}}%</div><div class="k">Prevention</div></div>
      <div class="kpi"><div class="n" style="color:{{prevColor .Summary.DetectionScore}}">{{if .Summary.DetectionMeasured}}{{fmtF .Summary.DetectionScore}}%{{else}}N/A{{end}}</div><div class="k">Detection</div></div>
      <div class="kpi"><div class="n" style="color:{{riskColor .Summary.PenetrationPct}}">{{.Summary.PenetrationPct}}%</div><div class="k">Penetration</div></div>
      {{if .Summary.AttackPathScore}}
      <div class="kpi"><div class="n" style="color:{{riskColor .Summary.AttackPathScore}}">{{.Summary.AttackPathScore}}</div><div class="k">Attack Path ({{.Summary.AttackPathBand}})</div></div>
      {{else}}
      <div class="kpi"><div class="n" style="color:{{prevColor .Summary.CoverageScore}}">{{fmtF .Summary.CoverageScore}}%</div><div class="k">Defense Coverage</div></div>
      {{end}}
    </div>
  </div>

  <!-- trend -->
  <div class="trend">
    <div class="lbl">Prevention Trend<b>{{trendArrow .TrendAnalysis.DeltaPrevention}}</b></div>
    {{if .SparkPoints}}
    <svg width="220" height="44" viewBox="0 0 200 40" preserveAspectRatio="none" style="flex:0 0 220px">
      <polyline points="{{.SparkPoints}}" fill="none" stroke="{{prevColor .TrendAnalysis.CurrentPrevention}}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
    </svg>
    {{else}}<span class="none">Not enough history for a trend yet — trend appears after the second assessment.</span>{{end}}
    <div class="lbl" style="margin-left:auto">Detection blind spots<b style="color:{{riskColor .Summary.UndetectedRate}}">{{.Summary.UndetectedRate}}%</b></div>
    <div class="lbl">Mean time-to-detect<b>{{if .Summary.MTTDMs}}{{fmtF .Summary.MTTDMs}} ms{{else}}—{{end}}</b></div>
  </div>

  <!-- compliance + top risks -->
  <div class="grid2">
    <div class="card">
      <h3>Regulatory Compliance</h3>
      {{if .Compliance}}
      {{range .Compliance}}
      <div class="row">
        <span class="fw" title="{{.Framework}}">{{.Framework}}</span>
        <div class="bar"><span style="width:{{pct .CompliancePct}};background:{{compColor .CompliancePct}}"></span></div>
        <span class="pctv" style="color:{{compColor .CompliancePct}}">{{pct .CompliancePct}}</span>
      </div>
      {{end}}
      {{else}}<p class="none">No compliance data yet — map scenarios to frameworks and run an assessment.</p>{{end}}
    </div>

    <div class="card risklist">
      <h3>Top Risk Drivers</h3>
      {{if .Drivers}}
      {{range $i, $d := .Drivers}}
      <div class="item">
        <span class="rank">{{add1 $i}}</span>
        <div style="flex:1">
          <b>{{$d.Name}}</b> <span style="color:var(--muted)">({{$d.TechniqueID}})</span><br>
          <span style="color:var(--muted);font-size:.72rem">{{$d.Tactic}} &middot; {{$d.Failures}} failure(s) &middot; {{fmtF $d.ScorePoints}} pts of risk</span>
        </div>
        <span class="sev" style="background:{{sevColor $d.Severity}}">{{$d.Severity}}</span>
      </div>
      {{end}}
      {{else}}<p class="none">No failing techniques — no material risk drivers this period.</p>{{end}}
    </div>
  </div>

  <!-- recommended actions -->
  <div class="card actlist" style="margin-bottom:12px">
    <h3>Priority Actions</h3>
    {{if .Actions}}
    {{range $i, $a := .Actions}}
    <div class="item">
      <span class="rank">{{add1 $i}}</span>
      <div style="flex:1"><b>{{$a.Tactic}}{{if $a.Objective}} — {{$a.Objective}}{{end}}</b><br>
        <span style="color:var(--muted);font-size:.74rem">{{$a.Recommendation}}</span></div>
      <span style="flex:0 0 60px;text-align:right;font-weight:700;color:var(--danger)">{{fmtF $a.ScorePoints}} pts</span>
    </div>
    {{end}}
    {{else}}<p class="none">No remediation actions outstanding from this assessment.</p>{{end}}
  </div>

  <!-- attestation footer -->
  <div class="foot">
    <b>Tamper-evidence ({{.Attestation.Algorithm}}).</b> Digest (SHA-256): <span class="mono">{{.Attestation.ContentSHA256}}</span>.
    Tool {{.Attestation.ToolVersion}} &middot; Generated {{.Attestation.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}}{{if .Attestation.GeneratedBy}} &middot; by {{.Attestation.GeneratedBy}}{{end}}.
    {{if .Attestation.Signature}}Signed — only the issuing Audspect deployment can reproduce this signature.{{end}}
    {{.Brand.OrgName}} — Executive Security Scorecard. CONFIDENTIAL, for authorized use only.
  </div>

</div>
</body>
</html>`
