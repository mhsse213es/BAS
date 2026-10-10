package reporting

// adAssessmentTmpl is the enterprise AD coverage assessment HTML (also the PDF
// source). Every dynamic field is auto-escaped by html/template.
const adAssessmentTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Active Directory Coverage Assessment</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:13px}
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;line-height:1.6;font-variant-numeric:tabular-nums}
:root{--line:#e8edf4;--surface:#f7f9fc;--navy:#0b1420;--teal:#0d9488;--muted:#6b7689}
.page{width:210mm;min-height:297mm;margin:0 auto;background:#fff;position:relative;page-break-after:always;break-after:page;overflow:hidden}
.page:last-child{page-break-after:avoid;break-after:avoid}
@media screen{body{background:#c8d0da;padding:24px 0}.page{box-shadow:0 6px 32px rgba(0,0,0,.22);margin:0 auto 28px}}
@media print{body{background:#fff;padding:0}.page{width:100%;margin:0;box-shadow:none;overflow:visible}thead{display:table-header-group}}
.cover{background:#0b1420;min-height:297mm;display:flex;flex-direction:column;padding:48px}
.clogo-name{font-size:1.15rem;font-weight:800;color:#fff;letter-spacing:-.03em}
.clogo-name span{color:#0d9488}
.clogo-sub{font-size:.58rem;text-transform:uppercase;letter-spacing:.16em;color:#4a6a8a;margin-top:1px}
.cover-body{flex:1;display:flex;flex-direction:column;justify-content:center}
.cover-eyebrow{font-size:.62rem;text-transform:uppercase;letter-spacing:.2em;color:#0d9488;font-weight:700;margin-bottom:12px}
.cover-title{font-size:2.4rem;font-weight:900;color:#fff;letter-spacing:-.04em;line-height:1.05;margin-bottom:10px}
.cover-sub{font-size:.95rem;color:#6a8aaa;margin-bottom:28px}
.cover-rule{width:56px;height:3px;background:linear-gradient(90deg,#0d9488,#2563eb);border-radius:2px;margin-bottom:28px}
.cb{display:inline-flex;align-items:center;gap:6px;padding:6px 13px;border-radius:20px;font-size:.64rem;font-weight:700;background:rgba(220,166,0,.1);border:1px solid rgba(220,166,0,.28);color:#e0bc30}
.inner{padding:0 48px 28px;min-height:297mm;display:flex;flex-direction:column}
.ph{display:flex;justify-content:space-between;align-items:center;padding:16px 0 14px;border-bottom:1px solid #e8edf4;margin-bottom:24px}
.ph-logo{font-size:.78rem;font-weight:800;color:#0b1420}.ph-logo span{color:#0d9488}
.ph-class{font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:#dc2626;background:#fff0f0;border:1px solid #fca5a5;padding:2px 8px;border-radius:3px}
.stag{font-size:.57rem;text-transform:uppercase;letter-spacing:.2em;color:#0d9488;font-weight:700;margin-bottom:5px}
.stitle{font-size:1.28rem;font-weight:900;color:#0b1420;letter-spacing:-.025em;line-height:1.15;margin-bottom:16px;padding-left:13px;border-left:4px solid #0d9488}
h2{font-size:.9rem;font-weight:800;color:#0b1420;margin:20px 0 10px}
p{margin-bottom:9px;font-size:.82rem}
.callout{border-radius:8px;padding:12px 15px;margin-bottom:16px;font-size:.8rem;line-height:1.6;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412}
.kpi-row{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:18px}
.kpi{background:#fff;border:1px solid #e7eaf0;border-radius:10px;padding:14px;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--c,#0d9488)}
.kpi-lbl{font-size:.55rem;text-transform:uppercase;letter-spacing:.08em;color:#9aa5b5;font-weight:700;margin-bottom:6px}
.kpi-val{font-size:1.5rem;font-weight:900;color:var(--c,#0d9488);line-height:1}
table{width:100%;border-collapse:collapse;font-size:.74rem;margin-bottom:16px}
thead th{background:#f0f4f8;color:#5a7a9a;text-transform:uppercase;font-size:.55rem;letter-spacing:.08em;font-weight:700;text-align:left;padding:7px 9px;border-bottom:1.5px solid #e0e7ef}
td{padding:7px 9px;border-bottom:1px solid #f0f4f8;vertical-align:top;color:#1a2332}
tbody tr:nth-child(even) td{background:#fbfcfe}
.mono{font-family:monospace;font-size:.68rem;color:#5a7a9a}
.pill{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.6rem;font-weight:700}
.p-grey{background:#eef1f6;color:#6b7280}.p-green{background:#d1fae5;color:#065f46}.p-amber{background:#fef3c7;color:#92400e}.p-red{background:#fee2e2;color:#991b1b}
ul{margin:0 0 12px 18px}li{font-size:.8rem;margin-bottom:5px}
.def{font-size:.78rem;margin-bottom:8px}.def b{color:#0b1420}
.pf{margin-top:auto;padding-top:12px;border-top:1px solid #f0f4f8;display:flex;justify-content:space-between;font-size:.58rem;color:#9ab0c8}
</style>
</head>
<body>

<div class="page"><div class="cover">
  <div class="clogo-name">Aud<span>spect</span> BAS</div>
  <div class="clogo-sub">Breach &amp; Attack Simulation Platform</div>
  <div class="cover-body">
    <div class="cover-eyebrow">Active Directory Coverage Assessment</div>
    <div class="cover-title">AD Capability Coverage &amp; Validation State</div>
    <div class="cover-sub">Generated {{fmtTime .GeneratedAt}} · Modeled coverage report — not validated against real Active Directory</div>
    <div class="cover-rule"></div>
    <div class="cb">&#9888; CONFIDENTIAL — Authorised Recipients Only</div>
  </div>
  <div style="font-size:.62rem;color:#2a4a6a">Audspect BAS Platform · Classification: CONFIDENTIAL</div>
</div></div>

<div class="page"><div class="inner">
<div class="ph"><div class="ph-logo">Aud<span>spect</span> BAS</div><div class="ph-class">CONFIDENTIAL</div></div>
<div class="stag">Section 1</div><div class="stitle">Executive Summary</div>
<div class="callout"><strong>Modeled coverage, not validated AD security.</strong> {{.Report.CapabilityStateSummary.Executed}} of {{.Report.CapabilityStateSummary.Total}} capabilities executed and {{.Report.CapabilityStateSummary.DetectionValidated}} detection-validated. These results are not validated against real Active Directory: content availability and scenario composition do not imply a technique has run against, or been detected in, a live domain.</div>
<div class="kpi-row">
  <div class="kpi" style="--c:#2563eb"><div class="kpi-lbl">Capabilities</div><div class="kpi-val">{{.Report.CapabilityStateSummary.Total}}</div></div>
  <div class="kpi" style="--c:#0d9488"><div class="kpi-lbl">Modeled</div><div class="kpi-val">{{.Report.CapabilityStateSummary.Modeled}}</div></div>
  <div class="kpi" style="--c:#6366f1"><div class="kpi-lbl">Scenario-composed</div><div class="kpi-val">{{.Report.CapabilityStateSummary.ScenarioComposed}}</div></div>
  <div class="kpi" style="--c:#9aa5b5"><div class="kpi-lbl">Executed vs real AD</div><div class="kpi-val">{{.Report.CapabilityStateSummary.Executed}}</div></div>
  <div class="kpi" style="--c:#9aa5b5"><div class="kpi-lbl">Detection-validated</div><div class="kpi-val">{{.Report.CapabilityStateSummary.DetectionValidated}}</div></div>
</div>
<h2>Coverage Summary</h2>
<table>
<thead><tr><th>Content availability</th><th>Count</th></tr></thead>
<tbody>
<tr><td>Scenario-composable</td><td>{{.Report.ContentSummary.ScenarioComposable}}</td></tr>
<tr><td>Reusable (unmapped)</td><td>{{.Report.ContentSummary.ReusableUnmapped}}</td></tr>
<tr><td>Model-only</td><td>{{.Report.ContentSummary.ModelOnly}}</td></tr>
<tr><td>Missing executable content</td><td>{{.Report.ContentSummary.MissingExecutable}}</td></tr>
</tbody>
</table>
<div class="pf"><span>Audspect BAS — AD Coverage Assessment</span><span>CONFIDENTIAL</span></div>
</div></div>

<div class="page"><div class="inner">
<div class="ph"><div class="ph-logo">Aud<span>spect</span> BAS</div><div class="ph-class">CONFIDENTIAL</div></div>
<div class="stag">Section 2</div><div class="stitle">Capability Results</div>
{{range .Families}}
<h2>{{.Name}}</h2>
<table>
<thead><tr><th>Capability</th><th>Technique</th><th>Content</th><th>Composition</th><th>Execution</th><th>Detection</th></tr></thead>
<tbody>
{{range .Caps}}
<tr>
<td>{{.Name}}<div class="mono">{{.PrimitiveID}}</div></td>
<td class="mono">{{.TechniqueID}}</td>
<td><span class="pill p-grey">{{contentLabel .ContentAvailability}}</span></td>
<td><span class="pill {{if .ScenarioComposed}}p-green{{else}}p-grey{{end}}">{{composedLabel .ScenarioComposed}}</span></td>
<td><span class="pill p-grey">{{execLabel .ExecutionValidation}}</span></td>
<td><span class="pill p-grey">{{detLabel .DetectionValidation}}</span></td>
</tr>
{{end}}
</tbody>
</table>
{{end}}
<div class="pf"><span>Audspect BAS — AD Coverage Assessment</span><span>CONFIDENTIAL</span></div>
</div></div>

<div class="page"><div class="inner">
<div class="ph"><div class="ph-logo">Aud<span>spect</span> BAS</div><div class="ph-class">CONFIDENTIAL</div></div>
<div class="stag">Section 3</div><div class="stitle">Limitations &amp; Content Provenance</div>
<p>The following constraints apply to what has actually been demonstrated. Content availability is a repository-classification axis: where the live ART/Caldera content stores are not attached, "missing" means not found in the attached store, never a verified absence across all libraries.</p>
{{if .AllLimitations}}
<ul>{{range .AllLimitations}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p>No capability-specific limitations recorded.</p>{{end}}
<div class="pf"><span>Audspect BAS — AD Coverage Assessment</span><span>CONFIDENTIAL</span></div>
</div></div>

<div class="page"><div class="inner">
<div class="ph"><div class="ph-logo">Aud<span>spect</span> BAS</div><div class="ph-class">CONFIDENTIAL</div></div>
<div class="stag">Section 4</div><div class="stitle">Outstanding Work &amp; Remediation</div>
{{if .AllOutstanding}}
<ul>{{range .AllOutstanding}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p>No outstanding items recorded.</p>{{end}}

<div class="stag" style="margin-top:28px">Section 5</div><div class="stitle">Methodology &amp; Status Definitions</div>
<div class="def"><b>Modeled</b> — represented in the capability catalog with environment predicates and a lab resolver. Does not imply any execution.</div>
<div class="def"><b>Content availability</b> — whether reusable execution content exists in the repository (scenario-composable / reusable-unmapped / model-only / missing). A repository classification, not a live-store guarantee.</div>
<div class="def"><b>Composition</b> — a committed Audspect scenario performs this capability. Composition does not imply the technique was executed.</div>
<div class="def"><b>Execution</b> — whether the capability has been executed against a real Active Directory and its postcondition observed. "Not executed" is the honest default.</div>
<div class="def"><b>Detection</b> — whether attributable telemetry/alerting was observed for an executed capability. Never inferred from execution or content.</div>
<p style="margin-top:12px;color:#6b7689">These five axes are independent and are never auto-promoted: a capability can be scenario-composable yet remain not-executed and not-detection-validated.</p>
<div class="pf"><span>Audspect BAS — AD Coverage Assessment</span><span>CONFIDENTIAL</span></div>
</div></div>

</body>
</html>
`
