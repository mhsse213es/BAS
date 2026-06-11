package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	fpdf "github.com/go-pdf/fpdf"

	"github.com/audspect/bas/internal/models"
)

// ── Theme ───────────────────────────────────────────────────────────────────
// Print-friendly: mostly white pages with a navy identity and meaningful
// status colours. The cover page is full-bleed navy for impact.

type rgb struct{ r, g, b int }

var (
	cNavy    = rgb{11, 20, 32}
	cAccent  = rgb{47, 129, 247}
	cMuted   = rgb{110, 124, 143}
	cInk     = rgb{30, 41, 59}
	cLine    = rgb{210, 217, 226}
	cSuccess = rgb{30, 122, 50}
	cWarning = rgb{176, 124, 12}
	cDanger  = rgb{200, 38, 36}
	cWhite   = rgb{255, 255, 255}
)

const (
	pageW    = 210.0
	margin   = 18.0
	contentW = pageW - 2*margin // 174mm
)

// rpt wraps the fpdf document with themed drawing helpers.
type rpt struct {
	pdf      *fpdf.Fpdf
	docTitle string
	tr       func(string) string // UTF-8 → core-font (CP1252) encoder
}

func (d *rpt) fill(c rgb) { d.pdf.SetFillColor(c.r, c.g, c.b) }
func (d *rpt) text(c rgb) { d.pdf.SetTextColor(c.r, c.g, c.b) }
func (d *rpt) draw(c rgb) { d.pdf.SetDrawColor(c.r, c.g, c.b) }

// cellT / mcellT / cfT are the text-writing entry points. They run every string
// through tr so UTF-8 punctuation (— · × …) is encoded for the WinAnsi/CP1252
// core fonts. Writing raw UTF-8 to fpdf's core fonts otherwise renders mojibake
// (e.g. "—" → "Ã¢â‚¬â€•", "×" → "Ã—"). All PDF text must go through these.
func (d *rpt) cellT(w, h float64, s string) { fp := d.pdf; fp.Cell(w, h, d.tr(s)) }
func (d *rpt) mcellT(w, h float64, s, border, align string, fill bool) {
	fp := d.pdf
	fp.MultiCell(w, h, d.tr(s), border, align, fill)
}
func (d *rpt) cfT(w, h float64, s, border string, ln int, align string, fill bool, link int, linkStr string) {
	fp := d.pdf
	fp.CellFormat(w, h, d.tr(s), border, ln, align, fill, link, linkStr)
}

// RenderReportPDF writes an enterprise-grade assessment PDF to w from the
// engine's rich FullReport plus the raw per-technique results (which carry
// Threat Impact and Remediation). It backs both the per-run report and the
// agent-level report / audit pack — the FullReport supplies the summary,
// tactic heatmap and findings, while results drive the detailed section.
func RenderReportPDF(w io.Writer, rep *FullReport, results []models.SimulationResult) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)
	pdf.AliasNbPages("")
	d := &rpt{pdf: pdf, docTitle: rep.Summary.LastScenarioName}
	d.tr = pdf.UnicodeTranslatorFromDescriptor("") // "" → cp1252 (built-in)

	pdf.SetHeaderFunc(func() {
		if pdf.PageNo() == 1 { // no header on the cover
			return
		}
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetXY(margin, 8)
		d.cfT(contentW/2, 5, "Audspect BAS — Confidential", "", 0, "L", false, 0, "")
		title := d.docTitle
		if len(title) > 60 {
			title = title[:60] + "…"
		}
		d.cfT(contentW/2, 5, title, "", 0, "R", false, 0, "")
		d.draw(cLine)
		pdf.SetLineWidth(0.2)
		pdf.Line(margin, 14, pageW-margin, 14)
	})
	pdf.SetFooterFunc(func() {
		if pdf.PageNo() == 1 {
			return
		}
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetY(-14)
		d.cfT(contentW/2, 6, "Audspect Breach & Attack Simulation", "", 0, "L", false, 0, "")
		d.cfT(contentW/2, 6, fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	d.coverPage(rep)

	pdf.AddPage()
	d.executiveSummary(rep)
	d.scorecard(rep)
	d.methodology(rep, results)
	d.tacticBreakdown(rep)
	d.keyFindings(rep)
	d.detailedResults(results)
	d.recommendations(rep)
	d.glossary()

	return pdf.Output(w)
}

// ── Cover page ──────────────────────────────────────────────────────────────

func (d *rpt) coverPage(rep *FullReport) {
	pdf := d.pdf
	pdf.AddPage()
	// Full-bleed navy.
	d.fill(cNavy)
	pdf.Rect(0, 0, pageW, 297, "F")
	// Accent rule near the top.
	d.fill(cAccent)
	pdf.Rect(0, 70, pageW, 1.4, "F")

	d.text(cWhite)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetXY(margin, 30)
	d.cellT(0, 8, "AUDSPECT")
	pdf.SetFont("Helvetica", "", 9)
	d.text(cMuted)
	pdf.SetXY(margin, 38)
	d.cellT(0, 6, "Breach & Attack Simulation Platform")

	d.text(cWhite)
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetXY(margin, 90)
	d.mcellT(contentW, 13, "Adversary Simulation\nAssessment Report", "", "L", false)

	scenario := rep.Summary.LastScenarioName
	if scenario == "" {
		scenario = "Scenario Run"
	}
	pdf.SetFont("Helvetica", "", 13)
	d.text(rgb{180, 195, 215})
	pdf.SetXY(margin, 128)
	d.mcellT(contentW, 7, scenario, "", "L", false)

	// Classification banner.
	cls := rep.Summary.Classification
	cc := d.classColor(cls)
	pdf.SetXY(margin, 150)
	d.fill(cc)
	pdf.RoundedRect(margin, 150, 70, 11, 2, "1234", "F")
	d.text(cWhite)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetXY(margin+4, 152)
	d.cellT(62, 7, "RISK: "+strings.ToUpper(emptyDash(cls)))

	// Metadata block near the bottom.
	rows := [][2]string{
		{"Prepared for", emptyDash(rep.Agent.Hostname)},
		{"Endpoint", emptyDash(rep.Agent.OSVersion)},
		{"Environment", emptyDash(rep.Agent.EnvLabel)},
		{"Assessment date", rep.Summary.LastRunAt.UTC().Format("02 January 2006, 15:04 UTC")},
		{"Report generated", rep.GeneratedAt.UTC().Format("02 January 2006, 15:04 UTC")},
		{"Run reference", runRef(rep)},
	}
	y := 210.0
	for _, r := range rows {
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetXY(margin, y)
		d.cellT(45, 6, r[0])
		d.text(cWhite)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetXY(margin+45, y)
		d.cellT(contentW-45, 6, r[1])
		y += 8
	}

	// Confidential strip at the very bottom.
	d.fill(cAccent)
	pdf.Rect(0, 285, pageW, 12, "F")
	d.text(cWhite)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetXY(margin, 288)
	d.cellT(contentW, 6, "CONFIDENTIAL — Contains sensitive security assessment findings. Distribute on a need-to-know basis only.")
}

// ── Section primitives ──────────────────────────────────────────────────────

func (d *rpt) sectionTitle(n int, title string) {
	pdf := d.pdf
	d.ensure(16)
	y := pdf.GetY() + 2
	d.fill(cAccent)
	pdf.Rect(margin, y, 3, 7, "F")
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetXY(margin+5, y-0.5)
	d.cellT(contentW-5, 8, fmt.Sprintf("%d.  %s", n, title))
	pdf.SetY(y + 10)
	d.draw(cLine)
	pdf.SetLineWidth(0.2)
	pdf.Line(margin, pdf.GetY()-1, pageW-margin, pdf.GetY()-1)
	pdf.SetY(pdf.GetY() + 2)
}

func (d *rpt) body(s string) {
	d.text(cInk)
	d.pdf.SetFont("Helvetica", "", 9.5)
	d.pdf.SetX(margin)
	d.mcellT(contentW, 5, s, "", "L", false)
	d.pdf.Ln(1)
}

// ensure adds a page break if less than h mm remains before the bottom margin.
func (d *rpt) ensure(h float64) {
	if d.pdf.GetY()+h > 277 {
		d.pdf.AddPage()
	}
}

// ── 1. Executive summary ────────────────────────────────────────────────────

func (d *rpt) executiveSummary(rep *FullReport) {
	d.sectionTitle(1, "Executive Summary")
	d.body(d.narrative(rep))

	// Highlight callout for posture.
	s := rep.Summary
	d.ensure(20)
	y := d.pdf.GetY() + 1
	cc := d.classColor(s.Classification)
	d.fill(rgb{246, 248, 251})
	d.draw(cLine)
	d.pdf.SetLineWidth(0.2)
	d.pdf.RoundedRect(margin, y, contentW, 16, 2, "1234", "FD")
	d.fill(cc)
	d.pdf.Rect(margin, y, 3, 16, "F")
	d.text(cNavy)
	d.pdf.SetFont("Helvetica", "B", 10)
	d.pdf.SetXY(margin+6, y+2.5)
	d.cellT(contentW-10, 5, fmt.Sprintf("Overall posture: %s  (risk score %d / 100, %s)",
		emptyDash(s.Classification), s.RiskScore, s.Trend))
	d.text(cMuted)
	d.pdf.SetFont("Helvetica", "", 8.5)
	d.pdf.SetXY(margin+6, y+8.5)
	d.cellT(contentW-10, 5, fmt.Sprintf("%d techniques · %d prevented · %d succeeded · %d errored · %d skipped · %d critical/high finding(s)",
		s.TotalTechniques, s.PassedTechniques, s.FailedTechniques, s.ErroredTechniques, s.SkippedTechniques, len(s.CriticalFailures)))
	d.pdf.SetY(y + 20)
}

func (d *rpt) narrative(rep *FullReport) string {
	s := rep.Summary
	host := emptyDash(rep.Agent.Hostname)
	when := s.LastRunAt.UTC().Format("02 January 2006")
	var b strings.Builder
	fmt.Fprintf(&b, "This report presents the results of an automated breach & attack simulation executed against %s", host)
	if rep.Agent.OSVersion != "" {
		fmt.Fprintf(&b, " (%s)", rep.Agent.OSVersion)
	}
	fmt.Fprintf(&b, " on %s. The assessment ran %d MITRE ATT&CK-aligned techniques to measure how effectively the endpoint's security controls prevent real adversary behaviour.\n\n", when, s.TotalTechniques)

	prevented := s.PassedTechniques
	succeeded := s.FailedTechniques
	fmt.Fprintf(&b, "Of the techniques executed, %d were prevented or blocked by a security control and %d executed successfully without being stopped. This yields a prevention effectiveness of %.0f%% and an overall risk classification of %s (risk score %d/100).",
		prevented, succeeded, s.PreventionScore, emptyDash(s.Classification), s.RiskScore)

	if s.KillChainAmplifier >= 1.3 {
		fmt.Fprintf(&b, " Consecutive failures across adjacent kill-chain phases amplified exposure by %.1f×, indicating an attacker could chain multiple steps with limited resistance.", s.KillChainAmplifier)
	}
	if s.ErroredTechniques > 0 || s.SkippedTechniques > 0 {
		fmt.Fprintf(&b, " A further %d technique(s) could not be evaluated (execution errors — malformed test content, timeouts, missing prerequisites or scheduler contention) and %d were skipped; both are excluded from the prevention and exposure scores so they neither inflate nor deflate the result.",
			s.ErroredTechniques, s.SkippedTechniques)
	}
	b.WriteString("\n\n")

	if len(s.CriticalFailures) > 0 {
		fmt.Fprintf(&b, "%d critical or high-severity technique(s) were not prevented and require prioritised remediation (see Key Findings). ", len(s.CriticalFailures))
	} else {
		b.WriteString("No critical or high-severity techniques went unprevented during this run. ")
	}
	fmt.Fprintf(&b, "Testing exercised %.0f%% of the ATT&CK enterprise kill chain; broadening scenario coverage in future runs will increase assurance. Prioritised recommendations are provided in section 7.",
		s.KillChainCoverage)
	return b.String()
}

// ── 2. Scorecard ────────────────────────────────────────────────────────────

func (d *rpt) scorecard(rep *FullReport) {
	d.sectionTitle(2, "Assessment Scorecard")
	s := rep.Summary
	type card struct {
		label, value, note string
		col                rgb
	}
	cards := []card{
		{"Prevention", fmt.Sprintf("%.0f%%", s.PreventionScore), "techniques blocked (higher is better)", d.gradeHigh(s.PreventionScore)},
		{"Exposure", fmt.Sprintf("%.0f", s.ExposureScore), "weighted fail rate (lower is better)", d.gradeLow(s.ExposureScore)},
		{"Tactic Coverage", fmt.Sprintf("%.0f%%", s.KillChainCoverage), "breadth — of 14 ATT&CK tactics", cAccent},
		{"Defense Rate", fmt.Sprintf("%.0f%%", s.CoverageScore), "tactics with zero failures", d.gradeHigh(s.CoverageScore)},
	}
	d.ensure(30)
	y := d.pdf.GetY()
	cw := (contentW - 3*4) / 4 // 4 cards, 4mm gaps
	for i, c := range cards {
		x := margin + float64(i)*(cw+4)
		d.fill(rgb{246, 248, 251})
		d.draw(cLine)
		d.pdf.SetLineWidth(0.2)
		d.pdf.RoundedRect(x, y, cw, 26, 2, "1234", "FD")
		d.fill(c.col)
		d.pdf.Rect(x, y, cw, 1.4, "F")
		d.text(cMuted)
		d.pdf.SetFont("Helvetica", "B", 7)
		d.pdf.SetXY(x+3, y+3)
		d.cellT(cw-6, 4, strings.ToUpper(c.label))
		d.text(c.col)
		d.pdf.SetFont("Helvetica", "B", 17)
		d.pdf.SetXY(x+3, y+8)
		d.cellT(cw-6, 9, c.value)
		d.text(cMuted)
		d.pdf.SetFont("Helvetica", "", 6.5)
		d.pdf.SetXY(x+3, y+18)
		d.mcellT(cw-5, 3, c.note, "", "L", false)
	}
	d.pdf.SetY(y + 30)
}

// ── 3. Methodology & scope ──────────────────────────────────────────────────

func (d *rpt) methodology(rep *FullReport, results []models.SimulationResult) {
	d.sectionTitle(3, "Methodology & Scope")
	frameworks := map[string]bool{}
	for _, r := range results {
		if r.Framework != "" {
			frameworks[r.Framework] = true
		}
	}
	fwNames := map[string]string{"art": "Atomic Red Team", "caldera": "MITRE Caldera", "custom": "Custom checks", "sigma": "Sigma"}
	var fws []string
	for f := range frameworks {
		if n, ok := fwNames[f]; ok {
			fws = append(fws, n)
		} else {
			fws = append(fws, f)
		}
	}
	sort.Strings(fws)
	if len(fws) == 0 {
		fws = []string{"MITRE ATT&CK techniques"}
	}

	rows := [][2]string{
		{"Framework", "MITRE ATT&CK (Enterprise)"},
		{"Engines", strings.Join(fws, ", ")},
		{"Target endpoint", emptyDash(rep.Agent.Hostname) + " — " + emptyDash(rep.Agent.OSVersion)},
		{"Environment", emptyDash(rep.Agent.EnvLabel)},
		{"Techniques executed", fmt.Sprintf("%d", rep.Summary.TotalTechniques)},
		{"Tactics exercised", fmt.Sprintf("%d of 14 ATT&CK tactics", len(rep.TacticHeatmap))},
		{"Window", rep.Summary.LastRunAt.UTC().Format("02 Jan 2006 15:04 UTC")},
	}
	d.keyValueTable(rows)
	d.body("Each technique is scored as PASS when a security control prevented or blocked it, FAIL when it executed without being stopped, ERROR when the test itself could not execute correctly (malformed content, timeout, missing prerequisite, scheduler contention), or SKIPPED when it was not run. Only PASS and FAIL count toward the score: a FAIL is a finding — the simulated adversary behaviour succeeded against this endpoint — while ERROR and SKIPPED are excluded because they reflect a test-execution problem, not the endpoint's defences.")
}

func (d *rpt) keyValueTable(rows [][2]string) {
	pdf := d.pdf
	for _, r := range rows {
		d.ensure(8)
		y := pdf.GetY()
		d.text(cMuted)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetXY(margin, y)
		d.cellT(45, 6, r[0])
		d.text(cInk)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetX(margin + 45)
		d.mcellT(contentW-45, 6, r[1], "", "L", false)
		d.draw(rgb{235, 239, 244})
		pdf.SetLineWidth(0.15)
		pdf.Line(margin, pdf.GetY(), pageW-margin, pdf.GetY())
		pdf.SetY(pdf.GetY() + 1.5)
	}
	pdf.Ln(1)
}

// ── 4. Tactic breakdown ─────────────────────────────────────────────────────

func (d *rpt) tacticBreakdown(rep *FullReport) {
	d.sectionTitle(4, "ATT&CK Tactic Breakdown")
	if len(rep.TacticHeatmap) == 0 {
		d.body("No tactic-level results were recorded for this run.")
		return
	}
	pdf := d.pdf
	for _, t := range rep.TacticHeatmap {
		d.ensure(11)
		y := pdf.GetY()
		d.text(cInk)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetXY(margin, y)
		d.cellT(55, 5, capTactic(t.Tactic))
		// Bar track.
		barX, barW := margin+58, 86.0
		d.fill(rgb{233, 237, 242})
		pdf.RoundedRect(barX, y+0.6, barW, 3.6, 1, "1234", "F")
		pct := t.PassPct
		col := d.gradeHigh(float64(pct))
		if t.Passed+t.Failed == 0 {
			col = cMuted
		}
		d.fill(col)
		fillW := barW * float64(pct) / 100
		if fillW < 1 && pct > 0 {
			fillW = 1
		}
		if fillW > 0 {
			pdf.RoundedRect(barX, y+0.6, fillW, 3.6, 1, "1234", "F")
		}
		d.text(col)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetXY(barX+barW+3, y)
		d.cellT(14, 5, fmt.Sprintf("%d%%", pct))
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetXY(barX+barW+18, y)
		d.cellT(0, 5, fmt.Sprintf("%d pass · %d fail", t.Passed, t.Failed))
		pdf.SetY(y + 7)
	}
	pdf.Ln(1)
}

// ── 5. Key findings ─────────────────────────────────────────────────────────

func (d *rpt) keyFindings(rep *FullReport) {
	d.sectionTitle(5, "Key Findings")
	if len(rep.TopFindings) == 0 {
		d.body("No critical or high-severity findings were identified in this run. Continue periodic testing to maintain assurance.")
		return
	}
	for i, f := range rep.TopFindings {
		d.finding(i+1, f)
	}
}

func (d *rpt) finding(n int, f Finding) {
	pdf := d.pdf
	d.ensure(26)
	sc := d.sevColor(f.Severity)
	yStart := pdf.GetY()
	// Title line with severity chip.
	d.chip(margin, yStart, strings.ToUpper(emptyDash(f.Severity)), sc)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetXY(margin+24, yStart-0.3)
	title := fmt.Sprintf("F-%02d  %s — %s", n, emptyDash(f.TechniqueID), emptyDash(f.TechniqueName))
	d.mcellT(contentW-24, 5, title, "", "L", false)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetX(margin + 24)
	d.cellT(0, 4, capTactic(f.Tactic))
	pdf.Ln(5)

	if f.Details != "" {
		d.labelled("What happened", f.Details)
	}
	if f.Remediation != "" {
		d.labelled("Remediation", f.Remediation)
	}
	// Accent left bar spanning the block (same page only).
	yEnd := pdf.GetY()
	if yEnd > yStart {
		d.fill(sc)
		pdf.Rect(margin-2.5, yStart, 1.2, yEnd-yStart-1, "F")
	}
	d.separator()
}

// ── 6. Detailed results ─────────────────────────────────────────────────────

func (d *rpt) detailedResults(results []models.SimulationResult) {
	d.sectionTitle(6, "Detailed Technique Results")
	executed := 0
	for _, r := range results {
		if r.Result == models.ResultSkipped {
			continue
		}
		executed++
		d.resultBlock(r)
	}
	if executed == 0 {
		d.body("No techniques were executed in this run.")
	}
}

func (d *rpt) resultBlock(r models.SimulationResult) {
	pdf := d.pdf
	d.ensure(18)
	rc := d.resultColor(r.Result)
	yStart := pdf.GetY()
	d.chip(margin, yStart, strings.ToUpper(string(r.Result)), rc)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetXY(margin+22, yStart-0.3)
	name := emptyDash(r.Technique.Name)
	head := fmt.Sprintf("%s — %s", emptyDash(r.Technique.ID), name)
	d.mcellT(contentW-22, 4.6, head, "", "L", false)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetX(margin + 22)
	meta := capTactic(r.Technique.Tactic)
	if r.Severity != "" {
		meta += "  ·  " + r.Severity
	}
	meta += "  ·  " + testKind(r.Framework)
	d.cellT(0, 4, meta)
	pdf.Ln(5)

	if r.Details != "" {
		d.labelled("Details", r.Details)
	}
	if r.ThreatImpact != "" {
		d.labelled("Threat impact", r.ThreatImpact)
	}
	if r.Remediation != "" {
		d.labelled("Remediation", r.Remediation)
	}
	yEnd := pdf.GetY()
	if yEnd > yStart {
		d.fill(rc)
		pdf.Rect(margin-2.5, yStart, 1.2, yEnd-yStart-1, "F")
	}
	d.separator()
}

// labelled renders an indented "Label: value" block with a wrapped value.
func (d *rpt) labelled(label, value string) {
	pdf := d.pdf
	d.ensure(8)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "B", 7.5)
	pdf.SetX(margin + 4)
	d.cellT(24, 4.4, label)
	d.text(cInk)
	pdf.SetFont("Helvetica", "", 8.5)
	pdf.SetX(margin + 28)
	d.mcellT(contentW-28, 4.4, value, "", "L", false)
}

// ── 7. Recommendations ──────────────────────────────────────────────────────

func (d *rpt) recommendations(rep *FullReport) {
	d.sectionTitle(7, "Prioritised Recommendations")
	recs := rep.Summary.Recommendations
	if len(recs) == 0 {
		d.body("Maintain the current security posture and schedule the next assessment within 30 days.")
		return
	}
	pdf := d.pdf
	for i, rec := range recs {
		d.ensure(12)
		y := pdf.GetY()
		d.fill(cAccent)
		pdf.RoundedRect(margin, y+0.4, 5, 5, 1, "1234", "F")
		d.text(cWhite)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetXY(margin, y+0.4)
		d.cfT(5, 5, fmt.Sprintf("%d", i+1), "", 0, "C", false, 0, "")
		d.text(cInk)
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetX(margin + 8)
		d.mcellT(contentW-8, 4.8, rec, "", "L", false)
		pdf.SetY(pdf.GetY() + 2)
	}
}

// ── 8. Glossary ─────────────────────────────────────────────────────────────

func (d *rpt) glossary() {
	d.sectionTitle(8, "Appendix — Metric Definitions")
	defs := [][2]string{
		{"PASS", "A security control prevented or blocked the simulated technique. More passes is better."},
		{"FAIL", "The technique executed successfully without being stopped — a finding requiring attention."},
		{"ERROR", "The test could not execute correctly (malformed content, timeout, missing prerequisite, scheduler contention). A BAS execution problem, not a security outcome — excluded from scoring."},
		{"SKIPPED", "The technique was deliberately not run (e.g. external payload not shipped) and was excluded from scoring."},
		{"Policy Configuration Check", "A passive audit that inspects a security setting (registry key, policy, service state) without running an attack — it confirms whether a control is correctly configured."},
		{"Active Adversary Behavioral Test", "An ART or Caldera test that actually executes the technique on the endpoint — it confirms whether deployed controls stop a live attack, not just whether they are configured."},
		{"Prevention", "Severity-weighted percentage of techniques that were prevented. Higher is better."},
		{"Exposure", "Tactic-weighted failure rate, amplified by consecutive kill-chain failures. Lower is better."},
		{"Tactic Coverage", "Breadth of testing: how many of the 14 MITRE ATT&CK Enterprise tactics this run exercised."},
		{"Defense Rate", "Share of tested tactics in which every technique was blocked (zero failures)."},
		{"Kill-chain amplifier", "Multiplier (1.0–2.5×) reflecting consecutive unprevented kill-chain phases."},
		{"Risk classification", "Overall posture band derived from the amplified exposure score."},
	}
	d.keyValueTable(defs)
}

// ── small helpers ───────────────────────────────────────────────────────────

func (d *rpt) chip(x, y float64, label string, c rgb) {
	pdf := d.pdf
	w := pdf.GetStringWidth(label) + 4
	if w < 18 {
		w = 18
	}
	d.fill(d.tint(c))
	pdf.RoundedRect(x, y, w, 4.6, 1, "1234", "F")
	d.text(c)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetXY(x, y+0.2)
	d.cfT(w, 4.2, label, "", 0, "C", false, 0, "")
}

func (d *rpt) separator() {
	pdf := d.pdf
	pdf.SetY(pdf.GetY() + 1)
	d.draw(rgb{233, 237, 242})
	pdf.SetLineWidth(0.15)
	pdf.Line(margin, pdf.GetY(), pageW-margin, pdf.GetY())
	pdf.SetY(pdf.GetY() + 2.5)
}

// tint returns a light wash of a status colour for chip backgrounds.
func (d *rpt) tint(c rgb) rgb {
	mix := func(v int) int { return v + (255-v)*82/100 }
	return rgb{mix(c.r), mix(c.g), mix(c.b)}
}

func (d *rpt) classColor(cls string) rgb {
	switch strings.ToLower(cls) {
	case "protected", "low risk":
		return cSuccess
	case "medium risk":
		return cWarning
	case "high risk", "critical":
		return cDanger
	default:
		return cMuted
	}
}

func (d *rpt) sevColor(sev string) rgb {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return cDanger
	case "medium":
		return cWarning
	default:
		return cMuted
	}
}

func (d *rpt) resultColor(res models.CheckResult) rgb {
	switch res {
	case models.ResultPass, models.ResultBlocked:
		return cSuccess
	case models.ResultFail:
		return cDanger
	case models.ResultError:
		return cWarning // amber: a BAS execution problem, not a security finding
	default:
		return cMuted
	}
}

// gradeHigh colours a higher-is-better score; gradeLow a lower-is-better one.
func (d *rpt) gradeHigh(v float64) rgb {
	switch {
	case v >= 80:
		return cSuccess
	case v >= 50:
		return cWarning
	default:
		return cDanger
	}
}

func (d *rpt) gradeLow(v float64) rgb {
	switch {
	case v <= 20:
		return cSuccess
	case v <= 50:
		return cWarning
	default:
		return cDanger
	}
}

func capTactic(t string) string {
	if t == "" {
		return "Uncategorised"
	}
	parts := strings.Split(t, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// testKind labels how a result was obtained so the report does not present a
// passive configuration audit (e.g. "is WDigest disabled?") and an active
// exploit (e.g. dumping LSASS) as the same kind of evidence. ART and Caldera
// actually execute the technique on the endpoint; everything else (custom
// posture checks, sigma) inspects configuration without running an attack.
func testKind(framework string) string {
	switch strings.ToLower(strings.TrimSpace(framework)) {
	case "art", "caldera":
		return "Active Adversary Behavioral Test"
	default:
		return "Policy Configuration Check"
	}
}

func runRef(rep *FullReport) string {
	if len(rep.Runs) > 0 && len(rep.Runs[0].ID) >= 8 {
		return rep.Runs[0].ID[:8]
	}
	if len(rep.Runs) > 0 {
		return rep.Runs[0].ID
	}
	return "—"
}
