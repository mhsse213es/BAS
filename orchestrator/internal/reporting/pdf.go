package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	fpdf "github.com/go-pdf/fpdf"

	"github.com/audspect/bas/internal/attackpath"
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
	cSuccess = rgb{13, 148, 136} // teal (brand "good/prevented")
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
	d.campaignBreakdown(rep)
	d.methodology(rep, results)
	d.tacticBreakdown(rep)
	d.keyFindings(rep)
	d.detailedResults(results)
	d.changesAndCleanup(rep)
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

	// Metadata block near the bottom — campaign scope when fleet-wide, else agent.
	var rows [][2]string
	if rep.Scope != nil {
		rows = [][2]string{
			{"Campaign", emptyDash(rep.Scope.Title)},
			{"Scenario", emptyDash(rep.Scope.Scenario)},
			{"Endpoints", fmt.Sprintf("%d agent(s) · %d run(s)", rep.Scope.AgentCount, rep.Scope.RunCount)},
			{"Assessment date", rep.Summary.LastRunAt.UTC().Format("02 January 2006, 15:04 UTC")},
			{"Report generated", rep.GeneratedAt.UTC().Format("02 January 2006, 15:04 UTC")},
		}
	} else {
		rows = [][2]string{
			{"Prepared for", emptyDash(rep.Agent.Hostname)},
			{"Endpoint", emptyDash(rep.Agent.OSVersion)},
			{"Environment", emptyDash(rep.Agent.EnvLabel)},
			{"Assessment date", rep.Summary.LastRunAt.UTC().Format("02 January 2006, 15:04 UTC")},
			{"Report generated", rep.GeneratedAt.UTC().Format("02 January 2006, 15:04 UTC")},
			{"Run reference", runRef(rep)},
		}
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
	d.productionBanner(rep)
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

	d.trendBlock(rep.TrendAnalysis)
	d.preventionDetection(rep.Detection)
	d.objectiveRisks(rep.ObjectiveRisks)
}

// trendBlock answers the question a BAS is bought to answer — "are we improving?"
// — by comparing this run's prevention effectiveness to the previous scored
// assessment and showing a short history. With no prior run it says so plainly
// rather than inventing a baseline.
func (d *rpt) trendBlock(t TrendSummary) {
	pdf := d.pdf
	d.ensure(16)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Trend vs Previous Assessment")
	pdf.Ln(5.4)

	if !t.HasPrevious {
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetX(margin)
		d.mcellT(contentW, 4.4, "This is the first scored assessment for this endpoint — a prevention trend will appear once a second assessment completes.", "", "L", false)
		pdf.Ln(1.5)
		return
	}

	delta := t.DeltaPrevention
	dir, col := "improved", cSuccess
	switch {
	case delta < 0:
		dir, col = "declined", cDanger
	case delta == 0:
		dir, col = "unchanged", cMuted
	}
	d.text(cInk)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetX(margin)
	d.mcellT(contentW, 4.6, fmt.Sprintf("Prevention effectiveness is %.0f%% this run versus %.0f%% in the previous assessment.",
		t.CurrentPrevention, t.PreviousPrevention), "", "L", false)
	yy := pdf.GetY()
	d.chip(margin+2, yy, fmt.Sprintf("%s %+.0f PTS", strings.ToUpper(dir), delta), col)
	pdf.Ln(7)

	if len(t.History) >= 2 {
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetX(margin)
		d.cellT(0, 4, fmt.Sprintf("Prevention over the last %d assessments (oldest to newest):", len(t.History)))
		pdf.Ln(4.6)
		for _, p := range t.History {
			d.ensure(6)
			y := pdf.GetY()
			d.text(cMuted)
			pdf.SetFont("Helvetica", "", 7.5)
			pdf.SetXY(margin+2, y)
			d.cellT(28, 4.4, p.Date.UTC().Format("02 Jan 2006"))
			barX, barW := margin+34, 80.0
			d.fill(rgb{233, 237, 242})
			pdf.RoundedRect(barX, y+0.6, barW, 3.4, 1, "1234", "F")
			d.fill(d.gradeHigh(p.PreventionScore))
			fw := barW * p.PreventionScore / 100
			if fw < 1 && p.PreventionScore > 0 {
				fw = 1
			}
			if fw > 0 {
				pdf.RoundedRect(barX, y+0.6, fw, 3.4, 1, "1234", "F")
			}
			d.text(cMuted)
			pdf.SetFont("Helvetica", "B", 7.5)
			pdf.SetXY(barX+barW+3, y)
			d.cellT(0, 4.4, fmt.Sprintf("%.0f%%", p.PreventionScore))
			pdf.SetY(y + 5)
		}
	}
	pdf.Ln(1)
}

// preventionDetection reframes the raw FAIL count as the defence-in-depth matrix
// a BAS buyer reads: of the techniques prevention did not stop, how many were
// still detected (a SOC would see them) versus executed completely unseen.
func (d *rpt) preventionDetection(s DetectionSummary) {
	if s.ExecutedUnprevented == 0 {
		return
	}
	pdf := d.pdf
	d.ensure(20)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Prevention & Detection")
	pdf.Ln(5.4)
	d.text(cInk)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetX(margin)
	d.mcellT(contentW, 4.6, fmt.Sprintf("%d technique(s) executed without being prevented. A FAIL means a prevention control "+
		"did not stop execution — not that the attacker's end objective was independently verified. "+
		"Of those that executed:", s.ExecutedUnprevented), "", "L", false)
	pdf.Ln(1)
	// Honest caveat: with zero telemetry for the whole run, detection was not
	// measurable — do NOT present the FAILs as having "evaded" the SOC.
	if !s.TelemetryObserved {
		d.text(cDanger)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetX(margin)
		d.mcellT(contentW, 4.4, "Detection results unavailable: no host telemetry was collected during this run.", "", "L", false)
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetX(margin)
		d.mcellT(contentW, 4.2, "This is a measurement gap, not proof the techniques evaded detection. Confirm the agent build collects "+
			"event-log telemetry and that Microsoft Defender (or Sysmon) is enabled on the endpoint, then re-run. The figures below "+
			"reflect prevention only; the detection split cannot be trusted until telemetry is collected.", "", "L", false)
		pdf.Ln(1.5)
	}
	undetectedNote := "no telemetry observed — executed unseen (worst case)"
	if !s.TelemetryObserved {
		undetectedNote = "detection not measured — no telemetry collected this run (see caveat above)"
	}
	rows := []struct {
		label, note string
		val         int
		col         rgb
	}{
		{"Detected", "an alert fired (Microsoft Defender) — a SOC would see this", s.Detected, cWarning},
		{"Logged only", "telemetry exists but no alert was raised", s.LoggedOnly, cAccent},
		{"Undetected", undetectedNote, s.Undetected, cDanger},
	}
	for _, rrow := range rows {
		d.ensure(6)
		yy := pdf.GetY()
		d.chip(margin+2, yy, fmt.Sprintf("%d", rrow.val), rrow.col)
		d.text(cNavy)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetXY(margin+18, yy+0.4)
		d.cellT(28, 5, rrow.label)
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetXY(margin+48, yy+0.7)
		d.cellT(0, 5, rrow.note)
		pdf.Ln(6)
	}
	pdf.Ln(1)
}

// objectiveRisks renders the run in business terms an executive reads first
// (Credential Theft, Privilege Escalation, …) with a colour-coded risk band per
// objective, instead of leaving them to infer risk from raw percentages.
func (d *rpt) objectiveRisks(risks []ObjectiveRisk) {
	if len(risks) == 0 {
		return
	}
	pdf := d.pdf
	d.ensure(16)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Business-Objective Risk")
	pdf.Ln(5.4)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetX(margin)
	d.mcellT(contentW, 4.2, "What an attacker could achieve against this endpoint, by objective — derived from the tested techniques in each area (execution errors excluded).", "", "L", false)
	pdf.Ln(1.5)
	for _, o := range risks {
		d.ensure(7)
		yy := pdf.GetY()
		d.text(cInk)
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetXY(margin+2, yy)
		d.cellT(64, 5, o.Objective)
		d.chip(margin+66, yy, strings.ToUpper(o.Risk)+" RISK", d.riskColor(o.Risk))
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetXY(margin+112, yy+0.7)
		d.cellT(0, 5, fmt.Sprintf("%d of %d technique(s) unprevented", o.Failed, o.Tested))
		pdf.Ln(6)
	}
	pdf.Ln(1)
}

func (d *rpt) riskColor(band string) rgb {
	switch band {
	case "High":
		return cDanger
	case "Medium":
		return cWarning
	default:
		return cSuccess
	}
}

// isProductionEnv reports whether the endpoint's environment label marks it as a
// production system (where running live adversary techniques carries real risk).
func isProductionEnv(label string) bool {
	return strings.Contains(strings.ToLower(label), "prod")
}

// productionBanner warns the reader, up front, that live techniques ran against a
// production endpoint and points to the cleanup section.
func (d *rpt) productionBanner(rep *FullReport) {
	if !isProductionEnv(rep.Agent.EnvLabel) {
		return
	}
	pdf := d.pdf
	d.ensure(16)
	y := pdf.GetY() + 1
	d.fill(rgb{253, 246, 246})
	d.draw(cDanger)
	pdf.SetLineWidth(0.2)
	pdf.RoundedRect(margin, y, contentW, 13, 2, "1234", "FD")
	d.fill(cDanger)
	pdf.Rect(margin, y, 3, 13, "F")
	d.text(cDanger)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetXY(margin+6, y+2)
	d.cellT(contentW-10, 5, "PRODUCTION ENVIRONMENT")
	d.text(cInk)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(margin+6, y+6.5)
	d.mcellT(contentW-10, 4, "This assessment executed live adversary techniques against a production endpoint. Endpoint changes were reverted where the snapshot system captured them — see section 7 (Changes & Cleanup Verification).", "", "L", false)
	pdf.SetY(y + 16)
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
	fmt.Fprintf(&b, "Testing exercised %d of the 14 MITRE ATT&CK Enterprise tactics across %d technique(s) — this is the breadth of THIS run, not a measure of overall MITRE ATT&CK coverage. Broadening scenario coverage in future runs will increase assurance. Prioritised recommendations are provided in section 8.",
		len(rep.TacticHeatmap), s.TotalTechniques)
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
	// Cymulate-priority headline cards: Prevention · Detection · Exposure · Penetration.
	detVal, detNote, detCol := "N/A", "no telemetry — not measurable", cMuted
	if s.DetectionMeasured {
		detVal = fmt.Sprintf("%.0f%%", s.DetectionScore)
		detNote = "alerts on unprevented techniques"
		detCol = d.gradeHigh(s.DetectionScore)
	}
	cards := []card{
		{"Prevention", fmt.Sprintf("%.0f%%", s.PreventionScore), "techniques blocked (higher is better)", d.gradeHigh(s.PreventionScore)},
		{"Detection", detVal, detNote, detCol},
		{"Exposure", emptyDash(s.ExposureLevel), "posture band (lower is better)", d.exposureColor(s.ExposureLevel)},
		{"Penetration", fmt.Sprintf("%d / %d", s.PenetrationFailed, s.PenetrationTested), fmt.Sprintf("%d%% of executed got through", s.PenetrationPct), d.gradeLow(float64(s.PenetrationPct))},
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

	// Secondary metrics + result confidence on one compact line.
	s2 := rep.Summary
	d.text(cMuted)
	d.pdf.SetFont("Helvetica", "", 8)
	d.pdf.SetX(margin)
	d.cellT(0, 5, fmt.Sprintf("Tactic breadth: %d / 14   ·   Defense rate: %.0f%%   ·   Mean time-to-detect: %s   ·   Result confidence: %s (%d valid of %d attempted, %d errored)",
		len(rep.TacticHeatmap), s2.CoverageScore, fmtMTTD(s2.MTTDMs), emptyDash(rep.Reliability.Confidence),
		rep.Reliability.Valid, rep.Reliability.Attempted, rep.Reliability.Errored))
	d.pdf.Ln(7)

	// Attack Surface Age Callout
	d.ensure(18)
	{
		y := d.pdf.GetY()
		slaCol := cSuccess
		if rep.AttackSurfaceSLAStatus == "critical-sla" {
			slaCol = cDanger
		} else if rep.AttackSurfaceSLAStatus == "over-sla" {
			slaCol = cWarning
		}
		d.fill(rgb{246, 248, 251})
		d.draw(cLine)
		d.pdf.SetLineWidth(0.2)
		d.pdf.RoundedRect(margin, y, contentW, 14, 2, "1234", "FD")
		d.fill(slaCol)
		d.pdf.Rect(margin, y, 3, 14, "F")

		d.text(cNavy)
		d.pdf.SetFont("Helvetica", "B", 9)
		d.pdf.SetXY(margin+5, y+2)
		d.cellT(80, 5, fmt.Sprintf("Attack Surface Age: Exposed weakness present for %d days", rep.AttackSurfaceAge))

		d.text(cMuted)
		d.pdf.SetFont("Helvetica", "", 8)
		d.pdf.SetXY(margin+85, y+2.5)
		if rep.OldestFindingID != "" {
			d.cellT(contentW-85, 5, fmt.Sprintf("Oldest weakness: %s (%s) · Status: %s", rep.OldestFindingID, rep.OldestFindingName, strings.ToUpper(rep.AttackSurfaceSLAStatus)))
		} else {
			d.cellT(contentW-85, 5, "No open weaknesses detected on this agent.")
		}
		d.pdf.SetY(y + 16)
	}

	// Endpoint Stability Check Callout — only when perf telemetry was captured.
	if rep.PerfCPUBefore != 0 {
		d.ensure(18)
		y := d.pdf.GetY()
		d.fill(rgb{246, 248, 251})
		d.draw(cLine)
		d.pdf.SetLineWidth(0.2)
		d.pdf.RoundedRect(margin, y, contentW, 14, 2, "1234", "FD")
		d.fill(cSuccess)
		d.pdf.Rect(margin, y, 3, 14, "F")

		d.text(cNavy)
		d.pdf.SetFont("Helvetica", "B", 9)
		d.pdf.SetXY(margin+5, y+2)
		d.cellT(100, 5, "Endpoint Stability Check — Health Impact: Negligible")

		d.text(cMuted)
		d.pdf.SetFont("Helvetica", "", 7.5)
		d.pdf.SetXY(margin+5, y+7.5)
		d.cellT(contentW-10, 5, fmt.Sprintf("Before Running: CPU: %.1f%% · RAM: %.1f GB · Disk: %.1f%%   |   After Running: CPU: %.1f%% · RAM: %.1f GB · Disk: %.1f%%",
			rep.PerfCPUBefore, rep.PerfRAMBefore, rep.PerfDiskBefore,
			rep.PerfCPUAfter, rep.PerfRAMAfter, rep.PerfDiskAfter))
		d.pdf.SetY(y + 18)
	}

	// Detection Source Ranking
	if len(rep.DetectionSources) > 0 {
		d.ensure(28)
		y := d.pdf.GetY()
		d.fill(rgb{246, 248, 251})
		d.draw(cLine)
		d.pdf.SetLineWidth(0.2)
		d.pdf.RoundedRect(margin, y, contentW, 24, 2, "1234", "FD")
		d.fill(cAccent)
		d.pdf.Rect(margin, y, 3, 24, "F")

		d.text(cNavy)
		d.pdf.SetFont("Helvetica", "B", 9)
		d.pdf.SetXY(margin+5, y+2)
		d.cellT(100, 5, "Detection Source Ranking")

		// Headers
		d.text(cMuted)
		d.pdf.SetFont("Helvetica", "B", 7)
		d.pdf.SetXY(margin+5, y+7)
		d.cfT(40, 4.5, "PRODUCT", "", 0, "L", false, 0, "")
		d.cfT(30, 4.5, "DETECTIONS", "", 0, "R", false, 0, "")
		d.cfT(45, 4.5, "MIN TIME-TO-DETECT", "", 0, "R", false, 0, "")
		d.cfT(45, 4.5, "AVG TIME-TO-DETECT", "", 0, "R", false, 0, "")

		// Rows (up to 3 to keep it compact)
		d.pdf.SetFont("Helvetica", "", 7.5)
		rowY := y + 11.0
		for i, ds := range rep.DetectionSources {
			if i >= 3 {
				break
			}
			d.pdf.SetXY(margin+5, rowY)
			d.text(cNavy)
			d.cfT(40, 4, fmt.Sprintf("%d. %s", i+1, ds.Product), "", 0, "L", false, 0, "")
			d.text(cSuccess)
			d.cfT(30, 4, fmt.Sprintf("%d", ds.Detections), "", 0, "R", false, 0, "")
			d.text(cInk)
			minStr := "—"
			if ds.MinMTTDMs > 0 {
				minStr = fmtMTTD(ds.MinMTTDMs)
			}
			d.cfT(45, 4, minStr, "", 0, "R", false, 0, "")
			avgStr := "—"
			if ds.AvgMTTDMs > 0 {
				avgStr = fmtMTTD(ds.AvgMTTDMs)
			}
			d.cfT(45, 4, avgStr, "", 0, "R", false, 0, "")
			rowY += 4
		}
		// If more than 3, show a brief note
		if len(rep.DetectionSources) > 3 {
			d.text(cMuted)
			d.pdf.SetFont("Helvetica", "I", 6.5)
			d.pdf.SetXY(margin+5, y+20)
			d.cellT(contentW-10, 4, fmt.Sprintf("... and %d more detection sources", len(rep.DetectionSources)-3))
		}

		d.pdf.SetY(y + 28)
	}

	d.insightsBlock(rep.Insights)
	d.controlMaturity(rep)
}

// campaignBreakdown renders the per-agent results table for a fleet-wide
// (campaign) report. No-op for single-agent reports.
func (d *rpt) campaignBreakdown(rep *FullReport) {
	if rep.Scope == nil || len(rep.CampaignAgents) == 0 {
		return
	}
	pdf := d.pdf
	d.ensure(16)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Per-Agent Breakdown")
	pdf.Ln(5.6)
	// Header row.
	d.fill(cNavy)
	d.text(cWhite)
	pdf.SetFont("Helvetica", "B", 8)
	y := pdf.GetY()
	cols := []struct {
		label string
		w     float64
	}{{"Endpoint", 70}, {"Status", 30}, {"Prevention", 28}, {"Tested", 23}, {"Failed", 23}}
	x := margin
	for _, c := range cols {
		pdf.Rect(x, y, c.w, 6, "F")
		pdf.SetXY(x+2, y+1)
		d.cellT(c.w-2, 4, c.label)
		x += c.w
	}
	pdf.SetY(y + 6)
	pdf.SetFont("Helvetica", "", 8)
	for _, a := range rep.CampaignAgents {
		d.ensure(6)
		yy := pdf.GetY()
		d.text(cInk)
		pdf.SetXY(margin+2, yy+1)
		d.cellT(68, 4, a.Hostname)
		pdf.SetXY(margin+70+2, yy+1)
		d.cellT(28, 4, a.Status)
		d.text(d.gradeHigh(a.PreventionScore))
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetXY(margin+100+2, yy+1)
		d.cellT(26, 4, fmt.Sprintf("%.0f%%", a.PreventionScore))
		pdf.SetFont("Helvetica", "", 8)
		d.text(cInk)
		pdf.SetXY(margin+128+2, yy+1)
		d.cellT(21, 4, fmt.Sprintf("%d", a.Tested))
		if a.Failed > 0 {
			d.text(cDanger)
		}
		pdf.SetXY(margin+151+2, yy+1)
		d.cellT(21, 4, fmt.Sprintf("%d", a.Failed))
		d.text(cInk)
		d.draw(cLine)
		pdf.SetLineWidth(0.1)
		pdf.Line(margin, yy+6, pageW-margin, yy+6)
		pdf.SetY(yy + 6)
	}
	pdf.Ln(3)
}

// insightsBlock renders the most/least-protected callout — the single fastest
// takeaway in the report.
func (d *rpt) insightsBlock(ins Insights) {
	if !ins.HasData || (ins.Most == nil && ins.Least == nil) {
		return
	}
	pdf := d.pdf
	d.ensure(16)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Assessment Insights")
	pdf.Ln(5.4)
	half := (contentW - 4) / 2
	y := pdf.GetY()
	if ins.Most != nil {
		d.fill(d.tint(cSuccess))
		pdf.RoundedRect(margin, y, half, 14, 2, "1234", "F")
		d.text(cSuccess)
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetXY(margin+3, y+2)
		d.cellT(half-6, 4, "MOST PROTECTED")
		d.text(cNavy)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetXY(margin+3, y+6)
		d.cellT(half-6, 5, fmt.Sprintf("%s (%d%%)", capTactic(ins.Most.Tactic), ins.Most.PassPct))
	}
	if ins.Least != nil {
		x := margin + half + 4
		d.fill(d.tint(cDanger))
		pdf.RoundedRect(x, y, half, 14, 2, "1234", "F")
		d.text(cDanger)
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetXY(x+3, y+2)
		d.cellT(half-6, 4, "LEAST PROTECTED")
		d.text(cNavy)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetXY(x+3, y+6)
		d.cellT(half-6, 5, fmt.Sprintf("%s (%d%%)", capTactic(ins.Least.Tactic), ins.Least.PassPct))
	}
	pdf.SetY(y + 16)
	if ins.TelemetryNote != "" {
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7.5)
		pdf.SetX(margin)
		d.mcellT(contentW, 3.8, ins.TelemetryNote, "", "L", false)
		pdf.Ln(1)
	}
}

// controlMaturity presents a per-category maturity score (0–10) management reads
// faster than ATT&CK IDs or raw percentages. Prevention categories are derived
// from this run's per-tactic prevention rate; the Detection category is derived
// from the detection telemetry — and is honestly shown as "not measured" when no
// telemetry was collected this run, rather than scored as zero.
func (d *rpt) controlMaturity(rep *FullReport) {
	if len(rep.TacticHeatmap) == 0 {
		return
	}
	pdf := d.pdf
	d.ensure(16)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Control Maturity by Category")
	pdf.Ln(5.2)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetX(margin)
	d.mcellT(contentW, 4, "Maturity (0–10) per control family, from this run's prevention rate — a management view of which controls held and which need investment. Derived from tested techniques only.", "", "L", false)
	pdf.Ln(1.5)

	type mrow struct {
		label string
		text  string // "8 / 10" or "not measured"
		score int    // 0..10 for the bar; <0 = not measured
		col   rgb
	}
	var rows []mrow
	for _, t := range rep.TacticHeatmap {
		sc := maturityScore(t.PassPct)
		rows = append(rows, mrow{
			label: capTactic(t.Tactic) + " Controls",
			text:  fmt.Sprintf("%d / 10", sc),
			score: sc,
			col:   d.gradeHigh(float64(t.PassPct)),
		})
	}
	// Detection controls — only scored when telemetry was actually collected.
	det := rep.Detection
	if det.TelemetryObserved && det.ExecutedUnprevented > 0 {
		seen := (det.Detected + det.LoggedOnly) * 100 / det.ExecutedUnprevented
		sc := maturityScore(seen)
		rows = append(rows, mrow{label: "Detection Controls", text: fmt.Sprintf("%d / 10", sc), score: sc, col: d.gradeHigh(float64(seen))})
	} else {
		rows = append(rows, mrow{label: "Detection Controls", text: "not measured (no telemetry)", score: -1, col: cMuted})
	}

	for _, m := range rows {
		d.ensure(7)
		y := pdf.GetY()
		d.text(cInk)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetXY(margin+2, y)
		d.cellT(60, 5, m.label)
		// Bar track (only for measured rows).
		barX, barW := margin+64, 70.0
		d.fill(rgb{233, 237, 242})
		pdf.RoundedRect(barX, y+0.6, barW, 3.6, 1, "1234", "F")
		if m.score >= 0 {
			d.fill(m.col)
			fillW := barW * float64(m.score) / 10
			if fillW < 1 && m.score > 0 {
				fillW = 1
			}
			if fillW > 0 {
				pdf.RoundedRect(barX, y+0.6, fillW, 3.6, 1, "1234", "F")
			}
		}
		d.text(m.col)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetXY(barX+barW+3, y)
		d.cellT(0, 5, m.text)
		pdf.SetY(y + 6.4)
	}
	pdf.Ln(1)
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

	secCtx := "Not reported by the agent"
	if len(rep.SecurityTools) > 0 {
		secCtx = strings.Join(rep.SecurityTools, ", ")
	}
	rows := [][2]string{
		{"Framework", "MITRE ATT&CK (Enterprise)"},
		{"Engines", strings.Join(fws, ", ")},
		{"Target endpoint", emptyDash(rep.Agent.Hostname) + " — " + emptyDash(rep.Agent.OSVersion)},
		{"Asset class", assetClass(rep.Agent.OSVersion)},
		{"Environment", emptyDash(rep.Agent.EnvLabel)},
		{"Business criticality", businessCriticality(rep.Agent.EnvLabel)},
		{"Security context", secCtx},
		{"Techniques executed", fmt.Sprintf("%d", rep.Summary.TotalTechniques)},
		{"Tactics exercised", fmt.Sprintf("%d of 14 ATT&CK tactics", len(rep.TacticHeatmap))},
		{"Window", rep.Summary.LastRunAt.UTC().Format("02 Jan 2006 15:04 UTC")},
	}
	d.keyValueTable(rows)
	if len(rep.SecurityTools) > 0 {
		d.body("Security context lists the AV/EDR products detected on the endpoint (presence only). " +
			"Detection by third-party EDR is not locally observable and is therefore never asserted in this report.")
	}
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
	d.topRiskDrivers(rep.TopRiskDrivers)
	d.attackPath(rep.AttackPath)
	if len(rep.TopFindings) == 0 {
		d.body("No critical or high-severity findings were identified in this run. Continue periodic testing to maintain assurance.")
		return
	}
	for i, f := range rep.TopFindings {
		d.finding(i+1, f)
	}
	d.knowledgeGraph(rep)
	d.attackPathValidation(rep.AttackPathValidation)
}

// attackPathValidation renders the native attack-path engine's lateral-movement
// summary in the fpdf fallback. The HTML→Chromium pipeline renders the full
// section (score card, paths, crown jewels, choke points); this keeps the
// fallback PDF in parity. Guarded — renders nothing until attackpath.collect has
// produced a graph for the subject.
func (d *rpt) attackPathValidation(s *attackpath.Summary) {
	if s == nil {
		return
	}
	pdf := d.pdf
	d.ensure(22)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Attack Path Validation")
	pdf.Ln(5.4)
	dc := "no path to Domain Admin found"
	if s.DomainCompromise {
		dc = "a host can reach Domain Admin / Tier-0"
	}
	d.body(fmt.Sprintf("Attack Path Score: %d/100 (%s risk — higher is safer). Lateral movement: %s, averaging %.1f and at most %d hosts compromisable per entry host. Domain compromise: %s.",
		s.AttackPathScore, s.Band, s.LateralMovementBand, s.AvgBlastRadius, s.MaxBlastRadius, dc))
	d.body(fmt.Sprintf("Graph scope: %d hosts, %d users, %d groups, %d relationship edges.", s.Hosts, s.Users, s.Groups, s.Edges))
	if len(s.CrownJewels) > 0 {
		reach := 0
		for _, cj := range s.CrownJewels {
			if cj.Reachable {
				reach++
			}
		}
		d.body(fmt.Sprintf("Crown jewels: %d of %d reachable from the fleet.", reach, len(s.CrownJewels)))
	}
	if n := len(s.SegmentationViols); n > 0 {
		d.body(fmt.Sprintf("Segmentation: %d lateral-movement edge(s) cross a network-segment boundary.", n))
	}
	if len(s.ChokePoints) > 0 {
		c := s.ChokePoints[0]
		d.body(fmt.Sprintf("Top choke point: %s appears on %.0f%% of attacker paths — remediating it eliminates many at once.", c.Label, c.Coverage*100))
	}
	pdf.Ln(1.5)
}

// topRiskDrivers lists the techniques whose failures account for the most lost
// prevention points — answering "why is my score low?". Score points are
// severity-weighted attribution, consistent with the headline score.
func (d *rpt) topRiskDrivers(drivers []RiskDriver) {
	if len(drivers) == 0 {
		return
	}
	pdf := d.pdf
	d.ensure(16)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Top Risk Drivers")
	pdf.Ln(5.4)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetX(margin)
	d.mcellT(contentW, 3.8, "Techniques whose failures account for the most lost prevention points (the points each accounts for, not a promised gain from any single fix).", "", "L", false)
	pdf.Ln(1)
	for i, dr := range drivers {
		d.ensure(7)
		y := pdf.GetY()
		d.text(cMuted)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetXY(margin+1, y)
		d.cellT(6, 5, fmt.Sprintf("%d.", i+1))
		d.text(cNavy)
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.SetXY(margin+8, y)
		label := dr.Name
		if dr.TechniqueID != "" {
			label = dr.TechniqueID + "  " + dr.Name
		}
		d.cellT(contentW-8-46, 5, label+"  ("+capTactic(dr.Tactic)+")")
		d.chip(pageW-margin-44, y+0.2, fmt.Sprintf("%.1f PTS · %dF · %s", dr.ScorePoints, dr.Failures, strings.ToUpper(dr.Severity)), d.sevColor(dr.Severity))
		pdf.SetY(y + 6)
	}
	pdf.Ln(1.5)
}

// attackPath renders the chain of unprevented kill-chain phases as a vertical
// flow — how an attacker would traverse this endpoint, not a list of isolated
// ATT&CK IDs. Only shown when the path spans at least two phases (a single phase
// is a finding, not a path). Connectors are drawn (not glyphs) to stay safe under
// the WinAnsi core font.
func (d *rpt) attackPath(ap AttackPath) {
	if len(ap.Steps) < 2 {
		return
	}
	pdf := d.pdf
	d.ensure(24)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Realized Attack Path")
	pdf.Ln(5.2)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetX(margin)
	d.mcellT(contentW, 4, "The unprevented techniques from this run, ordered by kill-chain phase. An attacker chaining these consecutive "+
		"phases met limited resistance — this is the path the endpoint's gaps actually permit, derived from observed FAILs (no inferred causal links).", "", "L", false)
	pdf.Ln(2)
	for i, s := range ap.Steps {
		d.ensure(12)
		d.text(cDanger)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.SetX(margin + 4)
		d.cellT(0, 4.6, capTactic(s.Tactic))
		pdf.Ln(4.4)
		d.text(cInk)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetX(margin + 8)
		d.mcellT(contentW-8, 4.2, strings.Join(s.Techniques, "   ·   "), "", "L", false)
		if i < len(ap.Steps)-1 {
			cx := margin + 6
			d.draw(cMuted)
			pdf.SetLineWidth(0.4)
			pdf.Line(cx, pdf.GetY()+0.8, cx, pdf.GetY()+3.6)
			pdf.SetY(pdf.GetY() + 4.6)
		}
		pdf.Ln(0.5)
	}
	pdf.Ln(1.5)
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
	d.threatIntel(f.TechniqueID)
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
	d.body("Results are grouped by ATT&CK technique. Each technique shows how many " +
		"of its tests executed, were blocked, or errored. ERROR tests (a BAS " +
		"execution problem, not a security outcome) are summarised in the counts " +
		"and excluded from scoring.")
	groups := groupResultsByTechnique(results)
	rendered := 0
	for _, g := range groups {
		// A group that only errored or was skipped carries no security finding,
		// but we still surface it so the reader sees the technique was attempted.
		if g.Total == 0 {
			continue
		}
		d.techniqueGroup(g)
		rendered++
	}
	if rendered == 0 {
		d.body("No techniques were executed in this run.")
	}
}

// techniqueGroup renders one rolled-up ATT&CK technique: a header with the
// per-verdict tally, the threat impact and remediation shown ONCE, then a
// compact row per security-relevant execution (FAIL / PASS / BLOCKED). ERROR and
// SKIPPED runs are represented by the tally only, to avoid report fatigue.
func (d *rpt) techniqueGroup(g TechniqueGroup) {
	pdf := d.pdf
	d.ensure(22)
	yStart := pdf.GetY()

	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin + 2)
	d.mcellT(contentW-2, 4.8, fmt.Sprintf("%s — %s", emptyDash(g.TechniqueID), emptyDash(g.Name)), "", "L", false)

	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetX(margin + 2)
	meta := capTactic(g.Tactic)
	if g.Severity != "" {
		meta += "  ·  " + g.Severity
	}
	meta += "  ·  " + testKind(groupFramework(g))
	d.cellT(0, 4, meta)
	pdf.Ln(4.4)

	pdf.SetX(margin + 2)
	d.text(cInk)
	pdf.SetFont("Helvetica", "B", 7.5)
	d.cellT(0, 4, fmt.Sprintf("%d test(s):  %d executed · %d blocked · %d errored · %d skipped",
		g.Total, g.Executed, g.Blocked, g.Errored, g.Skipped))
	pdf.Ln(5)

	// Threat impact + remediation once per technique (identical across its tests);
	// prefer a FAIL result so the remediation is the actionable one, not the
	// "control validated" message attached to a blocked test.
	rep := groupRepresentative(g)
	if rep.ThreatImpact != "" {
		d.labelled("Threat impact", rep.ThreatImpact)
	}
	if rep.Remediation != "" {
		d.labelled("Remediation", rep.Remediation)
	}

	for _, r := range g.Results {
		if r.Result != models.ResultFail && r.Result != models.ResultPass && r.Result != models.ResultBlocked {
			continue
		}
		d.executionRow(r)
	}

	stripe := cWarning
	if g.Executed > 0 {
		stripe = d.resultColor(models.ResultFail)
	} else if g.Blocked > 0 {
		stripe = d.resultColor(models.ResultPass)
	}
	yEnd := pdf.GetY()
	if yEnd > yStart {
		d.fill(stripe)
		pdf.Rect(margin-2.5, yStart, 1.2, yEnd-yStart-1, "F")
	}
	d.separator()
}

// executionRow renders one execution within a technique group: a verdict chip
// plus its detail (and, for a FAIL, the raw evidence) — without repeating the
// technique name, threat, or remediation already shown at the group header.
func (d *rpt) executionRow(r models.SimulationResult) {
	pdf := d.pdf
	d.ensure(8)
	y := pdf.GetY()
	d.chip(margin+2, y, strings.ToUpper(string(r.Result)), d.resultColor(r.Result))
	d.text(cInk)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(margin+24, y-0.3)
	d.mcellT(contentW-24, 4.4, emptyDash(r.Details), "", "L", false)
	if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
		// Attribution: name the control that blocked it when evidence supports it,
		// else say a control blocked it without guessing a product (honest).
		ctrl := attributeControl(r)
		if ctrl == "" {
			ctrl = "an active security control (not identifiable from local telemetry)"
		}
		d.text(cSuccess)
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetX(margin + 24)
		d.mcellT(contentW-24, 4, "Blocked by: "+ctrl, "", "L", false)
	}
	if r.Result == models.ResultFail {
		// Detection correlation: even when prevention failed, surface whether the
		// attack was DETECTED (Defender) or merely logged / unseen.
		det := classifyDetection(r.Events)
		dc := cMuted
		switch det.Status {
		case "Detected":
			dc = cWarning
		case "None":
			dc = cDanger
		}
		d.text(dc)
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetX(margin + 24)
		d.mcellT(contentW-24, 4, "Detection: "+det.Detail, "", "L", false)
		if ev := humanizeEvidence(r); ev != "" {
			d.text(cMuted)
			pdf.SetFont("Helvetica", "", 7.5)
			pdf.SetX(margin + 24)
			d.mcellT(contentW-24, 4, "Evidence: "+ev, "", "L", false)
		}
	}
	pdf.Ln(1.5)
}

// groupFramework returns the framework of the group's first test (all tests for a
// technique share the same framework in practice).
func groupFramework(g TechniqueGroup) string {
	if len(g.Results) > 0 {
		return g.Results[0].Framework
	}
	return ""
}

// groupRepresentative picks the result whose threat/remediation best represents
// the technique: a FAIL if any (carries the actionable remediation), else the
// first result.
func groupRepresentative(g TechniqueGroup) models.SimulationResult {
	for _, r := range g.Results {
		if r.Result == models.ResultFail {
			return r
		}
	}
	if len(g.Results) > 0 {
		return g.Results[0]
	}
	return models.SimulationResult{}
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

// ── 7. Changes & cleanup verification ───────────────────────────────────────

func (d *rpt) changesAndCleanup(rep *FullReport) {
	d.sectionTitle(7, "Changes & Cleanup Verification")
	pdf := d.pdf

	if rep.CleanupFailed {
		d.ensure(22)
		y := pdf.GetY()
		d.fill(rgb{253, 246, 246})
		d.draw(cDanger)
		pdf.SetLineWidth(0.2)
		pdf.RoundedRect(margin, y, contentW, 18, 2, "1234", "FD")
		d.fill(cDanger)
		pdf.Rect(margin, y, 3, 18, "F")

		d.text(cDanger)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetXY(margin+6, y+2)
		d.cellT(contentW-10, 5, "Warning: Cleanup failed")

		d.text(cInk)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetXY(margin+6, y+7)
		d.mcellT(contentW-10, 3.8, fmt.Sprintf("Out of the executed techniques, %d failed to clean up successfully. Residual simulation artifacts (files or registry entries) may remain on the endpoint. SOC/security teams should review the logs below to perform manual remediation.", rep.CleanupFailedCount), "", "L", false)
		pdf.SetY(y + 20.5)
	}

	n := len(rep.Reverted)
	if n == 0 {
		d.body("No endpoint changes were captured for reversal during this run — the " +
			"snapshot/revert system recorded no residual registry or file artifacts to " +
			"roll back.")
	} else {
		statusText := "COMPLETED — each captured change was rolled back from the pre-run snapshot."
		if rep.CleanupFailed {
			statusText = "WARNING — cleanup failed for one or more techniques. Some captured changes could not be rolled back automatically."
		}
		d.body(fmt.Sprintf("The agent reverted %d endpoint change(s) made during the run. "+
			"Cleanup status: %s", n, statusText))
		for _, item := range rep.Reverted {
			d.ensure(6)
			d.text(cMuted)
			pdf.SetFont("Helvetica", "", 8.5)
			pdf.SetX(margin + 4)
			d.cellT(4, 4.6, "•")
			d.text(cInk)
			pdf.SetX(margin + 9)
			d.mcellT(contentW-9, 4.6, item, "", "L", false)
		}
		pdf.Ln(1)
	}
	d.body("Scope note: residual-artifact tracking covers changes captured by the pre-run " +
		"snapshot (registry keys and files the engine instruments). Out-of-band changes a " +
		"technique may make outside that scope are not tracked here — verify manually for " +
		"high-impact techniques run in production.")
}

// ── 8. Recommendations ──────────────────────────────────────────────────────

func (d *rpt) recommendations(rep *FullReport) {
	d.sectionTitle(8, "Action Plan")
	pdf := d.pdf

	// Score-impact-ranked action plan: each tactic's failures and the prevention
	// points they ACCOUNT FOR (not a promised gain — a single control may not
	// resolve every underlying finding).
	if len(rep.ActionPlan) > 0 {
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetX(margin)
		d.mcellT(contentW, 4, "Ordered by the prevention-score points each tactic's failures account for (severity-weighted, the same weighting as the headline score). The points quantify current exposure — not a guaranteed score gain.", "", "L", false)
		pdf.Ln(1.5)
		for i, a := range rep.ActionPlan {
			d.ensure(16)
			y := pdf.GetY()
			d.fill(cAccent)
			pdf.RoundedRect(margin, y+0.4, 5, 5, 1, "1234", "F")
			d.text(cWhite)
			pdf.SetFont("Helvetica", "B", 8)
			pdf.SetXY(margin, y+0.4)
			d.cfT(5, 5, fmt.Sprintf("%d", i+1), "", 0, "C", false, 0, "")
			d.text(cNavy)
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetXY(margin+8, y)
			title := capTactic(a.Tactic)
			if a.Objective != "" {
				title += " — " + a.Objective
			}
			d.cellT(contentW-8-30, 5, title)
			d.chip(pageW-margin-30, y+0.2, fmt.Sprintf("%.1f PTS · %dF", a.ScorePoints, a.Failures), cDanger)
			pdf.SetXY(margin+8, y+5.2)
			d.text(cInk)
			pdf.SetFont("Helvetica", "", 8.5)
			d.mcellT(contentW-8, 4.4, a.Recommendation, "", "L", false)
			pdf.SetY(pdf.GetY() + 2)
		}
	}

	// Supplementary narrative guidance (programme-level), if any.
	recs := rep.Summary.Recommendations
	if len(rep.ActionPlan) == 0 && len(recs) == 0 {
		d.body("Maintain the current security posture and schedule the next assessment within 30 days.")
		return
	}
	if len(recs) > 0 {
		d.ensure(10)
		d.text(cNavy)
		pdf.SetFont("Helvetica", "B", 9.5)
		pdf.SetX(margin)
		d.cellT(0, 5, "Additional Guidance")
		pdf.Ln(5.4)
		for i, rec := range recs {
			d.ensure(12)
			y := pdf.GetY()
			d.fill(cMuted)
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
}

// ── 9. Glossary ─────────────────────────────────────────────────────────────

func (d *rpt) glossary() {
	d.sectionTitle(9, "Appendix — Metric Definitions")
	defs := [][2]string{
		{"PASS", "A security control prevented or blocked the simulated technique. More passes is better."},
		{"FAIL", "A prevention control did not stop the technique from executing — a finding requiring attention. This means execution was permitted; it does NOT independently verify the attacker's end objective was achieved (e.g. that credentials were actually exfiltrated), which is technique-specific. Check the Detection line for whether the execution was also detected."},
		{"Detection", "Whether the executed technique was seen by locally-observable telemetry: Detected (a Microsoft Defender alert fired), Logged only (Sysmon/Security telemetry exists but no alert), or Undetected (no telemetry). Third-party EDR detection is not locally observable and is never asserted."},
		{"Blocked by", "The control credited with blocking a technique, when local evidence (a Microsoft Defender event or a recognisable block signature in the output) supports it. Where no control can be evidenced locally, the report states that an active control blocked it without naming a product — it never guesses."},
		{"Trend", "Change in prevention effectiveness versus the previous scored assessment for this endpoint, with a short history. Appears once a second assessment has completed."},
		{"Threat Intelligence", "Per-technique context from MITRE ATT&CK® (threat actors, malware/tools, mitigations) — authoritative, published by MITRE. CVE/KEV/OWASP/CWE shown as 'illustrative' are analyst-curated context, not an authoritative per-technique mapping, and should be read as examples, not an exhaustive list."},
		{"ERROR", "The test could not execute correctly (malformed content, timeout, missing prerequisite, scheduler contention). A BAS execution problem, not a security outcome — excluded from scoring."},
		{"SKIPPED", "The technique was deliberately not run (e.g. external payload not shipped) and was excluded from scoring."},
		{"Policy Configuration Check", "A passive audit that inspects a security setting (registry key, policy, service state) without running an attack — it confirms whether a control is correctly configured."},
		{"Active Adversary Behavioral Test", "An ART or Caldera test that actually executes the technique on the endpoint — it confirms whether deployed controls stop a live attack, not just whether they are configured."},
		{"Prevention", "Severity-weighted percentage of techniques that were prevented. Higher is better."},
		{"Exposure", "Tactic-weighted failure rate, amplified by consecutive kill-chain failures. Lower is better."},
		{"Tactic Breadth", "Breadth of THIS run: how many of the 14 MITRE ATT&CK Enterprise tactics it exercised. Not a measure of overall MITRE ATT&CK technique coverage — running more Atomics in a tactic does not increase ATT&CK coverage."},
		{"Defense Rate", "Share of tested tactics in which every technique was blocked (zero failures)."},
		{"Kill-chain amplifier", "Multiplier (1.0–2.5×) reflecting consecutive unprevented kill-chain phases."},
		{"Risk classification", "Overall posture band derived from the amplified exposure score."},
	}
	d.keyValueTable(defs)
}

// ── small helpers ───────────────────────────────────────────────────────────

// exposureColor maps the plain-English exposure band to a status colour.
func (d *rpt) exposureColor(level string) rgb {
	switch level {
	case "Low":
		return cSuccess
	case "Medium":
		return cWarning
	case "High":
		return rgb{240, 136, 62}
	case "Critical":
		return cDanger
	}
	return cMuted
}

// fmtMTTD renders a mean-time-to-detect in ms as a short human string.
func fmtMTTD(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	s := ms / 1000
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	return fmt.Sprintf("%dm %02ds", s/60, s%60)
}

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

// evidenceLine condenses raw command output into a short single-line evidence
// string for the report: collapse whitespace/newlines and cap the length so the
// "Evidence" row stays a readable trace, not a wall of console text.
func evidenceLine(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.Join(strings.Fields(s), " ")
	const max = 240
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// benignOutputSignatures are common harness/atomic stdout lines that confirm a
// command merely ran but carry no security meaning (e.g. "Hello from PowerShell").
// We suppress them from the Evidence line so it stays a security statement, not a
// console transcript — the ART review flagged raw output as noise.
var benignOutputSignatures = []string{
	"hello from",
	"the operation completed successfully",
	"the command completed successfully",
	"completed successfully",
}

// humanizeEvidence returns the Evidence string for a FAIL row. The verdict and the
// row's detail already establish the technique was not prevented, so raw console
// chatter adds nothing; we show the captured output ONLY when it is genuinely
// informative (an error, an artefact path, a value), and drop benign confirmations.
// Honest by design: we filter noise, we never invent meaning the output does not
// carry. Applies to every framework, not just ART.
func humanizeEvidence(r models.SimulationResult) string {
	raw := evidenceLine(r.RawOutput)
	if raw == "" || isBenignOutput(raw) {
		return ""
	}
	return raw
}

func isBenignOutput(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	for _, sig := range benignOutputSignatures {
		if strings.Contains(low, sig) {
			return true
		}
	}
	return false
}

// maturityScore maps a per-category prevention percentage to a 0–10 maturity
// figure management reads faster than raw percentages (round to nearest).
func maturityScore(passPct int) int {
	s := (passPct + 5) / 10
	if s > 10 {
		s = 10
	}
	if s < 0 {
		s = 0
	}
	return s
}

// assetClass infers the endpoint class from the OS string. Honest: labelled
// "(inferred from OS)" because the agent does not report an explicit asset type.
func assetClass(os string) string {
	low := strings.ToLower(strings.TrimSpace(os))
	switch {
	case low == "":
		return "—"
	case strings.Contains(low, "server"):
		return "Server (inferred from OS)"
	case strings.Contains(low, "windows"):
		return "Workstation (inferred from OS)"
	default:
		return "Endpoint (inferred from OS)"
	}
}

// businessCriticality derives a criticality band from the environment label so the
// same finding reads differently on a production endpoint vs a test box. Derived
// from the environment tag — not an independent asset-management classification.
func businessCriticality(env string) string {
	if isProductionEnv(env) {
		return "High — production endpoint"
	}
	if strings.TrimSpace(env) == "" {
		return "Not classified"
	}
	return "Standard — non-production"
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
