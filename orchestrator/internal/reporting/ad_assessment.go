package reporting

// Active Directory coverage assessment report — JSON (the backend report
// verbatim), HTML (styled enterprise report), PDF (HTML→Chrome sidecar with an
// fpdf fallback). This package only formats; it consumes admatrix.Report()
// and knows nothing about how the AD capability model is built.
//
// Honesty contract (mirrors the operator UI): the report separates the five
// independent coverage axes and never presents modeled or content-available
// coverage as validated AD security. Executed / detection-validated counts are
// stated plainly, and every figure comes from the same admatrix.Report() the
// UI reads -- there are no report-local hardcoded tallies.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	fpdf "github.com/go-pdf/fpdf"

	"github.com/audspect/bas/internal/admatrix"
)

// ADAssessmentReport is the canonical input to every AD report render function.
// Build it server-side as {GeneratedAt: time.Now(), Report: admatrix.Report()}.
type ADAssessmentReport struct {
	GeneratedAt time.Time               `json:"generatedAt"`
	Report      admatrix.CoverageReport `json:"report"`
}

// ADFamilyGroup is one attack family and its capabilities, for per-family tables.
type ADFamilyGroup struct {
	Name string
	Caps []admatrix.CapabilityState
}

// Families groups the capability states by their Family label, each family's
// capabilities kept in report order, families sorted alphabetically.
func (r ADAssessmentReport) Families() []ADFamilyGroup {
	idx := map[string]int{}
	var groups []ADFamilyGroup
	for _, c := range r.Report.CapabilityStates {
		fam := c.Family
		if fam == "" {
			fam = "Unclassified"
		}
		i, ok := idx[fam]
		if !ok {
			idx[fam] = len(groups)
			groups = append(groups, ADFamilyGroup{Name: fam})
			i = len(groups) - 1
		}
		groups[i].Caps = append(groups[i].Caps, c)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups
}

// dedupeStrings collects the distinct, order-preserving union of a field across
// all capability states -- used for the aggregate Limitations and Outstanding
// sections so the report never fabricates items the per-capability data lacks.
func (r ADAssessmentReport) dedupe(pick func(admatrix.CapabilityState) []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range r.Report.CapabilityStates {
		for _, s := range pick(c) {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (r ADAssessmentReport) AllLimitations() []string {
	return r.dedupe(func(c admatrix.CapabilityState) []string { return c.Limitations })
}
func (r ADAssessmentReport) AllOutstanding() []string {
	return r.dedupe(func(c admatrix.CapabilityState) []string { return c.Outstanding })
}

// ── JSON export (secondary) ─────────────────────────────────────────────────

// ADAssessmentReportJSON writes the report as indented JSON -- the machine
// readable secondary export, identical in content to what the UI consumes.
func ADAssessmentReportJSON(w io.Writer, rep ADAssessmentReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ── HTML export ──────────────────────────────────────────────────────────────

var adReportFuncs = template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.UTC().Format("02 Jan 2006 15:04 UTC") },
	"contentLabel": func(s admatrix.ContentState) string {
		switch s {
		case admatrix.ContentScenarioComposable:
			return "Scenario-composable"
		case admatrix.ContentReusableUnmapped:
			return "Reusable (unmapped)"
		case admatrix.ContentModelOnly:
			return "Model-only"
		case admatrix.ContentMissingExecutable:
			return "Missing content"
		case "":
			return "Unknown"
		}
		return string(s)
	},
	"execLabel": func(s admatrix.ExecutionValidation) string {
		switch s {
		case admatrix.ExecNotExecuted, "":
			return "Not executed"
		case admatrix.ExecAttempted:
			return "Attempted"
		case admatrix.ExecCompleted:
			return "Completed"
		case admatrix.ExecPostconditionVerified:
			return "Postcondition verified"
		}
		return string(s)
	},
	"detLabel": func(s admatrix.DetectionValidation) string {
		switch s {
		case admatrix.DetNotValidated, "":
			return "Not validated"
		case admatrix.DetSimulatedEvidence:
			return "Simulated only"
		case admatrix.DetTelemetryObserved:
			return "Telemetry observed"
		}
		return string(s)
	},
	"composedLabel": func(b bool) string {
		if b {
			return "Composed"
		}
		return "Not composed"
	},
}

// ADAssessmentReportHTML renders the styled enterprise report. The same HTML is
// fed to the Chrome sidecar for the PDF. html/template auto-escapes every field,
// so hostile capability names / evidence strings can never inject markup.
func ADAssessmentReportHTML(w io.Writer, rep ADAssessmentReport) error {
	t, err := template.New("ad-assessment").Funcs(adReportFuncs).Parse(adAssessmentTmpl)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}
	return t.Execute(w, rep)
}

// ── PDF export (primary) ─────────────────────────────────────────────────────

// ADAssessmentReportPDF renders the HTML report to PDF via the Chrome sidecar,
// falling back to a plain fpdf summary when the sidecar is unconfigured or
// unreachable, so the primary export never hard-depends on the sidecar.
func ADAssessmentReportPDF(ctx context.Context, w io.Writer, rep ADAssessmentReport) error {
	var buf bytes.Buffer
	if err := ADAssessmentReportHTML(&buf, rep); err == nil {
		if pdf, perr := htmlToPDF(ctx, buf.Bytes()); perr == nil && len(pdf) > 0 {
			_, werr := w.Write(pdf)
			return werr
		}
	}
	return adAssessmentFallbackPDF(w, rep)
}

func adAssessmentFallbackPDF(w io.Writer, rep ADAssessmentReport) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()

	sum := rep.Report.CapabilityStateSummary
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(0, 10, tr("Active Directory Coverage Assessment"), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(0, 6, tr("Generated "+rep.GeneratedAt.UTC().Format("02 Jan 2006 15:04 UTC")+" — CONFIDENTIAL"), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 7, tr("Executive Summary"), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.MultiCell(0, 5, tr(fmt.Sprintf(
		"%d capabilities modeled; %d scenario-composed. %d of %d capabilities executed and %d detection-validated against real Active Directory. These results are not validated against real Active Directory: modeled coverage and scenario composition do not imply a technique has run against, or been detected in, a live domain.",
		sum.Modeled, sum.ScenarioComposed, sum.Executed, sum.Total, sum.DetectionValidated)), "", "L", false)
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 7, tr(fmt.Sprintf("Capability Results (%d)", sum.Total)), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 7)
	pdf.CellFormat(55, 6, tr("Capability"), "1", 0, "L", false, 0, "")
	pdf.CellFormat(22, 6, tr("Family"), "1", 0, "L", false, 0, "")
	pdf.CellFormat(38, 6, tr("Content"), "1", 0, "L", false, 0, "")
	pdf.CellFormat(32, 6, tr("Execution"), "1", 0, "L", false, 0, "")
	pdf.CellFormat(0, 6, tr("Detection"), "1", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 7)
	for _, c := range rep.Report.CapabilityStates {
		pdf.CellFormat(55, 6, tr(trunc(c.Name, 40)), "1", 0, "L", false, 0, "")
		pdf.CellFormat(22, 6, tr(c.Family), "1", 0, "L", false, 0, "")
		pdf.CellFormat(38, 6, tr(string(c.ContentAvailability)), "1", 0, "L", false, 0, "")
		pdf.CellFormat(32, 6, tr(string(c.ExecutionValidation)), "1", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, tr(string(c.DetectionValidation)), "1", 1, "L", false, 0, "")
	}
	pdf.Ln(3)

	if lims := rep.AllLimitations(); len(lims) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 7, tr("Limitations"), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		for _, l := range lims {
			pdf.MultiCell(0, 5, tr("• "+l), "", "L", false)
		}
		pdf.Ln(2)
	}
	if out := rep.AllOutstanding(); len(out) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 7, tr("Outstanding Work"), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		for _, o := range out {
			pdf.MultiCell(0, 5, tr("• "+o), "", "L", false)
		}
	}
	return pdf.Output(w)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
