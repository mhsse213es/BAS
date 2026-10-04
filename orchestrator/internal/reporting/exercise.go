package reporting

// Exercise report generation — JSON (canonical), HTML (styled), CSV (timeline),
// PDF (HTML→Chrome sidecar with fpdf fallback).
//
// The exercise engine owns execution, evidence, and scoring. This package
// owns formatting — it consumes exercise data structures via a flat report
// struct and knows nothing about the engine's DB or DAG logic.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	fpdf "github.com/go-pdf/fpdf"

	"github.com/audspect/bas/internal/exercise"
)

// ExerciseReport is the canonical representation of one exercise execution.
// Build it server-side from DB data and pass it to any of the render functions.
type ExerciseReport struct {
	Execution *exercise.Execution      `json:"execution"`
	Plan      *exercise.Plan           `json:"plan"`
	Steps     []exercise.StepExecution `json:"steps"`
	Evidence  []exercise.Evidence      `json:"evidence"`
	Events    []map[string]any         `json:"events"`
	Score     *exercise.ExerciseScore  `json:"score,omitempty"`
	ChainOK   bool                     `json:"chain_ok"`
	ChainErr  string                   `json:"chain_error,omitempty"`
	// Flat timeline sorted by timestamp — built by BuildTimeline.
	Timeline []TimelineEntry `json:"timeline,omitempty"`
}

// TimelineEntry is one moment in the exercise — an event, evidence record,
// or step status transition, merged and sorted by time.
type TimelineEntry struct {
	TS       time.Time `json:"ts"`
	Kind     string    `json:"kind"` // "event", "evidence", "step"
	StepID   string    `json:"step_id,omitempty"`
	StepType string    `json:"step_type,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Summary  string    `json:"summary"`
	Detail   any       `json:"detail,omitempty"`
}

// BuildTimeline merges events and evidence into a single chronological slice.
func BuildTimeline(rep *ExerciseReport) []TimelineEntry {
	var tl []TimelineEntry
	for _, ev := range rep.Events {
		ts, _ := ev["ts"].(time.Time)
		tl = append(tl, TimelineEntry{
			TS:      ts,
			Kind:    "event",
			StepID:  strAny(ev["step_id"]),
			Actor:   strAny(ev["actor"]),
			Summary: strAny(ev["event_type"]),
			Detail:  ev["detail"],
		})
	}
	for _, ev := range rep.Evidence {
		tl = append(tl, TimelineEntry{
			TS:      ev.CreatedAt,
			Kind:    "evidence",
			StepID:  ev.StepExecutionID,
			Actor:   ev.Actor,
			Summary: ev.EvidenceType,
			Detail:  ev.Payload,
		})
	}
	sort.Slice(tl, func(i, j int) bool { return tl[i].TS.Before(tl[j].TS) })
	return tl
}

// ── JSON export ───────────────────────────────────────────────────────────────

// ExerciseReportJSON writes the canonical JSON representation to w.
// This is the source-of-truth export: every field, every hash, machine-readable.
func ExerciseReportJSON(w io.Writer, rep *ExerciseReport) error {
	if rep.Timeline == nil {
		rep.Timeline = BuildTimeline(rep)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ── CSV export ────────────────────────────────────────────────────────────────

// ExerciseReportCSV writes a timeline CSV — one row per event/evidence record.
// Designed for analysts who want to review the exercise in Excel.
func ExerciseReportCSV(w io.Writer, rep *ExerciseReport) error {
	if rep.Timeline == nil {
		rep.Timeline = BuildTimeline(rep)
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"Timestamp", "Kind", "Step_ID", "Actor", "Summary", "Detail"})
	for _, e := range rep.Timeline {
		detail := ""
		if e.Detail != nil {
			b, _ := json.Marshal(e.Detail)
			detail = string(b)
		}
		_ = cw.Write([]string{
			e.TS.UTC().Format(time.RFC3339),
			e.Kind,
			e.StepID,
			e.Actor,
			e.Summary,
			detail,
		})
	}
	return cw.Error()
}

// ── HTML export ───────────────────────────────────────────────────────────────

// ExerciseReportHTML renders the styled HTML exercise report to w.
// The same HTML is fed to the Chrome sidecar for PDF generation.
func ExerciseReportHTML(w io.Writer, rep *ExerciseReport) error {
	if rep.Timeline == nil {
		rep.Timeline = BuildTimeline(rep)
	}
	t, err := template.New("exercise").Funcs(template.FuncMap{
		"fmtTime": func(v any) string {
			switch tv := v.(type) {
			case time.Time:
				return tv.UTC().Format("02 Jan 2006 15:04:05 UTC")
			case *time.Time:
				if tv == nil {
					return "—"
				}
				return tv.UTC().Format("02 Jan 2006 15:04:05 UTC")
			}
			return "—"
		},
		"fmtDur":   fmtDur,
		"pct":      func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"kindIcon": kindIcon,
		"evClass":  evClass,
		"seq":      func(i int) int { return i + 1 },
		// Accepts any, not string. The template calls this on
		// .Execution.Status, whose type is exercise.ExecStatus -- a DEFINED
		// string type, which Go does not consider assignable to a string
		// parameter. text/template therefore failed the call with "wrong type
		// for value; expected string; got exercise.ExecStatus", aborting the
		// render at that field for every exercise report.
		//
		// This went unnoticed because ExerciseReportHTML writes straight to the
		// http.ResponseWriter: Execute had already streamed the document up to
		// that point and committed a 200, so the handler's jsonError could not
		// change the status and merely appended JSON to a truncated page. The
		// existing handler test asserted only status 200 and the presence of
		// "<html", both of which a truncated response satisfies.
		"lower":    func(v any) string { return strings.ToLower(fmt.Sprint(v)) },
		"joinStrs": strings.Join,
		"scoreBar": func(f float64) int {
			v := int(f)
			if v < 0 {
				return 0
			}
			if v > 100 {
				return 100
			}
			return v
		},
		// scoreArc returns the stroke-dasharray fill length for a 276.46-circumference donut (r=44).
		"scoreArc": func(f float64) float64 {
			if f < 0 {
				f = 0
			}
			if f > 100 {
				f = 100
			}
			return 276.46 * f / 100
		},
		// scoreColor maps an overall score (0-100) to a semantic color.
		"scoreColor": func(f float64) string {
			switch {
			case f >= 70:
				return "#0d9488"
			case f >= 40:
				return "#d29922"
			default:
				return "#da3633"
			}
		},
		// pctInt converts a 0..1 fraction to a 0..100 integer (for CSS bar widths).
		"pctInt": func(f float64) int {
			v := int(f * 100)
			if v < 0 {
				return 0
			}
			if v > 100 {
				return 100
			}
			return v
		},
		// truncate clips s to n runes and appends "…" when clipped.
		"truncate": func(s string, n int) string {
			r := []rune(s)
			if len(r) <= n {
				return s
			}
			return string(r[:n]) + "…"
		},
	}).Parse(exerciseReportTmpl)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}
	return t.Execute(w, rep)
}

// ── PDF export ────────────────────────────────────────────────────────────────

// ExerciseReportPDF renders the HTML report and prints it to PDF via the
// Chrome sidecar; when the sidecar is unconfigured or unreachable it falls
// back to a plain fpdf-rendered summary (exerciseReportFallbackPDF), mirroring
// the fpdf-fallback pattern the full BAS report uses (Engine.PDFFromReport in
// htmlpdf.go) so this export never hard-depends on the sidecar being up.
func ExerciseReportPDF(ctx context.Context, w io.Writer, rep *ExerciseReport) error {
	var buf bytes.Buffer
	if err := ExerciseReportHTML(&buf, rep); err == nil {
		if pdf, perr := htmlToPDF(ctx, buf.Bytes()); perr == nil && len(pdf) > 0 {
			_, werr := w.Write(pdf)
			return werr
		}
	}
	return exerciseReportFallbackPDF(w, rep)
}

// exerciseReportFallbackPDF renders a plain (non-styled) PDF summary directly
// via fpdf, with no dependency on the Chrome sidecar: title/status, execution
// metadata, score, a step table, and the evidence/event timeline.
func exerciseReportFallbackPDF(w io.Writer, rep *ExerciseReport) error {
	if rep.Timeline == nil {
		rep.Timeline = BuildTimeline(rep)
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()

	ex, plan := rep.Execution, rep.Plan
	name := ex.Name
	if name == "" && plan != nil {
		name = plan.Name
	}
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(0, 10, tr("Exercise Report"), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 6, tr(fmt.Sprintf("%s — %s", name, ex.Status)), "", 1, "L", false, 0, "")
	pdf.Ln(2)

	planLabel := "—"
	if plan != nil {
		planLabel = fmt.Sprintf("%s (v%d)", plan.Name, plan.Version)
	}
	rows := [][2]string{
		{"Execution ID", ex.ID},
		{"Plan", planLabel},
		{"Status", string(ex.Status)},
		{"Initiated by", emptyDash(ex.InitiatedBy)},
		{"Started", fmtTimePtr(ex.StartedAt)},
		{"Completed", fmtTimePtr(ex.CompletedAt)},
		{"Evidence chain", chainStatusLabel(rep)},
	}
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 7, tr("Summary"), "", 1, "L", false, 0, "")
	for _, r := range rows {
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(45, 6, tr(r[0]), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(0, 6, tr(r[1]), "", 1, "L", false, 0, "")
	}
	pdf.Ln(3)

	if rep.Score != nil {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 7, tr("Score"), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(0, 6, tr(fmt.Sprintf("Overall: %.1f", rep.Score.Overall)), "", 1, "L", false, 0, "")
		pdf.Ln(2)
	}

	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 7, tr(fmt.Sprintf("Steps (%d)", len(rep.Steps))), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(70, 6, tr("Step"), "1", 0, "L", false, 0, "")
	pdf.CellFormat(40, 6, tr("Type"), "1", 0, "L", false, 0, "")
	pdf.CellFormat(0, 6, tr("Status"), "1", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	for _, s := range rep.Steps {
		pdf.CellFormat(70, 6, tr(s.StepID), "1", 0, "L", false, 0, "")
		pdf.CellFormat(40, 6, tr(string(s.StepType)), "1", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, tr(string(s.Status)), "1", 1, "L", false, 0, "")
	}
	pdf.Ln(3)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 7, tr(fmt.Sprintf("Timeline (%d)", len(rep.Timeline))), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	for _, e := range rep.Timeline {
		pdf.MultiCell(0, 5, tr(fmt.Sprintf("%s  [%s]  %s  %s",
			e.TS.UTC().Format(time.RFC3339), e.Kind, emptyDash(e.Actor), e.Summary)), "", "L", false)
	}

	return pdf.Output(w)
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}

func chainStatusLabel(rep *ExerciseReport) string {
	if rep.ChainOK {
		return "intact"
	}
	if rep.ChainErr != "" {
		return "TAMPERED: " + rep.ChainErr
	}
	return "TAMPERED"
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func strAny(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func fmtDur(secs int) string {
	if secs <= 0 {
		return "—"
	}
	d := time.Duration(secs) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func kindIcon(kind string) string {
	switch kind {
	case "evidence":
		return "🔒"
	case "event":
		return "⚡"
	default:
		return "•"
	}
}

func evClass(summary string) string {
	switch summary {
	case "email_sent":
		return "ev-info"
	case "email_opened", "link_clicked", "credentials_submitted":
		return "ev-warn"
	case "edr_detected", "siem_alerted":
		return "ev-success"
	case "step_failed", "step_cancelled":
		return "ev-danger"
	case "phishing_reported":
		return "ev-success"
	default:
		return "ev-muted"
	}
}

// ── HTML template ─────────────────────────────────────────────────────────────

const exerciseReportTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Exercise Report — {{.Execution.Name}}</title>
<style>
/* ── reset ── */
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:13px}
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;
  color:#1a2332;background:#fff;line-height:1.6;font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
code{font-family:"Cascadia Code","Consolas","SF Mono",monospace;font-size:.85em}
:root{--line:#e8edf4;--surface:#f7f9fc;--navy:#0b1420;--ink:#1a2332;--accent:#2563eb;--teal:#0d9488;--muted:#6b7689}

/* ── page ── */
.page{width:210mm;min-height:297mm;margin:0 auto;background:#fff;
  position:relative;page-break-after:always;break-after:page;overflow:hidden}
.page:last-child{page-break-after:avoid;break-after:avoid}
@media screen{body{background:#c8d0da;padding:24px 0}
  .page{box-shadow:0 6px 32px rgba(0,0,0,.22);margin:0 auto 28px;border-radius:2px}}
@media print{body{background:#fff;padding:0}
  .page{width:100%;margin:0;box-shadow:none;overflow:visible}
  .ph,.pf{page-break-inside:avoid}
  thead{display:table-header-group}}
@media screen and (max-width:700px){
  body{padding:0}.page{width:100%;min-height:unset;overflow:visible;border-radius:0;box-shadow:none;margin:0 0 16px}
  .inner{padding:0 16px 20px;min-height:unset}.cover{min-height:unset;padding-bottom:24px}
  .kpi-row{grid-template-columns:1fr 1fr}.cover-grid{grid-template-columns:1fr}
  .two-col{grid-template-columns:1fr}}

/* ── cover ── */
.cover{background:#0b1420;min-height:297mm;display:flex;flex-direction:column;position:relative}
.cover-grain{position:absolute;inset:0;opacity:.03;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size:200px}
.cover-accent{position:absolute;right:-100px;top:-100px;width:520px;height:520px;
  border-radius:50%;border:70px solid rgba(13,148,136,.07);pointer-events:none}
.cover-accent2{position:absolute;right:40px;bottom:80px;width:280px;height:280px;
  border-radius:50%;border:40px solid rgba(37,99,235,.05);pointer-events:none}
.cover-header{padding:40px 48px 0;position:relative;z-index:1}
.clogo{display:flex;align-items:center;gap:11px}
.clogo-mark{width:34px;height:34px;background:linear-gradient(135deg,#0d9488 0%,#2563eb 100%);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:15px;color:#fff;flex-shrink:0}
.clogo-name{font-size:1.15rem;font-weight:800;color:#fff;letter-spacing:-.03em}
.clogo-name span{color:#0d9488}
.clogo-sub{font-size:.58rem;text-transform:uppercase;letter-spacing:.16em;color:#4a6a8a;margin-top:1px}
.cover-body{flex:1;padding:0 48px;display:flex;flex-direction:column;justify-content:center;position:relative;z-index:1}
.cover-eyebrow{font-size:.62rem;text-transform:uppercase;letter-spacing:.2em;color:#0d9488;font-weight:700;margin-bottom:12px}
.cover-title{font-size:2.5rem;font-weight:900;color:#fff;letter-spacing:-.04em;line-height:1.05;margin-bottom:8px}
.cover-sub{font-size:.95rem;color:#6a8aaa;margin-bottom:32px;line-height:1.6}
.cover-rule{width:56px;height:3px;background:linear-gradient(90deg,#0d9488,#2563eb);border-radius:2px;margin-bottom:30px}
.cover-grid{display:grid;grid-template-columns:1fr 1fr;border:1px solid rgba(255,255,255,.07);
  border-radius:10px;overflow:hidden;margin-bottom:30px}
.cg-cell{padding:14px 18px;border-bottom:1px solid rgba(255,255,255,.05);border-right:1px solid rgba(255,255,255,.05)}
.cg-cell:nth-child(even){border-right:none}
.cg-cell:nth-last-child(-n+2){border-bottom:none}
.cg-label{font-size:.57rem;text-transform:uppercase;letter-spacing:.1em;color:#4a6a8a;font-weight:700;margin-bottom:4px}
.cg-value{font-size:.84rem;font-weight:600;color:#d8e8f8}
.cover-badges{display:flex;gap:9px;flex-wrap:wrap}
.cb{display:inline-flex;align-items:center;gap:6px;padding:6px 13px;border-radius:20px;font-size:.64rem;font-weight:700;letter-spacing:.04em}
.cb-conf{background:rgba(220,166,0,.1);border:1px solid rgba(220,166,0,.28);color:#e0bc30}
.cb-ex{background:rgba(13,148,136,.1);border:1px solid rgba(13,148,136,.25);color:#0d9488}
.cover-bottom{padding:24px 48px;border-top:1px solid rgba(255,255,255,.06);
  display:flex;justify-content:space-between;align-items:center;position:relative;z-index:1}
.cover-bottom-copy{font-size:.62rem;color:#2a4a6a;line-height:1.6}
.cover-scores{display:flex;gap:22px}
.cs-item{text-align:center}
.cs-num{font-size:1.45rem;font-weight:900;line-height:1}
.cs-lbl{font-size:.56rem;text-transform:uppercase;letter-spacing:.1em;color:#3a5a7a;margin-top:2px}

/* ── inner page scaffolding ── */
.inner{padding:0 48px 28px;min-height:297mm;display:flex;flex-direction:column}
.ph{display:flex;justify-content:space-between;align-items:center;
  padding:16px 0 14px;border-bottom:1px solid #e8edf4;margin-bottom:24px}
.ph-left{display:flex;align-items:center;gap:16px}
.ph-logo{font-size:.78rem;font-weight:800;color:#0b1420}
.ph-logo span{color:#0d9488}
.ph-sep{width:1px;height:14px;background:#d0d8e4}
.ph-title{font-size:.68rem;font-weight:600;color:#4a6a8a}
.ph-right{display:flex;align-items:center;gap:16px}
.ph-endpoint{font-size:.62rem;color:#7a9ab8}
.ph-class{font-size:.58rem;font-weight:800;text-transform:uppercase;
  letter-spacing:.08em;color:#dc2626;background:#fff0f0;border:1px solid #fca5a5;padding:2px 8px;border-radius:3px}
.pf{margin-top:auto;padding-top:12px;border-top:1px solid #f0f4f8;
  display:flex;justify-content:space-between;align-items:center;font-size:.58rem;color:#9ab0c8}

/* ── section headings ── */
.stag{font-size:.57rem;text-transform:uppercase;letter-spacing:.2em;color:#0d9488;font-weight:700;margin-bottom:5px}
.stitle{font-size:1.28rem;font-weight:900;color:#0b1420;letter-spacing:-.025em;
  line-height:1.15;margin-bottom:16px;padding-left:13px;border-left:4px solid #0d9488}
h2{font-size:.88rem;font-weight:800;color:#0b1420;margin:18px 0 10px;letter-spacing:-.01em}
h3{font-size:.63rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#6e7681;margin:0 0 10px}
p{margin-bottom:9px;font-size:.82rem}

/* ── risk hero ── */
.risk-hero{background:linear-gradient(130deg,#0b1420 0%,#152338 100%);
  border-radius:13px;padding:24px 28px;margin-bottom:18px;
  display:flex;align-items:center;gap:28px;position:relative;overflow:hidden}
.rh-ring{position:absolute;right:-50px;top:-50px;width:200px;height:200px;
  border-radius:50%;border:28px solid rgba(255,255,255,.025)}
.rh-info{flex:1;min-width:0}

/* ── kpi cards ── */
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:18px}
.kpi{background:#fff;border:1px solid #e7eaf0;border-radius:10px;
  padding:15px 15px 13px;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:var(--c,#0d9488);border-radius:3px 3px 0 0}
.kpi-lbl{font-size:.57rem;text-transform:uppercase;letter-spacing:.1em;color:#9aa5b5;font-weight:700;margin-bottom:7px}
.kpi-val{font-size:1.55rem;font-weight:900;color:var(--c,#0d9488);letter-spacing:-.02em;line-height:1;margin-bottom:5px}
.kpi-sub{font-size:.61rem;color:#9aa5b5}
.kpi-bar{height:4px;background:#eef1f6;border-radius:2px;margin-top:7px;overflow:hidden}
.kpi-bar-fill{height:100%;border-radius:2px;background:var(--c,#0d9488)}

/* ── two-column ── */
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}
.col-card{background:#f7f9fc;border:1px solid #e8edf4;border-radius:10px;padding:16px 18px}
.stat-row{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #e8edf4}
.stat-row:last-child{border-bottom:none}
.stat-lbl{font-size:.78rem;color:#6b7689}
.stat-val{font-size:.78rem;font-weight:700;color:#0b1420}
.stat-val.ok{color:#0d9488}
.stat-val.fail{color:#da3633}
.stat-val.muted{color:#9aa9bc;font-weight:400}

/* ── callouts ── */
.callout{border-radius:8px;padding:11px 15px;margin-bottom:14px;font-size:.77rem;line-height:1.6;
  display:flex;gap:10px;align-items:flex-start}
.callout-icon{flex-shrink:0;margin-top:1px}
.co-ok{background:#f0fdf9;border:1px solid #d1fae5;color:#065f46}
.co-danger{background:#fff5f5;border:1px solid #fecaca;color:#991b1b}

/* ── status badge ── */
.sbadge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:12px;
  font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.sb-completed{background:#14532d;color:#86efac}
.sb-aborted,.sb-failed,.sb-cancelled{background:#7f1d1d;color:#fca5a5}
.sb-running{background:#1e3a5f;color:#93c5fd}
.sb-default,.sb-pending{background:#1e293b;color:#94a3b8}

/* ── tables ── */
table{width:100%;border-collapse:collapse;font-size:.77rem;margin-bottom:14px}
thead th{background:#f0f4f8;color:#5a7a9a;text-transform:uppercase;font-size:.57rem;
  letter-spacing:.08em;font-weight:700;text-align:left;padding:8px 11px;
  border-bottom:1.5px solid #e0e7ef}
td{padding:8px 11px;border-bottom:1px solid #f0f4f8;vertical-align:middle;color:#1a2332}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#f7f9fc}
tbody tr:nth-child(even) td{background:#fbfcfe}
.mono{font-family:monospace;font-size:.7rem;color:#5a7a9a;word-break:break-all}

/* ── timeline ── */
.tl-item{display:flex;gap:14px;padding:11px 0;border-bottom:1px solid #f0f4f8}
.tl-item:last-child{border-bottom:none}
.tl-icon-wrap{width:30px;height:30px;border-radius:50%;background:#f0f4f8;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.9rem;margin-top:1px}
.tl-body{flex:1;min-width:0}
.tl-summary{font-size:.82rem;font-weight:600;color:#1a2332;line-height:1.4;margin-bottom:2px}
.tl-ts{font-size:.62rem;color:#9aa9bc;font-family:monospace}
.tl-meta{font-size:.68rem;color:#9aa9bc;margin-top:3px}
.ev-info .tl-icon-wrap{background:#dbeafe;color:#1d4ed8}
.ev-warn .tl-icon-wrap{background:#fef3c7;color:#d97706}
.ev-success .tl-icon-wrap{background:#d1fae5;color:#059669}
.ev-danger .tl-icon-wrap{background:#fee2e2;color:#dc2626}
.ev-muted .tl-icon-wrap{background:#f3f4f6;color:#6b7280}
.ev-info .tl-summary{color:#1d4ed8}
.ev-warn .tl-summary{color:#b45309}
.ev-success .tl-summary{color:#065f46}
.ev-danger .tl-summary{color:#991b1b}
</style>
</head>
<body>

<!-- ══════════════════ COVER ══════════════════ -->
<div class="page">
<div class="cover">
  <div class="cover-grain"></div>
  <div class="cover-accent"></div>
  <div class="cover-accent2"></div>

  <div class="cover-header">
    <div class="clogo">
      <div class="clogo-mark">A</div>
      <div>
        <div class="clogo-name">Aud<span>spect</span> BAS</div>
        <div class="clogo-sub">Breach &amp; Attack Simulation Platform</div>
      </div>
    </div>
  </div>

  <div class="cover-body">
    <div class="cover-eyebrow">Cyber Crisis Exercise Report</div>
    <div class="cover-title">{{.Execution.Name}}</div>
    <div class="cover-sub">{{.Plan.Name}}<br>Post-Execution Assessment — Confidential</div>
    <div class="cover-rule"></div>

    <div class="cover-grid">
      <div class="cg-cell">
        <div class="cg-label">Execution ID</div>
        <div class="cg-value" style="font-size:.74rem;font-family:monospace">{{.Execution.ID}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Plan</div>
        <div class="cg-value">{{.Plan.Name}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Status</div>
        <div class="cg-value">
          {{$s := lower .Execution.Status}}<span class="sbadge sb-{{$s}}">{{.Execution.Status}}</span>
        </div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Evidence Chain</div>
        <div class="cg-value" style="color:{{if .ChainOK}}#0d9488{{else}}#da3633{{end}};font-weight:700">
          {{if .ChainOK}}&#10003; Intact{{else}}&#9888; Compromised{{end}}
        </div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Started</div>
        <div class="cg-value">{{if .Execution.StartedAt}}{{fmtTime .Execution.StartedAt}}{{else}}—{{end}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Completed</div>
        <div class="cg-value">{{if .Execution.CompletedAt}}{{fmtTime .Execution.CompletedAt}}{{else}}—{{end}}</div>
      </div>
    </div>

    <div class="cover-badges">
      <div class="cb cb-conf">&#9888; CONFIDENTIAL — Authorised Recipients Only</div>
      <div class="cb cb-ex">&#9654; Cyber Crisis Exercise &nbsp;&#183;&nbsp; Audspect BAS</div>
    </div>
  </div>

  <div class="cover-bottom">
    <div class="cover-bottom-copy">
      Audspect BAS Platform &nbsp;&#183;&nbsp; Classification: CONFIDENTIAL<br>
      This document contains sensitive exercise data. Do not distribute without authorisation.
    </div>
    {{if .Score}}
    <div class="cover-scores">
      <div class="cs-item">
        <div class="cs-num" style="color:{{scoreColor .Score.Overall}}">{{scoreBar .Score.Overall}}</div>
        <div class="cs-lbl">Overall Score</div>
      </div>
      <div class="cs-item">
        <div class="cs-num" style="color:#2563eb">{{len .Steps}}</div>
        <div class="cs-lbl">Steps</div>
      </div>
      <div class="cs-item">
        <div class="cs-num" style="color:#9aa9bc">{{len .Evidence}}</div>
        <div class="cs-lbl">Evidence</div>
      </div>
    </div>
    {{end}}
  </div>
</div>
</div>

<!-- ════════════════ SCORE SUMMARY ════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{.Execution.Name}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{.Plan.Name}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 1</div>
<div class="stitle">Exercise Score Summary</div>

{{if .Score}}
<div class="risk-hero">
  <div class="rh-ring"></div>
  <svg width="120" height="120" viewBox="0 0 100 100" style="flex-shrink:0">
    <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10"/>
    <circle cx="50" cy="50" r="44" fill="none"
      stroke="{{scoreColor .Score.Overall}}"
      stroke-width="10" stroke-linecap="round"
      stroke-dasharray="{{scoreArc .Score.Overall}} 276.46"
      transform="rotate(-90 50 50)"/>
    <text x="50" y="47" text-anchor="middle" fill="#fff" font-size="20" font-weight="700" font-family="system-ui,sans-serif">{{scoreBar .Score.Overall}}</text>
    <text x="50" y="61" text-anchor="middle" fill="rgba(255,255,255,0.4)" font-size="8" font-family="system-ui,sans-serif">/ 100</text>
  </svg>
  <div class="rh-info">
    <div style="color:rgba(255,255,255,0.45);font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">Overall Exercise Score</div>
    <div style="font-size:2.2rem;font-weight:900;color:{{scoreColor .Score.Overall}};line-height:1">
      {{scoreBar .Score.Overall}}<span style="font-size:1rem;color:rgba(255,255,255,0.3);font-weight:400"> / 100</span>
    </div>
    <div style="margin-top:12px;display:flex;gap:9px;flex-wrap:wrap">
      <span style="padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:600;background:rgba(37,99,235,0.15);color:#60a5fa;border:1px solid rgba(37,99,235,0.3)">&#128100; Human Risk</span>
      <span style="padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:600;background:rgba(13,148,136,0.15);color:#2dd4bf;border:1px solid rgba(13,148,136,0.3)">&#128737; Technical Detection</span>
      {{if .ChainOK}}<span style="padding:3px 10px;border-radius:20px;font-size:.72rem;font-weight:600;background:rgba(34,197,94,0.12);color:#4ade80;border:1px solid rgba(34,197,94,0.25)">&#128274; Chain Intact</span>{{end}}
    </div>
  </div>
</div>

<div class="kpi-row">
  <div class="kpi" style="--c:#da3633">
    <div class="kpi-lbl">Click Rate</div>
    <div class="kpi-val">{{pct .Score.Human.ClickRate}}</div>
    <div class="kpi-sub">{{.Score.Human.Clicked}} of {{.Score.Human.Sent}} recipients</div>
    <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{{pctInt .Score.Human.ClickRate}}%"></div></div>
  </div>
  <div class="kpi" style="--c:#0d9488">
    <div class="kpi-lbl">Report Rate</div>
    <div class="kpi-val">{{pct .Score.Human.ReportRate}}</div>
    <div class="kpi-sub">{{.Score.Human.Reported}} of {{.Score.Human.Sent}} reported</div>
    <div class="kpi-bar"><div class="kpi-bar-fill" style="width:{{pctInt .Score.Human.ReportRate}}%"></div></div>
  </div>
  <div class="kpi" style="--c:#2563eb">
    <div class="kpi-lbl">Mean Time to Detect</div>
    <div class="kpi-val" style="font-size:1.05rem">{{fmtDur .Score.Technical.MTTDSeconds}}</div>
    <div class="kpi-sub">incident → alert</div>
  </div>
  <div class="kpi" style="--c:#6366f1">
    <div class="kpi-lbl">Mean Time to Respond</div>
    <div class="kpi-val" style="font-size:1.05rem">{{fmtDur .Score.Technical.MTTRSeconds}}</div>
    <div class="kpi-sub">alert → containment</div>
  </div>
</div>

<div class="two-col">
  <div class="col-card">
    <h3>Human Risk</h3>
    <div class="stat-row"><span class="stat-lbl">Emails Sent</span><span class="stat-val">{{.Score.Human.Sent}}</span></div>
    <div class="stat-row"><span class="stat-lbl">Opened</span><span class="stat-val">{{.Score.Human.Opened}}</span></div>
    <div class="stat-row"><span class="stat-lbl">Clicked</span>
      <span class="stat-val {{if gt .Score.Human.ClickRate 0.3}}fail{{else}}ok{{end}}">{{.Score.Human.Clicked}}</span></div>
    <div class="stat-row"><span class="stat-lbl">Reported</span>
      <span class="stat-val {{if gt .Score.Human.ReportRate 0.5}}ok{{else}}fail{{end}}">{{.Score.Human.Reported}}</span></div>
    <div class="stat-row"><span class="stat-lbl">Click Rate</span>
      <span class="stat-val {{if gt .Score.Human.ClickRate 0.3}}fail{{else}}ok{{end}}">{{pct .Score.Human.ClickRate}}</span></div>
    <div class="stat-row"><span class="stat-lbl">Report Rate</span>
      <span class="stat-val {{if gt .Score.Human.ReportRate 0.5}}ok{{else}}fail{{end}}">{{pct .Score.Human.ReportRate}}</span></div>
  </div>
  <div class="col-card">
    <h3>Technical Detection</h3>
    <div class="stat-row"><span class="stat-lbl">EDR Detected</span>
      <span class="stat-val {{if .Score.Technical.EDRDetected}}ok{{else}}fail{{end}}">{{if .Score.Technical.EDRDetected}}Yes{{else}}No{{end}}</span></div>
    <div class="stat-row"><span class="stat-lbl">SIEM Alerted</span>
      <span class="stat-val {{if .Score.Technical.SIEMAlerted}}ok{{else}}fail{{end}}">{{if .Score.Technical.SIEMAlerted}}Yes{{else}}No{{end}}</span></div>
    <div class="stat-row"><span class="stat-lbl">Ticket Created</span>
      <span class="stat-val {{if .Score.Technical.TicketCreated}}ok{{else}}muted{{end}}">{{if .Score.Technical.TicketCreated}}Yes{{else}}—{{end}}</span></div>
    <div class="stat-row"><span class="stat-lbl">MTTD</span><span class="stat-val">{{fmtDur .Score.Technical.MTTDSeconds}}</span></div>
    <div class="stat-row"><span class="stat-lbl">MTTR</span><span class="stat-val">{{fmtDur .Score.Technical.MTTRSeconds}}</span></div>
  </div>
</div>
{{else}}
<p style="color:#9aa9bc;font-style:italic;padding:24px 0">Score not yet computed for this execution.</p>
{{end}}

<div class="pf">
  <span>Audspect BAS &mdash; Cyber Crisis Exercise</span>
  <span>{{.Execution.Name}}</span>
  <span>CONFIDENTIAL</span>
</div>
</div>
</div>

<!-- ════════════════ TIMELINE ════════════════ -->
{{if .Timeline}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{.Execution.Name}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">Exercise Timeline</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 2</div>
<div class="stitle">Exercise Timeline</div>

{{range .Timeline}}
{{$cls := evClass .Summary}}
<div class="tl-item {{$cls}}">
  <div class="tl-icon-wrap">{{kindIcon .Kind}}</div>
  <div class="tl-body">
    <div class="tl-summary">{{.Summary}}</div>
    <div class="tl-ts">{{fmtTime .TS}}</div>
    {{if or .Actor .StepID}}
    <div class="tl-meta">
      {{if .Actor}}actor: {{.Actor}}{{end}}{{if and .Actor .StepID}} &middot; {{end}}{{if .StepID}}step: {{.StepID}}{{end}}{{if .StepType}} ({{.StepType}}){{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

<div class="pf">
  <span>Audspect BAS &mdash; Cyber Crisis Exercise</span>
  <span>{{.Execution.Name}}</span>
  <span>CONFIDENTIAL</span>
</div>
</div>
</div>
{{end}}

<!-- ════════════ STEPS + EVIDENCE ════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{.Execution.Name}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">Steps &amp; Evidence Chain</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 3</div>
<div class="stitle">Step Results</div>

{{if .Steps}}
<table>
  <thead><tr><th>#</th><th>Step ID</th><th>Type</th><th>Status</th><th>Started</th><th>Completed</th></tr></thead>
  <tbody>
  {{range $i, $s := .Steps}}
  {{$lc := lower $s.Status}}
  <tr>
    <td style="color:#9aa9bc">{{seq $i}}</td>
    <td style="font-family:monospace;font-size:.72rem">{{$s.StepID}}</td>
    <td style="color:#6b7689">{{$s.StepType}}</td>
    <td><span class="sbadge sb-{{$lc}}">{{$s.Status}}</span></td>
    <td style="color:#6b7689;font-size:.72rem">{{if $s.StartedAt}}{{fmtTime $s.StartedAt}}{{else}}—{{end}}</td>
    <td style="color:#6b7689;font-size:.72rem">{{if $s.CompletedAt}}{{fmtTime $s.CompletedAt}}{{else}}—{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#9aa9bc;font-style:italic">No step records for this execution.</p>
{{end}}

<div class="stag" style="margin-top:24px">Section 4</div>
<div class="stitle">Evidence Chain</div>

{{if .ChainOK}}
<div class="callout co-ok">
  <span class="callout-icon">&#128274;</span>
  <span>Evidence chain is intact — all {{len .Evidence}} record(s) verified successfully. No tampering detected.</span>
</div>
{{else}}
<div class="callout co-danger">
  <span class="callout-icon">&#9888;</span>
  <span><strong>Chain integrity failure:</strong> {{.ChainErr}}</span>
</div>
{{end}}

{{if .Evidence}}
<table>
  <thead><tr><th>Seq</th><th>Type</th><th>Actor</th><th>SHA-256 (truncated)</th><th>Prev Hash</th><th>Timestamp</th></tr></thead>
  <tbody>
  {{range .Evidence}}
  <tr>
    <td style="color:#9aa9bc">{{.Seq}}</td>
    <td>{{.EvidenceType}}</td>
    <td>{{.Actor}}</td>
    <td class="mono">{{truncate .SHA256 20}}</td>
    <td class="mono">{{truncate .PrevHash 20}}</td>
    <td style="color:#6b7689;font-size:.72rem">{{fmtTime .CreatedAt}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<div class="pf">
  <span>Audspect BAS &mdash; Cyber Crisis Exercise</span>
  <span>{{.Execution.Name}}</span>
  <span>CONFIDENTIAL</span>
</div>
</div>
</div>

</body>
</html>
`
