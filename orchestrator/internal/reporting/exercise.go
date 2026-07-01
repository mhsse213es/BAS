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
	Kind     string    `json:"kind"`    // "event", "evidence", "step"
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
		"lower":    strings.ToLower,
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
	}).Parse(exerciseReportTmpl)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}
	return t.Execute(w, rep)
}

// ── PDF export ────────────────────────────────────────────────────────────────

// ExerciseReportPDF renders the HTML report and prints it to PDF.
// Uses the Chrome sidecar if available, returns an error otherwise.
func ExerciseReportPDF(ctx context.Context, w io.Writer, rep *ExerciseReport) error {
	var buf bytes.Buffer
	if err := ExerciseReportHTML(&buf, rep); err != nil {
		return fmt.Errorf("render HTML: %w", err)
	}
	pdf, err := htmlToPDF(ctx, buf.Bytes())
	if err != nil {
		return fmt.Errorf("html→pdf: %w", err)
	}
	_, err = w.Write(pdf)
	return err
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
<title>Exercise Report — {{.Execution.Name}}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  body { font-family: Inter, system-ui, sans-serif; background: #f6f8fa; color: #1e293b; font-size: 13px; line-height: 1.5; }

  /* ── Cover ── */
  .cover { background: #0b1420; color: #fff; padding: 56px 48px 40px; page-break-after: always; }
  .cover .logo { font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: #9aa9bc; margin-bottom: 48px; }
  .cover h1 { font-size: 32px; font-weight: 700; margin-bottom: 8px; }
  .cover .subtitle { font-size: 15px; color: #9aa9bc; margin-bottom: 48px; }
  .cover-meta { display: flex; gap: 48px; flex-wrap: wrap; }
  .cover-meta dt { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #9aa9bc; margin-bottom: 2px; }
  .cover-meta dd { font-size: 13px; color: #e2e8f0; font-weight: 500; }
  .status-badge {
    display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: .5px;
  }
  .status-completed { background: #14532d; color: #86efac; }
  .status-aborted   { background: #7f1d1d; color: #fca5a5; }
  .status-running   { background: #1e3a5f; color: #93c5fd; }
  .status-default   { background: #1e293b; color: #94a3b8; }

  /* ── Layout ── */
  .page { padding: 40px 48px; }
  h2 { font-size: 18px; font-weight: 700; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #22324a; }
  h3 { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; color: #9aa9bc; margin-bottom: 12px; }
  .section { margin-bottom: 40px; }

  /* ── Score cards ── */
  .score-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
  .score-card { background: #152338; border: 1px solid #22324a; border-radius: 8px; padding: 20px; }
  .score-card-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #9aa9bc; margin-bottom: 16px; }
  .score-num { font-size: 36px; font-weight: 700; color: #2f81f7; line-height: 1; }
  .score-label { font-size: 11px; color: #9aa9bc; margin-top: 4px; }
  .stat-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #22324a; }
  .stat-row:last-child { border: 0; }
  .stat-label { color: #9aa9bc; }
  .stat-val { font-weight: 500; }
  .ok   { color: #238636; }
  .fail { color: #da3633; }
  .muted { color: #9aa9bc; }

  /* ── Progress bar ── */
  .bar-wrap { height: 6px; background: #22324a; border-radius: 3px; margin-top: 12px; }
  .bar-fill  { height: 6px; border-radius: 3px; background: #2f81f7; }

  /* ── Timeline ── */
  .timeline { list-style: none; }
  .timeline li { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid #22324a; }
  .tl-ts    { width: 180px; flex-shrink: 0; font-family: monospace; font-size: 11px; color: #9aa9bc; padding-top: 2px; }
  .tl-icon  { width: 20px; flex-shrink: 0; text-align: center; }
  .tl-body  { flex: 1; }
  .tl-summary { font-weight: 500; }
  .tl-meta    { font-size: 11px; color: #9aa9bc; margin-top: 2px; }
  .ev-info    { color: #2f81f7; }
  .ev-warn    { color: #d29922; }
  .ev-success { color: #238636; }
  .ev-danger  { color: #da3633; }
  .ev-muted   { color: #9aa9bc; }

  /* ── Evidence table ── */
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; padding: 8px; background: #152338; color: #9aa9bc; font-weight: 600;
       text-transform: uppercase; letter-spacing: .5px; font-size: 10px; }
  td { padding: 8px; border-bottom: 1px solid #22324a; vertical-align: top; }
  tr:last-child td { border-bottom: 0; }
  .mono { font-family: monospace; font-size: 10px; word-break: break-all; color: #9aa9bc; }

  /* ── Chain verification ── */
  .chain-ok   { background: #0d2d0f; border: 1px solid #238636; border-radius: 6px; padding: 12px 16px; color: #4ade80; }
  .chain-fail { background: #2d0f0f; border: 1px solid #da3633; border-radius: 6px; padding: 12px 16px; color: #f87171; }

  /* ── Print ── */
  @media print {
    body { background: #fff; }
    .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .score-card { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .page-break { page-break-before: always; }
  }
</style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <div class="logo">Audspect · Exercise Report</div>
  <h1>{{.Execution.Name}}</h1>
  <div class="subtitle">Cyber Crisis Exercise — Post-Execution Report</div>
  <dl class="cover-meta">
    <div>
      <dt>Execution ID</dt>
      <dd>{{.Execution.ID}}</dd>
    </div>
    <div>
      <dt>Plan</dt>
      <dd>{{.Plan.Name}}</dd>
    </div>
    <div>
      <dt>Status</dt>
      <dd>
        {{$s := lower .Execution.Status}}
        <span class="status-badge status-{{$s}}">{{.Execution.Status}}</span>
      </dd>
    </div>
    {{if .Execution.StartedAt}}<div>
      <dt>Started</dt>
      <dd>{{fmtTime .Execution.StartedAt}}</dd>
    </div>{{end}}
    {{if .Execution.CompletedAt}}<div>
      <dt>Completed</dt>
      <dd>{{fmtTime .Execution.CompletedAt}}</dd>
    </div>{{end}}
    <div>
      <dt>Evidence Chain</dt>
      <dd>{{if .ChainOK}}✅ Intact{{else}}⚠ {{.ChainErr}}{{end}}</dd>
    </div>
  </dl>
</div>

<!-- Score Summary -->
<div class="page section">
  <h2>Exercise Score</h2>
  {{if .Score}}
  <div class="score-grid">
    <!-- Overall -->
    <div class="score-card">
      <div class="score-card-title">Overall</div>
      <div class="score-num">{{scoreBar .Score.Overall}}</div>
      <div class="score-label">/ 100</div>
      <div class="bar-wrap"><div class="bar-fill" style="width:{{scoreBar .Score.Overall}}%"></div></div>
    </div>

    <!-- Human Risk -->
    <div class="score-card">
      <div class="score-card-title">Human Risk</div>
      <div class="stat-row"><span class="stat-label">Sent</span><span class="stat-val">{{.Score.Human.Sent}}</span></div>
      <div class="stat-row"><span class="stat-label">Opened</span><span class="stat-val">{{.Score.Human.Opened}}</span></div>
      <div class="stat-row"><span class="stat-label">Clicked</span><span class="stat-val">{{.Score.Human.Clicked}}</span></div>
      <div class="stat-row"><span class="stat-label">Reported</span><span class="stat-val">{{.Score.Human.Reported}}</span></div>
      <div class="stat-row"><span class="stat-label">Click Rate</span><span class="stat-val {{if gt .Score.Human.ClickRate 0.3}}fail{{else}}ok{{end}}">{{pct .Score.Human.ClickRate}}</span></div>
      <div class="stat-row"><span class="stat-label">Report Rate</span><span class="stat-val {{if gt .Score.Human.ReportRate 0.5}}ok{{else}}fail{{end}}">{{pct .Score.Human.ReportRate}}</span></div>
    </div>

    <!-- Technical -->
    <div class="score-card">
      <div class="score-card-title">Technical Detection</div>
      <div class="stat-row"><span class="stat-label">EDR Detected</span>
        <span class="stat-val {{if .Score.Technical.EDRDetected}}ok{{else}}fail{{end}}">{{if .Score.Technical.EDRDetected}}Yes{{else}}No{{end}}</span></div>
      <div class="stat-row"><span class="stat-label">SIEM Alerted</span>
        <span class="stat-val {{if .Score.Technical.SIEMAlerted}}ok{{else}}fail{{end}}">{{if .Score.Technical.SIEMAlerted}}Yes{{else}}No{{end}}</span></div>
      <div class="stat-row"><span class="stat-label">Ticket Created</span>
        <span class="stat-val {{if .Score.Technical.TicketCreated}}ok{{else}}muted{{end}}">{{if .Score.Technical.TicketCreated}}Yes{{else}}—{{end}}</span></div>
      <div class="stat-row"><span class="stat-label">MTTD</span>
        <span class="stat-val">{{fmtDur .Score.Technical.MTTDSeconds}}</span></div>
      <div class="stat-row"><span class="stat-label">MTTR</span>
        <span class="stat-val">{{fmtDur .Score.Technical.MTTRSeconds}}</span></div>
    </div>
  </div>
  {{else}}<p class="muted">Score not yet computed.</p>{{end}}
</div>

<!-- Timeline -->
<div class="page section page-break">
  <h2>Exercise Timeline</h2>
  {{if .Timeline}}
  <ul class="timeline">
    {{range .Timeline}}
    <li>
      <span class="tl-ts">{{fmtTime .TS}}</span>
      <span class="tl-icon">{{kindIcon .Kind}}</span>
      <div class="tl-body">
        <div class="tl-summary {{evClass .Summary}}">{{.Summary}}</div>
        {{if .Actor}}<div class="tl-meta">actor: {{.Actor}}{{if .StepID}} · step: {{.StepID}}{{end}}</div>{{end}}
      </div>
    </li>
    {{end}}
  </ul>
  {{else}}<p class="muted">No timeline events.</p>{{end}}
</div>

<!-- Steps Summary -->
<div class="page section page-break">
  <h2>Step Results</h2>
  {{if .Steps}}
  <table>
    <thead><tr><th>#</th><th>Step ID</th><th>Type</th><th>Status</th><th>Started</th><th>Completed</th></tr></thead>
    <tbody>
    {{range $i, $s := .Steps}}
    <tr>
      <td>{{seq $i}}</td>
      <td>{{$s.StepID}}</td>
      <td>{{$s.StepType}}</td>
      <td class="{{evClass (lower $s.Status)}}">{{$s.Status}}</td>
      <td>{{if $s.StartedAt}}{{fmtTime $s.StartedAt}}{{else}}—{{end}}</td>
      <td>{{if $s.CompletedAt}}{{fmtTime $s.CompletedAt}}{{else}}—{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<p class="muted">No steps recorded.</p>{{end}}
</div>

<!-- Evidence Chain -->
<div class="page section page-break">
  <h2>Evidence Chain</h2>
  <div class="{{if .ChainOK}}chain-ok{{else}}chain-fail{{end}}" style="margin-bottom:24px;">
    {{if .ChainOK}}✅ Evidence chain is intact — all {{len .Evidence}} record(s) verified.
    {{else}}⚠ Chain integrity failure: {{.ChainErr}}{{end}}
  </div>
  {{if .Evidence}}
  <table>
    <thead><tr><th>Seq</th><th>Type</th><th>Actor</th><th>SHA-256</th><th>Prev Hash</th><th>Time</th></tr></thead>
    <tbody>
    {{range .Evidence}}
    <tr>
      <td>{{.Seq}}</td>
      <td>{{.EvidenceType}}</td>
      <td>{{.Actor}}</td>
      <td class="mono">{{.SHA256}}</td>
      <td class="mono">{{.PrevHash}}</td>
      <td>{{fmtTime .CreatedAt}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</div>

</body>
</html>
`
