package reporting

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
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
	"addInt": func(a, b float64) int { return int(a) + int(b) },
	"filterLabel": func(f string) string {
		switch f {
		case "prevented":
			return "Prevented Only"
		case "not_prevented":
			return "Not Prevented"
		case "detected":
			return "Detected Only"
		case "not_detected":
			return "Not Detected"
		}
		return f
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
	// Detection Validation Pack — expected-detection status colour/label.
	"dvStatusColor": func(s string) string {
		switch s {
		case "Detected":
			return "#0d9488"
		case "NotDetected":
			return "#da3633"
		case "Pending":
			return "#d29922"
		}
		return "#6e7681" // Unknown / NotApplicable
	},
	"dvStatusLabel": func(s string) string {
		switch s {
		case "Detected":
			return "DETECTED"
		case "NotDetected":
			return "SILENT"
		case "Pending":
			return "PENDING"
		case "Unknown":
			return "UNKNOWN"
		case "NotApplicable":
			return "N/A"
		}
		return s
	},
	"upper":    strings.ToUpper,
	"lower":    strings.ToLower,
	"add1":     func(i int) int { return i + 1 },
	"humanize": humanizeTactic,
	// join renders a []string report field as a comma-separated list. It also
	// accepts []any because the template executes against a json-round-tripped
	// map[string]any (see GenerateHTML) — a JSON array always decodes as []any
	// regardless of the source Go field's static type — and nil/absent so a
	// missing key doesn't abort the render.
	"join": func(v any) string {
		switch s := v.(type) {
		case []string:
			return strings.Join(s, ", ")
		case []any:
			parts := make([]string, 0, len(s))
			for _, e := range s {
				if str, ok := e.(string); ok {
					parts = append(parts, str)
				} else {
					parts = append(parts, fmt.Sprint(e))
				}
			}
			return strings.Join(parts, ", ")
		}
		return ""
	},
	// str coerces a template value to a string, defaulting to "" for nil or a
	// non-string type — used to guard builtin `eq` comparisons (e.g.
	// {{eq (str .cleanupVerdict) "reverted"}}) against a missing/omitempty map
	// key, which otherwise surfaces as a nil interface and errors `eq` outright.
	"str": func(v any) string {
		s, _ := v.(string)
		return s
	},
	// num coerces a template value to float64, defaulting to 0 for nil or a
	// non-numeric type — used to guard builtin `gt`/`lt` comparisons against a
	// missing/omitempty map key (numbers decode as float64 in the report map).
	"num": func(v any) float64 {
		f, _ := v.(float64)
		return f
	},
	// techActors returns up to 3 ATT&CK group names that use the given technique ID,
	// or nil when none are found in the bundled STIX data.
	"techActors": func(techID string) []string {
		e := attackdata.Lookup(techID)
		if e == nil || len(e.Groups) == 0 {
			return nil
		}
		if len(e.Groups) <= 3 {
			return e.Groups
		}
		return e.Groups[:3]
	},
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
	// cleanupVerdictColor maps a cleanup verdict to a CSS color. Accepts any
	// because CleanupVerdict is omitempty (engine.go) — an empty/absent verdict
	// arrives as a missing map key, i.e. a nil interface{}, not a "" string.
	"cleanupVerdictColor": func(v any) string {
		s, _ := v.(string)
		switch s {
		case "reverted":
			return "#0d9488" // green — cleanup command succeeded
		case "partial":
			return "#d29922" // amber — non-zero exit, artifacts may remain
		case "leaked":
			return "#da3633" // red — cleanup timed out or failed to start
		}
		return "#6e7681" // grey — no cleanup defined
	},
	// cleanupVerdictLabel maps a cleanup verdict to a display label. Accepts
	// any for the same reason as cleanupVerdictColor above.
	"cleanupVerdictLabel": func(v any) string {
		s, _ := v.(string)
		switch s {
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
	// contains reports whether substr appears in s (used for privilege fallback detection).
	"contains": func(s, substr string) bool { return strings.Contains(s, substr) },
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
	"verdictBg": func(v string) string {
		switch v {
		case "pass":
			return "#238636"
		case "fail":
			return "#da3633"
		case "error":
			return "#d29922"
		case "skipped":
			return "#6e7681"
		}
		return "#6e7681"
	},
	"verdictColor": func(string) string { return "#ffffff" },
	// scoreArc returns the stroke-dasharray offset for a donut arc where the
	// full circumference is 276.46 (r=44 circle: 2π×44≈276.46). score is 0-100.
	"scoreArc": func(score float64) float64 {
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		return 276.46 * score / 100.0
	},
	// tacticAccent returns a consistent accent color per ATT&CK tactic slug,
	// used in kill chain strips and tactic chips.
	"tacticAccent": func(tactic string) string {
		switch strings.ToLower(strings.TrimSpace(tactic)) {
		case "initial-access":
			return "#c0392b"
		case "execution":
			return "#e74c3c"
		case "persistence":
			return "#e67e22"
		case "privilege-escalation":
			return "#f39c12"
		case "defense-evasion":
			return "#d35400"
		case "credential-access":
			return "#8e44ad"
		case "discovery":
			return "#2980b9"
		case "lateral-movement":
			return "#16a085"
		case "collection":
			return "#1abc9c"
		case "command-and-control":
			return "#27ae60"
		case "exfiltration":
			return "#2c3e50"
		case "impact":
			return "#7f8c8d"
		case "resource-development":
			return "#6c5ce7"
		case "reconnaissance":
			return "#0984e3"
		}
		return "#6e7681"
	},
	"agentStatusColor": func(status string) string {
		switch strings.ToLower(strings.TrimSpace(status)) {
		case "active", "online":
			return "#0d9488"
		case "idle":
			return "#d29922"
		default:
			return "#6e7681"
		}
	},
	// sumInts sums any number of JSON-decoded numeric values (float64) into an int.
	"sumInts": func(vals ...any) int {
		total := 0
		for _, v := range vals {
			if f, ok := v.(float64); ok {
				total += int(f)
			}
		}
		return total
	},
	// privConclusion returns a one-sentence executive assessment of a technique's
	// privilege context: what it means that it ran (or was blocked) at that tier.
	"privConclusion": func(executedAs, verdict any) string {
		ea := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", executedAs)))
		v := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", verdict)))
		blocked := v == "pass" || v == "blocked"
		switch {
		case ea == "user" && blocked:
			return "✅ Blocked at standard-user level — controls prevented this technique even without requiring elevated privileges."
		case ea == "user" && !blocked:
			return "⚠️ Succeeded without administrator privileges. This technique is exploitable from any initial-access scenario — phishing, malicious document, or compromised standard account — before privilege escalation occurs. Prioritise remediation."
		case (ea == "admin" || ea == "system") && blocked:
			return "✅ Blocked even at elevated privilege — controls are effective regardless of execution context. Strong prevention signal."
		case (ea == "admin" || ea == "system") && !blocked:
			return "⚠️ Requires elevated privileges to succeed. An attacker must first escalate from a standard user account before this technique becomes feasible. Focus on preventing privilege escalation and securing administrator credentials."
		case strings.Contains(ea, "→") && !blocked:
			return "⚠️ Tested under admin fallback — no interactive user session was active at execution time. Re-run with a logged-in standard user to confirm whether this technique is accessible without elevation."
		default:
			if !blocked && (ea == "legacy" || ea == "") {
				return "ℹ️ Privilege context not annotated for this step. Re-run with privilege annotation (requires_priv in the scenario YAML) to determine whether this technique is accessible to standard users."
			}
		}
		return ""
	},
	// privSummaryConclusion returns an executive-grade paragraph summarising the
	// overall privilege posture from the PrivilegeSummary map (JSON-decoded).
	"privSummaryConclusion": func(ps any) string {
		m, ok := ps.(map[string]any)
		if !ok {
			return ""
		}
		getInt := func(key string) int {
			f, _ := m[key].(float64)
			return int(f)
		}
		user := getInt("user")
		admin := getInt("admin")
		system := getInt("system")
		userPrev := getInt("userPrevented")
		fallbacks := getInt("fallbacks")
		if user == 0 && admin == 0 && system == 0 {
			return ""
		}
		userFailed := user - userPrev
		elevTotal := admin + system
		var sb strings.Builder
		switch {
		case userFailed > 0 && elevTotal > 0:
			sb.WriteString(fmt.Sprintf("⚠️ %d technique(s) succeeded from a standard user account — exploitable immediately after initial access, before any privilege escalation. Additionally, %d technique(s) required elevated privileges to succeed.", userFailed, elevTotal))
		case userFailed > 0:
			sb.WriteString(fmt.Sprintf("⚠️ %d technique(s) succeeded from a standard user account without requiring elevation. These are exploitable from any phishing or drive-by initial-access scenario. Prioritise their remediation.", userFailed))
		case user > 0 && userFailed == 0 && elevTotal > 0:
			sb.WriteString(fmt.Sprintf("✅ All standard-user attempts were blocked. %d technique(s) required elevated privileges to succeed — preventing privilege escalation is the primary control priority.", elevTotal))
		case user > 0 && userFailed == 0 && elevTotal == 0:
			sb.WriteString("✅ All tested techniques were blocked across all privilege tiers. Controls are effective regardless of execution context.")
		case user == 0 && elevTotal > 0:
			sb.WriteString(fmt.Sprintf("All %d successful technique(s) required elevated privileges — an attacker must first escalate from a standard user account before these become feasible. Preventing privilege escalation is the primary control priority.", elevTotal))
		}
		if fallbacks > 0 {
			sb.WriteString(fmt.Sprintf(" Note: %d step(s) fell back to admin context (no interactive user session was active). Re-run with a logged-in standard user to verify standard-user coverage.", fallbacks))
		}
		return sb.String()
	},
}).Parse(reportHTML))

// ── Logo helpers ──────────────────────────────────────────────────────────────

var (
	_logoLight    string
	_logoDark     string
	_logoLoadOnce sync.Once
	_wwwRootDir   string
)

// SetWWWRoot tells the reporting engine exactly where wwwroot lives on disk.
// Call once from main() right after resolveWWWRoot() so the logo loader uses
// the same verified path as the static file server — zero path guessing.
func SetWWWRoot(dir string) { _wwwRootDir = dir }

// _loadLogos reads the Audspect logo PNGs from wwwroot and converts them to
// inline base64 data URIs so the HTML report is self-contained (Chromium
// sidecar cannot access local file:// paths). Called at most once per process.
func _loadLogos() {
	// _wwwRootDir is set by SetWWWRoot() from the same resolveWWWRoot() call
	// that serves static files — if it's non-empty it's guaranteed to exist.
	// /wwwroot is the absolute Docker container path (bind-mounted by compose).
	// The relative paths are fallbacks for local dev.
	candidates := []string{_wwwRootDir, "/wwwroot", "./wwwroot", "../../wwwroot", "../wwwroot"}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		lightPath := filepath.Join(candidate, "images", "logo_name.png")
		data, err := os.ReadFile(lightPath)
		if err != nil {
			continue
		}
		_logoLight = "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)
		if dark, err2 := os.ReadFile(filepath.Join(candidate, "images", "logo.png")); err2 == nil {
			_logoDark = "data:image/png;base64," + base64.StdEncoding.EncodeToString(dark)
		}
		return
	}
}

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
	_logoLoadOnce.Do(_loadLogos)
	data["logoLightUri"] = _logoLight
	data["logoDarkUri"] = _logoDark
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

const reportHTML = `{{define "pf-right"}}{{if or .agent.ipAddress .agent.status}}<span>{{if .agent.ipAddress}}{{.agent.ipAddress}}&nbsp;&middot;&nbsp;{{end}}{{if .agent.status}}<span style="color:{{agentStatusColor .agent.status}}">&#9679;</span>&nbsp;{{.agent.status}}&nbsp;&middot;&nbsp;{{end}}Audspect&nbsp;BAS</span>{{end}}{{end}}
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BAS Security Assessment Report — {{.agent.hostname}}</title>
<style>
/* ── Reset ── */
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact;font-size:13px}
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;
  color:#1a2332;background:#fff;line-height:1.6;
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
code{font-family:"Cascadia Code","Consolas","SF Mono",monospace;font-size:0.85em}
:root{--line:#e8edf4;--line2:#eef1f6;--surface:#f7f9fc;--navy:#0b1420;--ink:#1a2332;--accent:#2563eb;--teal:#0d9488;--muted:#6b7689;--faint:#9aa5b5}

/* ── Page ── */
.page{width:210mm;min-height:297mm;margin:0 auto;background:#fff;
  position:relative;page-break-after:always;break-after:page;overflow:hidden}
.page:last-child{page-break-after:avoid;break-after:avoid}
@media screen{body{background:#c8d0da;padding:24px 0}
  .page{box-shadow:0 6px 32px rgba(0,0,0,0.22);margin:0 auto 28px;border-radius:2px}}
@media print{body{background:#fff;padding:0}
  .page{width:100%;margin:0;box-shadow:none;overflow:visible}
  .fc,.scard,.gloss-item{page-break-inside:avoid;break-inside:avoid}
  thead{display:table-header-group}
  .ph,.pf{page-break-inside:avoid}}
@media screen and (max-width:700px){
  body{padding:0}
  .page{width:100%;min-height:unset;overflow:visible;border-radius:0;box-shadow:none;margin:0 0 16px}
  .inner{padding:0 16px 20px;min-height:unset}
  .cover{min-height:unset;padding-bottom:24px}
  .kpi-row{grid-template-columns:1fr 1fr}
  .score-row{grid-template-columns:1fr 1fr}
  .fc-grid{grid-template-columns:1fr}
  .cover-grid{grid-template-columns:1fr}
  .risk-hero{flex-direction:column;gap:12px}
  table{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}
  .hm{min-width:unset;flex-wrap:wrap}
}

/* ── Cover ── */
.cover{background:#0b1420;min-height:297mm;display:flex;flex-direction:column;position:relative}
.cover-grain{position:absolute;inset:0;opacity:0.03;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size:200px}
.cover-accent{position:absolute;right:-100px;top:-100px;width:520px;height:520px;
  border-radius:50%;border:70px solid rgba(13,148,136,0.07);pointer-events:none}
.cover-accent2{position:absolute;right:40px;bottom:80px;width:280px;height:280px;
  border-radius:50%;border:40px solid rgba(37,99,235,0.05);pointer-events:none}
.cover-header{padding:40px 48px 0;position:relative;z-index:1}
.clogo{display:flex;align-items:center;gap:11px}
.clogo-mark{width:34px;height:34px;background:linear-gradient(135deg,#0d9488 0%,#2563eb 100%);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:15px;color:#fff;flex-shrink:0}
.clogo-name{font-size:1.15rem;font-weight:800;color:#fff;letter-spacing:-0.03em}
.clogo-name span{color:#0d9488}
.clogo-sub{font-size:0.58rem;text-transform:uppercase;letter-spacing:0.16em;color:#4a6a8a;margin-top:1px}
.cover-body{flex:1;padding:0 48px;display:flex;flex-direction:column;justify-content:center;
  position:relative;z-index:1}
.cover-eyebrow{font-size:0.62rem;text-transform:uppercase;letter-spacing:0.2em;
  color:#0d9488;font-weight:700;margin-bottom:12px}
.cover-title{font-size:2.8rem;font-weight:900;color:#fff;letter-spacing:-0.04em;
  line-height:1.02;margin-bottom:8px}
.cover-sub{font-size:0.95rem;color:#6a8aaa;margin-bottom:32px;line-height:1.6}
.cover-rule{width:56px;height:3px;background:linear-gradient(90deg,#0d9488,#2563eb);
  border-radius:2px;margin-bottom:30px}
.cover-grid{display:grid;grid-template-columns:1fr 1fr;border:1px solid rgba(255,255,255,0.07);
  border-radius:10px;overflow:hidden;margin-bottom:30px}
.cg-cell{padding:14px 18px;border-bottom:1px solid rgba(255,255,255,0.05);
  border-right:1px solid rgba(255,255,255,0.05)}
.cg-cell:nth-child(even){border-right:none}
.cg-cell:nth-last-child(-n+2){border-bottom:none}
.cg-label{font-size:0.57rem;text-transform:uppercase;letter-spacing:0.1em;
  color:#4a6a8a;font-weight:700;margin-bottom:4px}
.cg-value{font-size:0.84rem;font-weight:600;color:#d8e8f8}
.cover-badges{display:flex;gap:9px;flex-wrap:wrap}
.cb{display:inline-flex;align-items:center;gap:6px;padding:6px 13px;
  border-radius:20px;font-size:0.64rem;font-weight:700;letter-spacing:0.04em}
.cb-conf{background:rgba(220,166,0,0.1);border:1px solid rgba(220,166,0,0.28);color:#e0bc30}
.cb-live{background:rgba(13,148,136,0.1);border:1px solid rgba(13,148,136,0.25);color:#0d9488}
.filter-badge{display:inline-flex;align-items:center;gap:7px;
  background:rgba(37,99,235,0.1);color:#60a5fa;border:1px solid rgba(37,99,235,0.3);
  padding:6px 13px;border-radius:20px;font-size:0.72rem;font-weight:700;letter-spacing:0.03em;margin-top:14px}
.cover-bottom{padding:24px 48px;border-top:1px solid rgba(255,255,255,0.06);
  display:flex;justify-content:space-between;align-items:center;position:relative;z-index:1}
.cover-bottom-copy{font-size:0.62rem;color:#2a4a6a;line-height:1.6}
.cover-scores{display:flex;gap:22px}
.cs-item{text-align:center}
.cs-num{font-size:1.45rem;font-weight:900;line-height:1}
.cs-lbl{font-size:0.56rem;text-transform:uppercase;letter-spacing:0.1em;color:#3a5a7a;margin-top:2px}

/* ── Inner Page Scaffolding ── */
.inner{padding:0 48px 28px;min-height:297mm;display:flex;flex-direction:column}
.ph{display:flex;justify-content:space-between;align-items:center;
  padding:16px 0 14px;border-bottom:1px solid #e8edf4;margin-bottom:24px}
.ph-left{display:flex;align-items:center;gap:16px}
.ph-logo{font-size:0.78rem;font-weight:800;color:#0b1420}
.ph-logo span{color:#0d9488}
.ph-sep{width:1px;height:14px;background:#d0d8e4}
.ph-title{font-size:0.68rem;font-weight:600;color:#4a6a8a}
.ph-right{display:flex;align-items:center;gap:16px}
.ph-endpoint{font-size:0.62rem;color:#7a9ab8}
.ph-class{font-size:0.58rem;font-weight:800;text-transform:uppercase;
  letter-spacing:0.08em;color:#dc2626;background:#fff0f0;border:1px solid #fca5a5;
  padding:2px 8px;border-radius:3px}
.pf{margin-top:auto;padding-top:12px;border-top:1px solid #f0f4f8;
  display:flex;justify-content:space-between;align-items:center;font-size:0.58rem;color:#9ab0c8}
/* legacy footer alias */
.footer{margin-top:auto;padding-top:12px;border-top:1px solid #f0f4f8;
  display:flex;justify-content:space-between;align-items:center;font-size:0.58rem;color:#9ab0c8}

/* ── Section headings ── */
.stag{font-size:0.57rem;text-transform:uppercase;letter-spacing:0.2em;color:#0d9488;font-weight:700;margin-bottom:5px}
.stitle{font-size:1.28rem;font-weight:900;color:#0b1420;letter-spacing:-0.025em;
  line-height:1.15;margin-bottom:16px;padding-left:13px;border-left:4px solid #0d9488}
h1{font-size:1.28rem;font-weight:900;color:#0b1420;letter-spacing:-0.025em;
  line-height:1.15;margin:0 0 16px;padding-left:13px;border-left:4px solid #0d9488}
.toc-list{display:flex;flex-direction:column;margin-top:8px}
.toc-item{display:flex;align-items:baseline;gap:14px;padding:9px 0;
  border-bottom:1px solid var(--line2);text-decoration:none;color:var(--ink)}
.toc-item:hover{color:var(--accent)}
.toc-num{font-size:0.7rem;font-weight:700;color:var(--muted);min-width:28px;flex-shrink:0}
.toc-title{font-size:0.86rem;font-weight:600}
h2{font-size:0.88rem;font-weight:800;color:#0b1420;margin:18px 0 10px;letter-spacing:-0.01em}
h3{font-size:0.63rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#6e7681;margin:14px 0 7px}
p{margin-bottom:9px;font-size:0.82rem}
em{color:#6e7681;font-style:normal}
strong{font-weight:700}
a{color:#2563eb;text-decoration:none}

/* ── Narrative box ── */
.narrative{background:#f8faff;border:1px solid #dce8f8;border-left:4px solid #2563eb;
  border-radius:0 10px 10px 0;padding:18px 20px;margin-bottom:18px}
.narrative-label{font-size:0.57rem;text-transform:uppercase;letter-spacing:0.14em;
  color:#2563eb;font-weight:800;margin-bottom:9px}
.narrative p{font-size:0.86rem;color:#1a2332;line-height:1.75}
.narrative strong{color:#0b1420}

/* ── KPI row ── */
.kpi-row{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:18px}
.kpi{background:#fff;border:1px solid #e7eaf0;border-radius:10px;
  padding:15px 15px 13px;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
  background:var(--c,#0d9488);border-radius:3px 3px 0 0}
.kpi-lbl{font-size:0.57rem;text-transform:uppercase;letter-spacing:0.1em;
  color:#9aa5b5;font-weight:700;margin-bottom:7px}
.kpi-val{font-size:1.55rem;font-weight:900;color:var(--c,#0d9488);
  letter-spacing:-0.02em;line-height:1;margin-bottom:5px}
.kpi-sub{font-size:0.61rem;color:#9aa5b5}
.kpi-bar{height:4px;background:#eef1f6;border-radius:2px;margin-top:7px;overflow:hidden}
.kpi-bar-fill{height:100%;border-radius:2px;background:var(--c,#0d9488)}

/* ── Score cards (backward-compat) ── */
.score-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:11px;margin-bottom:18px}
.scard{background:#fff;border:1px solid #e7eaf0;border-radius:10px;padding:15px 15px 13px}
.scard-label{font-size:0.57rem;text-transform:uppercase;letter-spacing:0.1em;color:#9aa5b5;font-weight:700;margin-bottom:7px}
.scard-value{font-size:1.55rem;font-weight:900;color:#0b1420;letter-spacing:-0.02em;line-height:1;margin-bottom:5px}
.scard-bar{height:4px;background:#eef1f6;border-radius:2px;margin-top:7px;overflow:hidden}
.scard-bar-fill{height:100%;border-radius:2px;background:#0d9488}

/* ── Callouts ── */
.callout{border-radius:8px;padding:11px 15px;margin-bottom:10px;
  font-size:0.77rem;line-height:1.6;display:flex;gap:10px;align-items:flex-start}
.callout-icon{flex-shrink:0;margin-top:1px;font-size:0.9rem}
.co-danger{background:#fff5f5;border:1px solid #fecaca;color:#991b1b}
.co-warn{background:#fffbeb;border:1px solid #fde68a;color:#92400e}
.co-ok{background:#f0fdf9;border:1px solid #d1fae5;color:#065f46}

/* ── Risk hero ── */
.risk-hero{background:linear-gradient(130deg,#0b1420 0%,#152338 100%);
  border-radius:13px;padding:24px 28px;margin-bottom:18px;
  display:flex;align-items:center;gap:28px;position:relative;overflow:hidden}
.rh-ring{position:absolute;right:-50px;top:-50px;width:200px;height:200px;
  border-radius:50%;border:28px solid rgba(255,255,255,0.025)}
.rh-donut{flex-shrink:0;position:relative;width:110px;height:110px}
.rh-donut svg{display:block}
.rh-center{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center}
.rh-num{font-size:1.75rem;font-weight:900;color:#fff;line-height:1}
.rh-denom{font-size:0.62rem;color:#4a6a8a;line-height:1;margin-top:1px}
.rh-info{flex:1}
.rh-class{font-size:0.6rem;text-transform:uppercase;letter-spacing:0.14em;color:#4a6a8a;font-weight:700;margin-bottom:4px}
.rh-label{font-size:1.35rem;font-weight:900;letter-spacing:-0.02em;margin-bottom:7px}
.rh-desc{font-size:0.76rem;color:#7a9ab8;line-height:1.6;max-width:340px}
.rh-pills{display:flex;gap:7px;margin-top:10px;flex-wrap:wrap}
.rh-pill{padding:3px 11px;border-radius:20px;font-size:0.62rem;font-weight:700;border:1px solid}

/* ── MITRE Heatmap ── */
.hm-wrap{overflow-x:auto;margin-bottom:12px}
.hm{display:flex;gap:5px;min-width:580px}
.hm-col{flex:1;min-width:56px}
.hm-tactic{font-size:0.5rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;
  color:#5a7a9a;text-align:center;padding:4px 2px 5px;
  border-bottom:2px solid #e7eaf0;margin-bottom:4px;line-height:1.3}
.hm-cell{height:21px;border-radius:3px;margin-bottom:2px;font-size:0.48rem;font-weight:700;
  color:#fff;display:flex;align-items:center;justify-content:center;
  letter-spacing:0.02em;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;padding:0 2px}
.hm-cell.P{background:#0d9488}.hm-cell.D{background:#2563eb}
.hm-cell.M{background:#dc2626}.hm-cell.N{background:#e7eaf0;color:#9aa5b5}
.hm-legend{display:flex;gap:14px;margin-top:6px;margin-bottom:16px}
.hml-item{display:flex;align-items:center;gap:5px;font-size:0.62rem;color:#6e7681}
.hml-dot{width:11px;height:11px;border-radius:2px}

/* ── Execution context / priv badges ── */
.ctx-table{width:100%;border-collapse:collapse;font-size:0.72rem;margin-bottom:14px}
.ctx-table thead th{background:#f0f4f8;color:#5a7a9a;text-transform:uppercase;
  font-size:0.56rem;letter-spacing:0.08em;font-weight:700;text-align:left;
  padding:8px 10px;border-bottom:1.5px solid #e0e7ef}
.ctx-table td{padding:8px 10px;border-bottom:1px solid #f0f4f8;vertical-align:middle}
.priv-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;
  border-radius:3px;font-size:0.6rem;font-weight:700;border:1px solid}
.priv-system{background:rgba(220,38,38,0.08);border-color:rgba(220,38,38,0.3);color:#dc2626}
.priv-admin{background:rgba(234,88,12,0.08);border-color:rgba(234,88,12,0.3);color:#ea580c}
.priv-user{background:rgba(37,99,235,0.08);border-color:rgba(37,99,235,0.3);color:#2563eb}
.priv-fallback{background:rgba(217,119,6,0.08);border-color:rgba(217,119,6,0.3);color:#d97706}
.priv-skipped{background:#f3f4f6;border-color:#d1d5db;color:#6b7280}

/* ── Finding Cards ── */
.fc{border-radius:10px;margin-bottom:14px;overflow:hidden;border:1px solid #e7eaf0;
  border-left-width:5px}
.fc.fc-critical{border-left-color:#dc2626}
.fc.fc-high{border-left-color:#ea580c}
.fc.fc-medium{border-left-color:#d97706}
.fc.fc-low{border-left-color:#0d9488}
.fc.fc-prevented{border-left-color:#0d9488}
.fc.fc-detected{border-left-color:#2563eb}
.fc-stripe{height:0}
.fc-header{padding:12px 16px;display:flex;align-items:flex-start;gap:12px;
  background:#fafbfc;border-bottom:1px solid #f0f4f8}
.fc-sev-block{padding:4px 10px;border-radius:5px;font-size:0.62rem;font-weight:900;
  text-transform:uppercase;letter-spacing:0.08em;color:#fff;flex-shrink:0;margin-top:1px}
.fc-sev-block.critical{background:#dc2626}
.fc-sev-block.high{background:#ea580c}
.fc-sev-block.medium{background:#d97706}
.fc-sev-block.low{background:#0d9488}
.fc-sev-block.prevented{background:#0d9488}
.fc-sev-block.detected{background:#2563eb}
.fc-heading{flex:1;min-width:0}
.fc-name{font-size:0.9rem;font-weight:800;color:#0b1420;line-height:1.25;margin-bottom:3px}
.fc-name.critical{font-size:1.02rem}
.fc-tid{font-size:0.65rem;color:#9aa5b5;font-family:monospace;font-weight:500}
.fc-verdict{flex-shrink:0}
.fc-body{padding:14px 16px}
.fc-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.fc-detail-row{display:flex;gap:8px;margin-bottom:7px;align-items:flex-start}
.fc-detail-label{font-size:0.6rem;font-weight:700;text-transform:uppercase;
  letter-spacing:0.08em;color:#9aa5b5;min-width:88px;padding-top:2px;flex-shrink:0}
.fc-detail-value{font-size:0.75rem;color:#1a2332;line-height:1.5}
.fc-blocked-by{font-size:0.73rem;font-weight:700;color:#065f46;
  background:#f0fdf9;border:1px solid #a7f3d0;border-radius:4px;
  padding:2px 9px;display:inline-flex;align-items:center;gap:4px}
.fc-blocked-none{font-size:0.73rem;color:#dc2626;font-weight:600}
/* Evidence block — dark terminal */
.fc-evidence,.evidence-block{background:#0d1621;border-radius:7px;padding:11px 13px;font-family:monospace}
.fc-ev-hdr,.ev-header{font-size:0.56rem;text-transform:uppercase;letter-spacing:0.14em;
  color:#2563eb;font-weight:700;margin-bottom:8px}
.fc-ev-row,.ev-row{display:flex;gap:6px;margin-bottom:4px;font-size:0.63rem}
.fc-ev-k,.ev-key{color:#4a6a8a;min-width:70px;flex-shrink:0}
.fc-ev-v,.ev-val{color:#a0c4e0;word-break:break-all;line-height:1.4}
.fc-ev-v.ok,.ev-val.ok{color:#0d9488}
.fc-ev-v.bad,.ev-val.bad{color:#f87171}
.fc-ev-v.warn,.ev-val.warn{color:#fbbf24}
.fc-ev-v.code,.ev-val.code{color:#c084fc}
.fc-ev-sec{margin-top:6px;padding-top:6px;border-top:1px solid rgba(255,255,255,0.06)}
.fc-ev-sec-lbl{font-size:0.5rem;text-transform:uppercase;letter-spacing:0.12em;color:#2f81f7;font-weight:700;margin-bottom:4px}
.fc-rr-none{color:#34d399}.fc-rr-partial{color:#fbbf24}.fc-rr-leaked{color:#f87171}.fc-rr-none-dash{color:#6e7681}
.fc-remediation{background:#f0fdf9;border-left:3px solid #0d9488;
  padding:10px 13px;margin-top:10px;border-radius:0 7px 7px 0}
.fc-rem-label{font-size:0.57rem;font-weight:700;text-transform:uppercase;
  letter-spacing:0.1em;color:#0d9488;margin-bottom:4px}
.fc-rem-text{font-size:0.74rem;color:#1a2332;line-height:1.6}
/* Remediation (legacy inline) */
.remediation{background:#f0fdf9;border-left:3px solid #0d9488;padding:8px 12px;
  font-size:0.78rem;color:#1a2332;margin-top:6px;border-radius:0 6px 6px 0;line-height:1.55}

/* ── Verdict badges ── */
.vb{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;
  border-radius:4px;font-size:0.62rem;font-weight:800;letter-spacing:0.04em}
.vb-missed{background:#fee2e2;color:#dc2626}
.vb-detected{background:#dbeafe;color:#1d4ed8}
.vb-prevented{background:#dcfce7;color:#16a34a}
.vb-error{background:#fef3c7;color:#d97706}
.vb-skipped{background:#f3f4f6;color:#6b7280}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;font-size:0.77rem;margin-bottom:14px}
thead th{background:#f0f4f8;color:#5a7a9a;text-transform:uppercase;font-size:0.57rem;
  letter-spacing:0.08em;font-weight:700;text-align:left;padding:8px 11px;
  border-bottom:1.5px solid #e0e7ef}
td{padding:8px 11px;border-bottom:1px solid #f0f4f8;vertical-align:middle;color:#1a2332}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:#f7f9fc}
tbody tr:nth-child(even) td{background:#fbfcfe}

/* ── Misc ── */
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
.tool-tag{display:inline-block;background:#eef4ff;color:#2353c4;border:1px solid #cfe0ff;
  padding:3px 10px;border-radius:20px;font-size:0.72rem;margin:2px 3px 2px 0}
.comp-pct{font-weight:700}
.tbar-wrap{width:100%;height:8px;background:#eef1f6;border-radius:4px;overflow:hidden;display:inline-block;min-width:80px;vertical-align:middle;position:relative}
.tbar-fill{height:100%;border-radius:4px}
.sev{display:inline-flex;align-items:center;gap:4px;font-size:0.72rem;font-weight:600}
.sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sd-c{background:#dc2626}.sd-h{background:#ea580c}.sd-m{background:#d97706}.sd-l{background:#0d9488}
.gloss-item{margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid #e5e7eb}
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
      {{if .logoDarkUri}}<img src="{{.logoDarkUri}}" alt="Audspect BAS" style="height:32px;filter:brightness(0) invert(1);opacity:0.9">{{else}}
      <div class="clogo-mark">A</div>
      <div>
        <div class="clogo-name">Aud<span>spect</span> BAS</div>
        <div class="clogo-sub">Breach &amp; Attack Simulation Platform</div>
      </div>
      {{end}}
    </div>
  </div>

  <div class="cover-body">
    <div class="cover-eyebrow">Security Assessment Report</div>
    {{if .scope}}
    <div class="cover-title">{{.scope.title}}</div>
    <div class="cover-sub">{{.scope.subtitle}}<br>ATT&amp;CK-Aligned BAS — Executive &amp; Technical Report</div>
    {{else}}
    <div class="cover-title">Endpoint Security<br>Posture Assessment</div>
    <div class="cover-sub">ATT&amp;CK-Aligned Breach &amp; Attack Simulation<br>Executive &amp; Technical Report — Confidential</div>
    {{end}}
    <div class="cover-rule"></div>

    <div class="cover-grid">
      {{if .scope}}
      <div class="cg-cell">
        <div class="cg-label">Campaign</div>
        <div class="cg-value">{{.scope.title}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Scenario</div>
        <div class="cg-value">{{.scope.scenario}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Endpoints Assessed</div>
        <div class="cg-value">{{.scope.agentCount}} agent(s)</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Runs Aggregated</div>
        <div class="cg-value">{{.scope.runCount}} run(s)</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Assessment Date</div>
        <div class="cg-value">{{fmtTime .summary.lastRunAt}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Report Generated</div>
        <div class="cg-value">{{fmtTime .generatedAt}}</div>
      </div>
      {{else}}
      <div class="cg-cell">
        <div class="cg-label">Endpoint</div>
        <div class="cg-value">{{.agent.hostname}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">IP / Environment</div>
        <div class="cg-value">{{.agent.ipAddress}} &nbsp;&#183;&nbsp; {{.agent.envLabel}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Operating System</div>
        <div class="cg-value">{{.agent.osVersion}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Logged-in User</div>
        <div class="cg-value">{{.agent.username}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Assessment Date</div>
        <div class="cg-value">{{fmtTime .summary.lastRunAt}}</div>
      </div>
      <div class="cg-cell">
        <div class="cg-label">Last Scenario</div>
        <div class="cg-value">{{.summary.lastScenarioName}}</div>
      </div>
      {{if .agent.status}}
      <div class="cg-cell">
        <div class="cg-label">Agent Status</div>
        <div class="cg-value" style="color:{{agentStatusColor .agent.status}};font-weight:700">&#9679; {{.agent.status}}</div>
      </div>
      {{end}}
      {{end}}
    </div>

    <div class="cover-badges">
      <div class="cb cb-conf">&#9888; CONFIDENTIAL &#8212; Authorised Recipients Only</div>
      <div class="cb cb-live">&#10003; Live Simulation &nbsp;&#183;&nbsp; Audspect BAS</div>
    </div>
    {{if .activeFilter}}<div class="filter-badge">&#9660; Filtered View: {{filterLabel .activeFilter}} &#8212; {{.filterMatchCount}} of {{.filterTotalCount}} techniques shown &nbsp;&#183;&nbsp; Scores reflect the full unfiltered run</div>{{end}}
  </div>

  <div class="cover-bottom">
    <div class="cover-bottom-copy">
      Audspect BAS Platform &nbsp;&#183;&nbsp; Classification: CONFIDENTIAL<br>
      This document contains sensitive security posture information. Do not forward or distribute.
    </div>
    <div class="cover-scores">
      <div class="cs-item">
        <div class="cs-num" style="color:#0d9488">{{fmtScore .summary.preventionScore}}%</div>
        <div class="cs-lbl">Prevention</div>
      </div>
      <div class="cs-item">
        <div class="cs-num" style="color:#2563eb">{{fmtScore .summary.detectionScore}}%</div>
        <div class="cs-lbl">Detection</div>
      </div>
      <div class="cs-item">
        <div class="cs-num" style="color:{{riskColor .summary.classification}}">{{.summary.classification}}</div>
        <div class="cs-lbl">Risk Class</div>
      </div>
    </div>
  </div>
</div>
</div>

<!-- ═══ 1. EXECUTIVE SUMMARY ════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 1</div>
<div class="stitle">Executive Summary</div>


<div class="risk-hero">
  <div class="rh-ring"></div>
  <!-- SVG donut — prevention score ring -->
  <svg width="120" height="120" viewBox="0 0 100 100" style="flex-shrink:0">
    <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10"/>
    <circle cx="50" cy="50" r="44" fill="none"
      stroke="{{riskColor .summary.classification}}"
      stroke-width="10"
      stroke-linecap="round"
      stroke-dasharray="{{scoreArc .summary.preventionScore}} 276.46"
      transform="rotate(-90 50 50)"/>
    <text x="50" y="45" text-anchor="middle" fill="#fff" font-size="18" font-weight="700" font-family="system-ui,sans-serif">{{fmtScore .summary.preventionScore}}%</text>
    <text x="50" y="62" text-anchor="middle" fill="rgba(255,255,255,0.55)" font-size="9" font-family="system-ui,sans-serif">PREVENTION</text>
  </svg>
  <div style="flex:1;min-width:0">
    <div style="color:rgba(255,255,255,0.5);font-size:0.75rem;letter-spacing:.08em;text-transform:uppercase;margin-bottom:4px">Overall Risk Score</div>
    <div style="font-size:2.6rem;font-weight:800;color:{{riskColor .summary.classification}};line-height:1">{{.summary.riskScore}}<span style="font-size:1rem;color:rgba(255,255,255,0.4);font-weight:400"> / 100</span></div>
    <div style="font-size:1.1rem;color:#fff;font-weight:600;margin-top:4px">{{.summary.classification}}</div>
    <div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap">
      <span style="padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:600;background:{{exposureColor .summary.exposureLevel}}22;color:{{exposureColor .summary.exposureLevel}};border:1px solid {{exposureColor .summary.exposureLevel}}55">Exposure: {{.summary.exposureLevel}}</span>
      {{if .summary.detectionMeasured}}<span style="padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:600;background:#2f81f722;color:#2f81f7;border:1px solid #2f81f755">Detection: {{fmtScore .summary.detectionScore}}%</span>{{end}}
      <span style="padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:600;background:rgba(255,255,255,0.06);color:rgba(255,255,255,0.5);border:1px solid rgba(255,255,255,0.12)">{{.summary.penetrationFailed}} / {{.summary.penetrationTested}} techniques evaded</span>
    </div>
  </div>
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

{{if .tacticHeatmap}}
<!-- Kill-chain coverage strip — one tile per tested tactic, colored by prevention rate -->
<div style="margin-bottom:18px">
  <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:.1em;color:#6e7681;font-weight:700;margin-bottom:8px">ATT&amp;CK Kill-Chain Coverage</div>
  <div style="display:flex;flex-wrap:wrap;gap:6px">
    {{range .tacticHeatmap}}
    <div style="display:flex;flex-direction:column;align-items:center;min-width:62px;max-width:80px;background:#f8faff;border:1px solid #e7eaf0;border-top:3px solid {{tacticAccent .tactic}};border-radius:7px;padding:6px 8px">
      <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:.05em;color:#6e7681;text-align:center;line-height:1.3;margin-bottom:4px">{{humanize .tactic}}</div>
      <div style="font-size:0.95rem;font-weight:800;color:{{if ge .passPct 70.0}}#0d9488{{else if ge .passPct 40.0}}#d29922{{else}}#da3633{{end}}">{{fmtScore .passPct}}%</div>
      <div style="font-size:0.58rem;color:#9ca3af;margin-top:2px">{{printf "%.0f" .total}} tested</div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{/* ── Privilege Assessment block ── */}}
{{$ps := .privilegeSummary}}
{{if or $ps.user $ps.admin $ps.system}}
<div style="margin-bottom:18px;padding:14px 16px;background:rgba(13,17,23,0.5);border:1px solid #30363d;border-radius:8px">
  <div style="font-size:0.62rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#6e7681;margin-bottom:10px">&#x1F6E1; Privilege Assessment</div>
  <div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid #21262d">
    <div style="text-align:center">
      <div style="font-size:1.3rem;font-weight:900;color:#fff">{{sumInts $ps.user $ps.admin $ps.system}}</div>
      <div style="font-size:0.58rem;color:#6e7681;white-space:nowrap">Techniques Tested</div>
    </div>
    {{if $ps.user}}<div style="text-align:center">
      <div style="font-size:1.3rem;font-weight:900;color:#c9d1d9">{{$ps.user}}</div>
      <div style="font-size:0.58rem;color:#6e7681;white-space:nowrap">Standard User</div>
    </div>{{end}}
    {{if or $ps.admin $ps.system}}<div style="text-align:center">
      <div style="font-size:1.3rem;font-weight:900;color:#d29922">{{sumInts $ps.admin $ps.system}}</div>
      <div style="font-size:0.58rem;color:#6e7681;white-space:nowrap">Required Elevation</div>
    </div>{{end}}
    {{if $ps.fallbacks}}<div style="text-align:center">
      <div style="font-size:1.3rem;font-weight:900;color:#9aa5b5">{{$ps.fallbacks}}</div>
      <div style="font-size:0.58rem;color:#6e7681;white-space:nowrap">WTS Fallbacks</div>
    </div>{{end}}
  </div>
  {{$psc := privSummaryConclusion .privilegeSummary}}
  {{if $psc}}<div style="font-size:0.78rem;color:#c9d1d9;line-height:1.7">{{$psc}}</div>{{end}}
</div>
{{end}}

<h2>Executive Conclusion</h2>
<p style="font-size:0.92rem;line-height:1.7">{{.executiveConclusion}}</p>

<div class="pf">
  <span>{{.agent.hostname}} — Executive Summary</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 2. ASSESSMENT SUMMARY ═══════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 2</div>
<div class="stitle">Assessment Summary</div>


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

{{if .kevExposure}}{{if .kevExposure.hasData}}{{if gt .kevExposure.kevFailed 0.0}}
<div style="background:#fff5f5;border:1px solid #fca5a5;border-left:4px solid #da3633;border-radius:6px;padding:14px 18px;margin-bottom:20px;display:flex;gap:14px;align-items:flex-start">
  <span style="color:#da3633;font-size:1.3rem;line-height:1.2;flex-shrink:0">&#9888;</span>
  <div>
    <strong style="color:#991b1b;font-size:0.9rem">KEV Exposure Alert</strong>
    <div style="font-size:0.82rem;color:#374151;margin-top:4px">
      <strong>{{.kevExposure.kevFailed}}</strong> of <strong>{{.kevExposure.totalKevTechs}}</strong> tested techniques with active CISA Known Exploited Vulnerability (KEV) CVEs were <strong style="color:#991b1b">not blocked</strong> by your controls.{{if gt .kevExposure.ransomwareLinked 0.0}} <strong style="color:#d29922">{{.kevExposure.ransomwareLinked}} are linked to active ransomware campaigns.</strong>{{end}}
      These vulnerabilities are under real-world active exploitation — prioritise remediation immediately.
    </div>
  </div>
</div>
{{end}}{{end}}{{end}}

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

<h3>Execution Summary</h3>
<table>
  <tr><td>Executed</td><td><strong>{{addInt .summary.passedTechniques .summary.failedTechniques}}</strong></td>
      <td>Succeeded</td><td style="color:#0d9488"><strong>{{.summary.passedTechniques}}</strong></td></tr>
  <tr><td>Failed</td><td style="color:#da3633"><strong>{{.summary.failedTechniques}}</strong></td>
      <td></td><td></td></tr>
  <tr><td>Skipped (Policy)</td><td><strong>{{.skipBreakdown.policy}}</strong></td>
      <td>Skipped (Content)</td><td><strong>{{.skipBreakdown.content}}</strong></td></tr>
  <tr><td>Skipped (Platform)</td><td><strong>{{.skipBreakdown.platform}}</strong></td>
      <td></td><td></td></tr>
  <tr><td>Scenario Coverage</td><td colspan="3"><strong>{{.coverage.executed}}/{{.coverage.scenarioTotal}}</strong> ({{.coverage.scenarioCoveragePct}}%)</td></tr>
  <tr><td>Eligible Coverage</td><td colspan="3"><strong>{{.coverage.executed}}/{{.coverage.eligible}}</strong> ({{.coverage.eligibleCoveragePct}}%)</td></tr>
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

<h3>Execution Context (Privilege)</h3>
<p style="color:#6e7681;margin-bottom:8px">Per-step privilege context from multi-context execution. <strong>Legacy</strong> steps ran in the agent's default context (requires_priv not yet annotated). <strong>User→Admin</strong> indicates a requested user-context step that fell back to admin because no interactive session was available. Prevention rate = steps blocked / steps attempted per tier.</p>
<table>
  <thead><tr><th>Tier</th><th>Steps</th><th>Prevented</th><th>Prevention Rate</th></tr></thead>
  {{if .privilegeSummary.user}}<tr>
    <td>User (interactive)</td>
    <td><strong>{{.privilegeSummary.user}}</strong></td>
    <td><strong style="color:#0d9488">{{.privilegeSummary.userPrevented}}</strong></td>
    <td><strong>{{.privilegeSummary.userRate}}%</strong></td>
  </tr>{{end}}
  {{if .privilegeSummary.admin}}<tr>
    <td>Admin (elevated)</td>
    <td><strong>{{.privilegeSummary.admin}}</strong></td>
    <td><strong style="color:#0d9488">{{.privilegeSummary.adminPrevented}}</strong></td>
    <td><strong>{{.privilegeSummary.adminRate}}%</strong></td>
  </tr>{{end}}
  {{if .privilegeSummary.system}}<tr>
    <td>System (NT AUTHORITY)</td>
    <td><strong>{{.privilegeSummary.system}}</strong></td>
    <td><strong style="color:#0d9488">{{.privilegeSummary.systemPrevented}}</strong></td>
    <td><strong>{{.privilegeSummary.systemRate}}%</strong></td>
  </tr>{{end}}
  {{if .privilegeSummary.legacy}}<tr style="color:#6e7681">
    <td>Legacy (unannotated)</td>
    <td><strong>{{.privilegeSummary.legacy}}</strong></td>
    <td><strong>{{.privilegeSummary.legacyPrevented}}</strong></td>
    <td><strong>{{.privilegeSummary.legacyRate}}%</strong></td>
  </tr>{{end}}
  {{if .privilegeSummary.fallbacks}}<tr><td colspan="4" style="color:#d29922;font-size:0.85em">WTS Fallbacks (User→Admin): <strong>{{.privilegeSummary.fallbacks}}</strong> step(s) requested user context but fell back to admin — no interactive session was active.</td></tr>{{end}}
</table>

<div class="pf">
  <span>{{.agent.hostname}} — Assessment Summary</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 3. TOP RISK DRIVERS ═════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 3</div>
<div class="stitle">Top Risk Drivers</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Top Risk Drivers</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 4. RISK SUMMARY ═════════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 4</div>
<div class="stitle">Risk Summary</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Risk Summary</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 5. ASSET CONTEXT ════════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 5</div>
<div class="stitle">Asset Context</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Asset Context</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 6. KILL-CHAIN PATH ══════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 6</div>
<div class="stitle">Kill-Chain Path</div>

<p style="color:#6e7681;margin-bottom:14px">The chain of kill-chain phases this endpoint's gaps actually permit — built strictly from observed unprevented techniques, ordered by ATT&amp;CK phase. No hypothetical or inferred steps.</p>

{{if .killChain}}
<!-- Attack Simulation Timeline — wrapping tile grid, one card per step -->
<div style="margin-bottom:20px">
  <div style="font-size:0.62rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#6e7681;margin-bottom:10px">Attack Simulation Timeline</div>
  <div style="display:flex;flex-wrap:wrap;gap:6px">
    {{range $i,$s := .killChain}}
    <div style="display:flex;flex-direction:column;align-items:center;gap:3px;width:88px;padding:7px 4px 6px;border:1px solid {{if eq $s.outcome "prevented"}}#0d948833{{else if eq $s.outcome "detected"}}#d2992233{{else}}#da363333{{end}};border-top:3px solid {{if eq $s.outcome "prevented"}}#0d9488{{else if eq $s.outcome "detected"}}#d29922{{else}}#da3633{{end}};border-radius:6px;background:#fafbfc">
      <div style="font-size:0.5rem;font-weight:700;color:#9aa5b5;letter-spacing:0.04em">#{{add1 $i}}</div>
      <div style="width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:{{if eq $s.outcome "prevented"}}#0d9488{{else if eq $s.outcome "detected"}}#d29922{{else}}#da3633{{end}}">
        <span style="font-size:10px;color:#fff;line-height:1">{{if eq $s.outcome "prevented"}}&#10003;{{else if eq $s.outcome "detected"}}!{{else}}&#10007;{{end}}</span>
      </div>
      <div style="font-size:0.42rem;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:#6e7681;text-align:center">{{humanize $s.phase}}</div>
      <div style="font-size:0.48rem;font-weight:700;color:#0b1420;font-family:monospace;text-align:center">{{$s.techniqueId}}</div>
      <div style="font-size:0.42rem;color:#6e7681;text-align:center;line-height:1.3;word-break:break-word">{{$s.technique}}</div>
      <div style="font-size:0.44rem;font-weight:800;text-transform:uppercase;letter-spacing:0.05em;color:{{if eq $s.outcome "prevented"}}#0d9488{{else if eq $s.outcome "detected"}}#d29922{{else}}#da3633{{end}}">{{$s.outcome}}</div>
    </div>
    {{end}}
  </div>
  <div style="display:flex;gap:16px;margin-top:8px">
    <div style="display:flex;align-items:center;gap:5px;font-size:0.6rem;color:#6e7681"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#0d9488"></span>Prevented</div>
    <div style="display:flex;align-items:center;gap:5px;font-size:0.6rem;color:#6e7681"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#d29922"></span>Detected (not blocked)</div>
    <div style="display:flex;align-items:center;gap:5px;font-size:0.6rem;color:#6e7681"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#da3633"></span>Missed (no detection)</div>
  </div>
</div>
{{end}}

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

<div class="pf">
  <span>{{.agent.hostname}} — Kill-Chain Path</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 7. ATTACK FLOW ═══════════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 7</div>
<div class="stitle">Attack Flow</div>

<p style="color:#6e7681;margin-bottom:14px">Per-technique execution outcome ordered by ATT&amp;CK kill-chain phase. Each row shows which security control acted (or failed to act) on the technique and the resulting verdict: <strong style="color:#238636">Blocked</strong> (control prevented execution), <strong style="color:#d29922">Detected</strong> (logged and alerted but not stopped), <strong style="color:#b58800">Logged</strong> (telemetry captured, no alert), or <strong style="color:#da3633">Bypassed</strong> (no control observed the technique).</p>

{{if .attackFlow}}

<div style="display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap">
  <div style="flex:1;min-width:80px;border:1px solid #30363d;border-top:3px solid #238636;border-radius:4px;padding:8px 12px">
    <div style="font-size:1.3rem;font-weight:700;color:#238636">{{.attackFlowSummary.blocked}}</div>
    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:.06em;color:#6e7681">Blocked</div>
  </div>
  <div style="flex:1;min-width:80px;border:1px solid #30363d;border-top:3px solid #d29922;border-radius:4px;padding:8px 12px">
    <div style="font-size:1.3rem;font-weight:700;color:#d29922">{{.attackFlowSummary.detected}}</div>
    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:.06em;color:#6e7681">Detected</div>
  </div>
  <div style="flex:1;min-width:80px;border:1px solid #30363d;border-top:3px solid #b58800;border-radius:4px;padding:8px 12px">
    <div style="font-size:1.3rem;font-weight:700;color:#b58800">{{.attackFlowSummary.logged}}</div>
    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:.06em;color:#6e7681">Logged</div>
  </div>
  <div style="flex:1;min-width:80px;border:1px solid #30363d;border-top:3px solid #da3633;border-radius:4px;padding:8px 12px">
    <div style="font-size:1.3rem;font-weight:700;color:#da3633">{{.attackFlowSummary.bypassed}}</div>
    <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:.06em;color:#6e7681">Bypassed</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th style="width:9%">Technique</th>
      <th style="width:25%">Name</th>
      <th style="width:14%">Tactic</th>
      <th style="width:14%">Verdict</th>
      <th>Security Control</th>
      <th style="width:8%">Severity</th>
      <th style="width:7%">Duration</th>
    </tr>
  </thead>
  <tbody>
  {{$prevTactic := ""}}
  {{range .attackFlow}}
  {{if ne .tactic $prevTactic}}
  {{$prevTactic = .tactic}}
  <tr>
    <td colspan="7" style="background:#161b22;font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:#58a6ff;padding:5px 8px;border-left:3px solid #58a6ff">{{humanize .tactic}}</td>
  </tr>
  {{end}}
  {{$vc := "#6e7681"}}
  {{if eq .verdict "blocked"}}{{$vc = "#238636"}}{{end}}
  {{if eq .verdict "detected"}}{{$vc = "#d29922"}}{{end}}
  {{if eq .verdict "logged"}}{{$vc = "#b58800"}}{{end}}
  {{if eq .verdict "bypassed"}}{{$vc = "#da3633"}}{{end}}
  {{if eq .verdict "error"}}{{$vc = "#6e7681"}}{{end}}
  <tr>
    <td><code>{{.techniqueId}}</code></td>
    <td>{{.techniqueName}}</td>
    <td style="font-size:0.7rem;color:#6e7681">{{humanize .tactic}}</td>
    <td style="font-weight:600;color:{{$vc}}">{{.verdictLabel}}</td>
    <td>
      {{if .controlName}}{{.controlName}}{{if .alertName}} <span style="color:#6e7681;font-size:0.75rem">· {{.alertName}}</span>{{end}}{{else}}<span style="color:#6e7681">—</span>{{end}}
      {{if .isStopPoint}}<div style="font-size:0.68rem;color:#238636;font-weight:600;margin-top:2px">&#9940; Attack stopped here</div>{{end}}
    </td>
    <td style="font-size:0.8rem">{{if .severity}}{{.severity}}{{else}}—{{end}}</td>
    <td style="font-size:0.8rem;color:#6e7681">{{if .durationMs}}{{.durationMs}}ms{{else}}—{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>

{{else}}
<p style="color:#0d9488;font-weight:600">&#10003; No techniques were executed in this run.</p>
{{end}}

<div class="pf">
  <span>{{.agent.hostname}} — Attack Flow</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 8. ATTACK PATH VALIDATION ═══════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 8</div>
<div class="stitle">Attack Path Validation</div>

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

{{with .pathCorrelation}}
<h3>Attack Path Detection Coverage</h3>
<p style="color:#6e7681;font-size:0.82rem">{{.summary}}</p>
<div class="score-row">
  <div class="scard" style="border-left:3px solid {{scoreColor .detectionCoverageScore}}">
    <div class="scard-label">Detection Coverage Score</div>
    <div class="scard-value" style="color:{{scoreColor .detectionCoverageScore}}">{{.detectionCoverageScore}}<span style="font-size:0.9rem;color:#6e7681">/100</span></div>
    <div style="font-size:0.8rem;color:#6e7681">higher is safer · independent of Attack Path Score</div>
  </div>
  <div class="scard">
    <div class="scard-label">Verified Coverage</div>
    <div class="scard-value" style="font-size:1.2rem">{{.statistics.verifiedCovered}}<span style="font-size:0.9rem;color:#6e7681">/{{.statistics.edgesTotal}}</span></div>
    <div style="font-size:0.8rem;color:#6e7681">{{.statistics.verifiedPartial}} partial · {{.statistics.verifiedGap}} gap · {{.statistics.verifiedUnknown}} unknown</div>
  </div>
  {{if .statistics.highestRiskTechnique}}
  <div class="scard" style="border-left:3px solid #da3633">
    <div class="scard-label">Highest-Risk Technique</div>
    <div class="scard-value" style="color:#da3633;font-size:1.2rem">{{.statistics.highestRiskTechnique}}</div>
    <div style="font-size:0.8rem;color:#6e7681">largest cumulative contribution across all gaps</div>
  </div>
  {{end}}
</div>

{{if .gaps}}
<h4 style="margin-top:14px">Prioritized Detection Gaps</h4>
<p style="color:#6e7681;font-size:0.82rem">Edges an attacker could cross with no fully verified detection, ranked by how many paths cross them and how close they sit to a high-value target.</p>
<table>
  <thead><tr><th>From</th><th>Via</th><th>To</th><th>Technique(s)</th><th>Priority</th><th>Reason</th></tr></thead>
  <tbody>
  {{range .gaps}}
  <tr>
    <td style="font-weight:600">{{.edge.from}}</td>
    <td>{{upper .edge.kind}}</td>
    <td style="font-weight:600">{{.edge.to}}</td>
    <td>{{range .techniques}}{{.techniqueId}} {{end}}</td>
    <td style="font-weight:700;color:{{exposureColor .priority}}">{{.priority}}</td>
    <td style="color:#6e7681;font-size:0.82rem">{{.reason}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}
{{end}}
{{else}}
<p style="color:#6e7681">No attack-path data has been collected yet. Enable the <code>attackpath.collect</code> task on enrolled agents to map lateral-movement reachability, blast radius, segmentation, and crown-jewel exposure across the fleet.</p>
{{end}}

<div class="pf">
  <span>{{.agent.hostname}} — Attack Path Validation</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 9. TACTIC SUMMARY ═══════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 9</div>
<div class="stitle">MITRE ATT&amp;CK Tactic Summary</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Tactic Summary</span>
  {{template "pf-right" .}}
</div>
</div>
</div>


<!-- ═══ 10. THREAT ACTOR READINESS ═════════════════════════════════════════ -->
{{if .readinessScores}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 10</div>
<div class="stitle">Threat Actor Readiness</div>

<p style="color:#6e7681;margin-bottom:6px">For each ATT&amp;CK threat group whose techniques overlap this assessment, how well are your controls positioned? Derived from the MITRE ATT&amp;CK knowledge base — no external feed required. Worst prevention readiness shown first.</p>
<p style="font-size:0.75rem;color:#6e7681;margin-bottom:14px">
  <strong>Prevention Readiness:</strong> % of tested techniques that were blocked.&nbsp;
  <strong>Detection Readiness:</strong> % of tested techniques that were blocked <em>or</em> detected (alert raised).&nbsp;
  The gap between the two reveals how much you rely on detection-only coverage.
</p>
<table>
  <thead><tr>
    <th>Threat Actor / Group</th>
    <th style="text-align:right">Tested / Total</th>
    <th style="text-align:right">Coverage</th>
    <th style="text-align:right">Prevention Readiness</th>
    <th style="text-align:right">Detection Readiness</th>
    <th style="text-align:right">Trend</th>
    <th>Readiness</th>
    <th>Confidence</th>
  </tr></thead>
  <tbody>
  {{range .readinessScores}}
  <tr>
    <td style="font-weight:600">{{.groupName}}</td>
    <td style="text-align:right;font-size:0.82rem;color:#6e7681">{{.testedTechs}} / {{.totalTechs}}</td>
    <td style="text-align:right;font-size:0.82rem;color:#6e7681">{{printf "%.0f" .coveragePct}}%</td>
    <td style="text-align:right;font-weight:700;color:{{if gt .preventionReadiness 79.9}}#0d9488{{else if gt .preventionReadiness 49.9}}#d29922{{else}}#da3633{{end}}">
      {{printf "%.1f" .preventionReadiness}}%
      <div style="font-size:0.72rem;font-weight:400;color:#6e7681">{{.preventedTechs}} prevented</div>
    </td>
    <td style="text-align:right;font-weight:700;color:{{if gt .detectionReadiness 79.9}}#0d9488{{else if gt .detectionReadiness 49.9}}#d29922{{else}}#da3633{{end}}">
      {{printf "%.1f" .detectionReadiness}}%
      <div style="font-size:0.72rem;font-weight:400;color:#6e7681">+{{.detectedTechs}} detected</div>
    </td>
    <td style="text-align:right">
      {{if .hasTrend}}
        {{if eq .trendDirection "up"}}
          <span style="font-size:0.8rem;font-weight:700;color:#0d9488">&#8679; +{{printf "%.1f" .preventionDelta}}%</span>
          <div style="font-size:0.65rem;color:#6e7681">{{printf "%.1f" .prevPreventionReadiness}}% &#8594; now</div>
        {{else if eq .trendDirection "down"}}
          <span style="font-size:0.8rem;font-weight:700;color:#da3633">&#8681; {{printf "%.1f" .preventionDelta}}%</span>
          <div style="font-size:0.65rem;color:#6e7681">{{printf "%.1f" .prevPreventionReadiness}}% &#8594; now</div>
        {{else}}
          <span style="font-size:0.8rem;color:#6e7681">&#8213; stable</span>
        {{end}}
      {{else}}
        <span style="font-size:0.75rem;color:#6e7681">&#8212;</span>
      {{end}}
    </td>
    <td>
      <span style="font-size:0.78rem;font-weight:700;border-radius:4px;padding:2px 8px;
        {{if eq .readinessBand "High"}}background:#f0fdf4;border:1px solid #86efac;color:#15803d
        {{else if eq .readinessBand "Medium"}}background:#fffbeb;border:1px solid #fde68a;color:#92400e
        {{else}}background:#fef2f2;border:1px solid #fca5a5;color:#991b1b{{end}}">
        {{.readinessBand}}
      </span>
    </td>
    <td>
      <span style="font-size:0.72rem;border-radius:4px;padding:2px 8px;
        {{if eq .confidenceBand "High"}}background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8
        {{else if eq .confidenceBand "Medium"}}background:#f8fafc;border:1px solid #cbd5e1;color:#475569
        {{else}}background:#f8fafc;border:1px solid #cbd5e1;color:#94a3b8{{end}}">
        {{.confidenceBand}} Confidence
        <span style="font-size:0.65rem;color:#94a3b8">({{.testedTechs}} tested)</span>
      </span>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
<p style="font-size:0.72rem;color:#6e7681;margin-top:10px">Groups with fewer than 3 tested techniques are excluded. Technique attribution sourced from MITRE ATT&amp;CK&reg;. &copy; The MITRE Corporation.</p>
<div class="pf">
  <span>{{.agent.hostname}} &#8212; Threat Actor Readiness</span>
  {{template "pf-right" .}}
</div>
</div>
</div>
{{end}}
<!-- ═══ 10a. RANSOMWARE READINESS ═══════════════════════════════════════════ -->
{{if .ransomwareReadiness}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 10a</div>
<div class="stitle">Ransomware Readiness</div>

<p style="color:#6e7681;margin-bottom:6px">Prevention and detection readiness against known ransomware threat actors, derived from MITRE ATT&amp;CK technique attribution. Worst performers shown first — these represent the highest breach risk from currently active ransomware groups.</p>
<p style="font-size:0.75rem;color:#6e7681;margin-bottom:14px">Only groups with ≥3 tested techniques are included. Confidence reflects sample size: <strong>High</strong> ≥10 tested, <strong>Medium</strong> ≥5, <strong>Low</strong> 3–4.</p>
<table>
  <thead><tr>
    <th>Ransomware Group</th>
    <th style="text-align:right">Tested</th>
    <th style="text-align:right">Prevention</th>
    <th style="text-align:right">Detection</th>
    <th style="text-align:right">Trend</th>
    <th>Posture</th>
    <th>Confidence</th>
  </tr></thead>
  <tbody>
  {{range .ransomwareReadiness}}
  <tr>
    <td>
      <strong style="font-size:0.92rem">{{.groupName}}</strong>
      <div style="font-size:0.7rem;color:#6e7681">{{.testedTechs}} of {{.totalTechs}} ATT&amp;CK techniques covered</div>
    </td>
    <td style="text-align:right;font-size:0.82rem;color:#6e7681">{{.testedTechs}} / {{.totalTechs}}</td>
    <td style="text-align:right">
      <strong style="font-size:1.05rem;color:{{if gt .preventionReadiness 79.9}}#0d9488{{else if gt .preventionReadiness 49.9}}#d29922{{else}}#da3633{{end}}">{{printf "%.0f" .preventionReadiness}}%</strong>
      <div style="width:80px;height:5px;background:#e5e7eb;border-radius:3px;margin:3px 0 0 auto">
        <div style="height:5px;border-radius:3px;width:{{printf "%.0f" .preventionReadiness}}%;background:{{if gt .preventionReadiness 79.9}}#0d9488{{else if gt .preventionReadiness 49.9}}#d29922{{else}}#da3633{{end}}"></div>
      </div>
    </td>
    <td style="text-align:right">
      <strong style="font-size:1.05rem;color:{{if gt .detectionReadiness 79.9}}#2f81f7{{else if gt .detectionReadiness 49.9}}#d29922{{else}}#da3633{{end}}">{{printf "%.0f" .detectionReadiness}}%</strong>
      <div style="font-size:0.7rem;color:#6e7681">+{{.detectedTechs}} detected</div>
    </td>
    <td style="text-align:right">
      {{if .hasTrend}}
        {{if eq .trendDirection "up"}}
          <span style="font-size:0.8rem;font-weight:700;color:#0d9488">&#8679; +{{printf "%.1f" .preventionDelta}}%</span>
        {{else if eq .trendDirection "down"}}
          <span style="font-size:0.8rem;font-weight:700;color:#da3633">&#8681; {{printf "%.1f" .preventionDelta}}%</span>
        {{else}}
          <span style="font-size:0.8rem;color:#6e7681">&#8213;</span>
        {{end}}
      {{else}}
        <span style="color:#e5e7eb">—</span>
      {{end}}
    </td>
    <td>
      <span style="font-size:0.78rem;font-weight:700;border-radius:4px;padding:2px 8px;
        {{if eq .readinessBand "High"}}background:#f0fdf4;border:1px solid #86efac;color:#15803d
        {{else if eq .readinessBand "Medium"}}background:#fffbeb;border:1px solid #fde68a;color:#92400e
        {{else}}background:#fef2f2;border:1px solid #fca5a5;color:#991b1b{{end}}">
        {{.readinessBand}}
      </span>
    </td>
    <td>
      <span style="font-size:0.72rem;border-radius:4px;padding:2px 8px;background:#f8fafc;border:1px solid #cbd5e1;color:{{if eq .confidenceBand "High"}}#1d4ed8{{else if eq .confidenceBand "Medium"}}#475569{{else}}#94a3b8{{end}}">
        {{.confidenceBand}}&nbsp;<span style="color:#94a3b8">({{.testedTechs}})</span>
      </span>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
<p style="font-size:0.72rem;color:#6e7681;margin-top:10px">Technique attribution from MITRE ATT&amp;CK&reg; &copy; The MITRE Corporation. Groups identified as ransomware-associated by curated keyword matching.</p>
<div class="pf">
  <span>{{.agent.hostname}} &#8212; Ransomware Readiness</span>
  {{template "pf-right" .}}
</div>
</div>
</div>
{{end}}

<!-- ═══ 10b. EPSS PRIORITY INDEX ═══════════════════════════════════════════ -->
{{if .priorityScores}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 10b</div>
<div class="stitle">EPSS Priority Index</div>

<p style="color:#6e7681;margin-bottom:6px">Composite prioritisation combining CISA KEV active-exploitation status, FIRST EPSS exploitation probability, and ATT&amp;CK threat-actor usage frequency. Techniques with higher scores represent the greatest unremediated risk.</p>
<p style="font-size:0.75rem;color:#6e7681;margin-bottom:14px">
  Formula: <strong>KEV</strong> +40 pts · <strong>EPSS ≥90th %ile</strong> +30 pts · <strong>≥70th</strong> +20 pts · <strong>≥50th</strong> +10 pts · <strong>Threat Actors ≥5</strong> +20 pts · <strong>≥2</strong> +10 pts · <strong>Unblocked</strong> +10 pts.
</p>
<table>
  <thead><tr>
    <th>#</th>
    <th>Technique</th>
    <th>Tactic</th>
    <th style="text-align:right">Score</th>
    <th>Tier</th>
    <th style="text-align:center">KEV</th>
    <th style="text-align:right">EPSS</th>
    <th style="text-align:right">Actors</th>
    <th>Verdict</th>
  </tr></thead>
  <tbody>
  {{range $i, $p := .priorityScores}}
  <tr>
    <td style="font-size:0.8rem;color:#6e7681">{{add1 $i}}</td>
    <td>
      <code style="font-size:0.8rem">{{$p.techniqueId}}</code>
      <div style="font-size:0.75rem;color:#374151">{{$p.name}}</div>
      {{if $p.relationshipCount}}<div style="font-size:0.65rem;color:#6e7681">{{$p.relationshipCount}} scored relationship{{if ne $p.relationshipCount 1}}s{{end}}{{if $p.primarySource}} &middot; {{$p.primarySource}}{{end}}</div>{{end}}
    </td>
    <td style="font-size:0.8rem;color:#6e7681">{{humanize $p.tactic}}</td>
    <td style="text-align:right">
      <strong style="font-size:1rem;color:{{if ge $p.priorityScore 70.0}}#da3633{{else if ge $p.priorityScore 40.0}}#d29922{{else if ge $p.priorityScore 20.0}}#2f81f7{{else}}#6e7681{{end}}">{{$p.priorityScore}}</strong>
      <div style="width:50px;height:4px;background:#e5e7eb;border-radius:2px;margin:2px 0 0 auto">
        <div style="height:4px;border-radius:2px;width:{{$p.priorityScore}}%;background:{{if ge $p.priorityScore 70.0}}#da3633{{else if ge $p.priorityScore 40.0}}#d29922{{else if ge $p.priorityScore 20.0}}#2f81f7{{else}}#6e7681{{end}}"></div>
      </div>
    </td>
    <td>
      <span style="font-size:0.73rem;font-weight:700;border-radius:4px;padding:2px 7px;
        {{if eq $p.priorityTier "Critical"}}background:#fef2f2;border:1px solid #fca5a5;color:#991b1b
        {{else if eq $p.priorityTier "High"}}background:#fffbeb;border:1px solid #fde68a;color:#92400e
        {{else if eq $p.priorityTier "Medium"}}background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8
        {{else}}background:#f8fafc;border:1px solid #cbd5e1;color:#64748b{{end}}">
        {{$p.priorityTier}}
      </span>
    </td>
    <td style="text-align:center">
      {{if $p.kev}}<span style="background:#fef2f2;color:#991b1b;border:1px solid #fca5a5;border-radius:3px;padding:1px 5px;font-size:0.68rem;font-weight:700">KEV</span>{{else}}<span style="color:#e5e7eb">—</span>{{end}}
    </td>
    <td style="text-align:right;font-size:0.8rem;color:#6e7681">
      {{if gt $p.epssScore 0.0}}{{printf "%.4f" $p.epssScore}}<div style="font-size:0.65rem">{{printf "%.0f" $p.epssPercentile}}th %ile</div>{{else}}—{{end}}
    </td>
    <td style="text-align:right;font-size:0.85rem">{{$p.threatActorCount}}</td>
    <td>
      <span style="font-size:0.75rem;font-weight:600;color:{{if eq $p.verdict "fail"}}#da3633{{else if eq $p.verdict "pass"}}#0d9488{{else if eq $p.verdict "blocked"}}#0d9488{{else}}#6e7681{{end}}">
        {{if eq $p.verdict "fail"}}UNBLOCKED{{else if eq $p.verdict "pass"}}PASS{{else if eq $p.verdict "blocked"}}BLOCKED{{else}}{{$p.verdict}}{{end}}
      </span>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
<p style="font-size:0.72rem;color:#6e7681;margin-top:10px">EPSS scores from FIRST.org (offline snapshot). KEV from CISA Known Exploited Vulnerabilities catalog. ATT&amp;CK attribution from MITRE &copy; The MITRE Corporation. CVE↔technique relationships shown here are Active with High/Medium confidence only — Low-confidence (illustrative) links are excluded from this score.</p>
<div class="pf">
  <span>{{.agent.hostname}} &#8212; EPSS Priority Index</span>
  {{template "pf-right" .}}
</div>
</div>
</div>
{{end}}

<!-- ═══ 11. VARIANT COVERAGE ANALYSIS ════════════════════════════════════ -->
{{if .variantCoverage}}{{if .variantCoverage.hasData}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 11</div>
<div class="stitle">Variant Coverage Analysis</div>

<p style="color:#6e7681;margin-bottom:14px">Multi-variant evasion testing: encoding obfuscation, execution-context, and privilege-tier combinations per technique. Shows which control gaps allowed bypasses and provides targeted remediation guidance.</p>

<div class="score-row">
  <div class="scard">
    <div class="scard-label">Techniques Tested</div>
    <div class="scard-value">{{.variantCoverage.techniquesTotal}}</div>
    <div style="font-size:0.78rem;color:#6e7681">{{.variantCoverage.variantsExecuted}} variants executed</div>
  </div>
  <div class="scard" style="border-left:3px solid #0d9488">
    <div class="scard-label">Blocked</div>
    <div class="scard-value" style="color:#0d9488">{{.variantCoverage.blocked}}</div>
    <div style="font-size:0.78rem;color:#6e7681">Detected: {{.variantCoverage.detected}}</div>
  </div>
  <div class="scard" style="border-left:3px solid #2563eb">
    <div class="scard-label">Prevention Score</div>
    <div class="scard-value" style="color:#2563eb">{{printf "%.1f" .variantCoverage.preventionScore}}%</div>
    <div style="font-size:0.78rem;color:#6e7681">Detection Score: {{printf "%.1f" .variantCoverage.detectionScore}}%</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .variantCoverage.bypassRate 20.0}}#da3633{{else if gt .variantCoverage.bypassRate 5.0}}#d29922{{else}}#0d9488{{end}}">
    <div class="scard-label">Bypass Rate</div>
    <div class="scard-value" style="color:{{if gt .variantCoverage.bypassRate 20.0}}#da3633{{else if gt .variantCoverage.bypassRate 5.0}}#d29922{{else}}#0d9488{{end}}">{{printf "%.1f" .variantCoverage.bypassRate}}%</div>
    <div style="font-size:0.78rem;color:#6e7681">{{.variantCoverage.techniquesWithBypass}} technique(s) with bypass</div>
  </div>
</div>

<h3>Test Coverage Maturity</h3>
<table>
  <thead><tr><th>Dimension</th><th>Status</th></tr></thead>
  <tbody>
    <tr><td>Execution Variants</td><td>{{if .variantCoverage.maturity.executionTested}}<span style="color:#0d9488;font-weight:600">&#10003; Tested</span>{{else}}<span style="color:#6e7681">&#8212; Not Tested</span>{{end}}</td></tr>
    <tr><td>Encoding Obfuscation</td><td>{{if .variantCoverage.maturity.encodingTested}}<span style="color:#0d9488;font-weight:600">&#10003; Tested</span>{{else}}<span style="color:#6e7681">&#8212; Not Tested</span>{{end}}</td></tr>
    <tr><td>Privilege Tiers</td><td>{{if .variantCoverage.maturity.privilegeTested}}<span style="color:#0d9488;font-weight:600">&#10003; Tested</span>{{else}}<span style="color:#6e7681">&#8212; Not Tested</span>{{end}}</td></tr>
    <tr><td>Proxy Execution</td><td>{{if .variantCoverage.maturity.proxyTested}}<span style="color:#0d9488;font-weight:600">&#10003; Tested</span>{{else}}<span style="color:#6e7681">&#8212; Not Tested</span>{{end}}</td></tr>
    <tr><td>Advanced Evasion</td><td><span style="color:#6e7681">&#8212; Not Tested</span></td></tr>
  </tbody>
</table>

{{if .variantCoverage.techniquesWithBypass}}
<h2>Bypass Findings</h2>
{{range .variantCoverage.techniques}}{{if .hasBypass}}
<div style="border:1px solid #fca5a5;border-left:4px solid {{if eq .severity "Critical"}}#7f1d1d{{else if eq .severity "High"}}#da3633{{else}}#d29922{{end}};border-radius:6px;padding:14px 16px;margin-bottom:14px;background:#fff8f8">

  {{/* ── Header: tactic + technique + severity + evidence ── */}}
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:6px;margin-bottom:10px">
    <div>
      {{if .tactic}}<span style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.07em;color:#6e7681;display:block;margin-bottom:2px">{{humanize .tactic}}</span>{{end}}
      <span style="font-weight:700;color:#0b1420;font-size:1rem">{{.techniqueId}}</span>
      {{if .techniqueName}}<span style="color:#6e7681;margin-left:8px;font-size:0.88rem">{{.techniqueName}}</span>{{end}}
    </div>
    <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
      {{if .severity}}
      <span style="font-size:0.78rem;font-weight:700;border-radius:4px;padding:2px 9px;
        {{if eq .severity "Critical"}}background:#fef2f2;border:1px solid #fca5a5;color:#991b1b
        {{else if eq .severity "High"}}background:#fff7ed;border:1px solid #fdba74;color:#c2410c
        {{else if eq .severity "Medium"}}background:#eff6ff;border:1px solid #93c5fd;color:#1d4ed8
        {{else}}background:#f9fafb;border:1px solid #d1d5db;color:#6b7280{{end}}">
        {{.severity}}
      </span>
      {{end}}
      {{if .bestBypassLabel}}<span style="font-size:0.78rem;background:#fef9c3;border:1px solid #fde047;border-radius:4px;padding:2px 8px;color:#713f12;font-weight:600">{{.bestBypassLabel}}</span>{{end}}
    </div>
  </div>

  {{/* ── Security Control Gap ── */}}
  {{if .headline}}
  <div style="margin-bottom:10px">
    <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#6e7681;margin-bottom:3px">Security Control Gap</div>
    <p style="font-weight:650;color:#da3633;font-size:0.92rem;margin:0">{{.headline}}</p>
  </div>
  {{end}}

  {{/* ── Best Bypass evidence ── */}}
  {{if .bestBypassLabel}}
  <div style="margin-bottom:10px">
    <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#6e7681;margin-bottom:3px">Best Bypass</div>
    <p style="font-size:0.85rem;color:#374151;margin:0;font-weight:600">{{.bestBypassLabel}}</p>
  </div>
  {{end}}

  {{/* ── Remediation ── */}}
  {{if .remediationPoints}}
  <div>
    <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#6e7681;margin-bottom:3px">Remediation</div>
    <ul style="margin:0;padding-left:18px;color:#374151;font-size:0.83rem">
      {{range .remediationPoints}}<li style="margin-bottom:3px">{{.}}</li>{{end}}
    </ul>
  </div>
  {{end}}

</div>
{{end}}{{end}}
{{end}}

<h3>Technique Coverage</h3>
<table>
  <thead><tr>
    <th>Technique</th>
    <th>Tactic</th>
    <th style="text-align:right">Variants</th>
    <th style="text-align:right">Blocked</th>
    <th style="text-align:right">Detected</th>
    <th style="text-align:right">Allowed</th>
    <th style="text-align:right">Bypass%</th>
    <th>Best Bypass</th>
  </tr></thead>
  <tbody>
  {{range .variantCoverage.techniques}}
  <tr{{if .hasBypass}} style="background:#fff8f8"{{end}}>
    <td style="font-weight:600">{{.techniqueId}}{{if .techniqueName}}<br><span style="font-weight:400;font-size:0.78rem;color:#6e7681">{{.techniqueName}}</span>{{end}}</td>
    <td style="font-size:0.82rem;color:#6e7681">{{if .tactic}}{{humanize .tactic}}{{else}}&#8212;{{end}}</td>
    <td style="text-align:right">{{.variantsExecuted}}</td>
    <td style="text-align:right;color:#0d9488;font-weight:600">{{.blocked}}</td>
    <td style="text-align:right;color:#d29922">{{.detected}}</td>
    <td style="text-align:right;color:{{if gt .bypassed 0.0}}#da3633{{else}}#6e7681{{end}};font-weight:{{if gt .bypassed 0.0}}700{{else}}400{{end}}">{{.bypassed}}</td>
    <td style="text-align:right;font-weight:700;color:{{if gt .bypassRate 50.0}}#da3633{{else if gt .bypassRate 20.0}}#d29922{{else}}#0d9488{{end}}">{{printf "%.0f" .bypassRate}}%</td>
    <td style="font-size:0.82rem">{{if .bestBypassLabel}}<span style="color:#374151;font-weight:600">{{.bestBypassLabel}}</span>{{if .severity}}&nbsp;<span style="font-size:0.72rem;color:{{if eq .severity "Critical"}}#991b1b{{else if eq .severity "High"}}#c2410c{{else}}#1d4ed8{{end}}">({{.severity}})</span>{{end}}{{else}}<span style="color:#6e7681">&#8212;</span>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>

{{if .variantCoverage.firstBypassElapsed}}
<p style="color:#6e7681;font-size:0.82rem;margin-top:10px">First successful bypass occurred <strong>{{.variantCoverage.firstBypassElapsed}}</strong> into the assessment.</p>
{{end}}

<div style="margin-top:16px;padding:10px 14px;background:#f7f9fc;border:1px solid #e7eaf0;border-radius:6px;font-size:0.8rem;color:#6e7681">
  <strong>Trend:</strong> {{if .variantCoverage.trendNote}}{{.variantCoverage.trendNote}}{{else}}No prior variant run on record.{{end}}
</div>

<div class="pf">
  <span>{{.agent.hostname}} &#8212; Variant Coverage Analysis</span>
  {{template "pf-right" .}}
</div>
</div>
</div>
{{end}}{{end}}

<!-- ═══ 10b. CAMPAIGN VARIANT COVERAGE TRENDS ═══════════════════════════════ -->
{{if .campaignVariantCoverage}}{{if .campaignVariantCoverage.hasData}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 11</div>
<div class="stitle">Variant Coverage Trends</div>

<p style="color:#6e7681;margin-bottom:14px">Aggregated multi-variant evasion results across {{.campaignVariantCoverage.runCount}} campaign run(s). Identifies recurring control gaps, tactic-level weaknesses, and improvement vs the previous campaign.</p>

{{/* ── Trend banner ── */}}
{{if .campaignVariantCoverage.hasTrend}}
<div style="border-radius:6px;padding:12px 16px;margin-bottom:18px;
  {{if .campaignVariantCoverage.trendImproved}}background:#f0fdf4;border:1px solid #86efac
  {{else}}background:#fff7ed;border:1px solid #fdba74{{end}}">
  <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
    color:{{if .campaignVariantCoverage.trendImproved}}#15803d{{else}}#c2410c{{end}};margin-bottom:4px">
    {{if .campaignVariantCoverage.trendImproved}}&#9650; Improvement vs Previous Campaign{{else}}&#9660; Regression vs Previous Campaign{{end}}
  </div>
  <div style="font-size:0.92rem;font-weight:600;color:{{if .campaignVariantCoverage.trendImproved}}#15803d{{else}}#92400e{{end}}">
    {{.campaignVariantCoverage.trendNote}}
  </div>
  <div style="margin-top:8px;display:flex;gap:24px;font-size:0.82rem;color:#6e7681">
    <span>Previous: <strong>{{.campaignVariantCoverage.prevBypassed}}</strong> bypassed</span>
    <span>Current: <strong>{{.campaignVariantCoverage.bypassed}}</strong> bypassed</span>
    {{if .campaignVariantCoverage.trendImproved}}<span style="color:#15803d;font-weight:600">&#8595; {{printf "%.0f" .campaignVariantCoverage.improvementPct}}% reduction</span>{{end}}
  </div>
</div>
{{else}}
<p style="font-size:0.82rem;color:#6e7681;margin-bottom:14px">{{.campaignVariantCoverage.trendNote}}</p>
{{end}}

{{/* ── KPI summary ── */}}
<div class="score-row">
  <div class="scard">
    <div class="scard-label">Techniques Tested</div>
    <div class="scard-value">{{.campaignVariantCoverage.techniquesTested}}</div>
    <div style="font-size:0.78rem;color:#6e7681">{{.campaignVariantCoverage.variantsExecuted}} variants across {{.campaignVariantCoverage.runCount}} run(s)</div>
  </div>
  <div class="scard" style="border-left:3px solid #0d9488">
    <div class="scard-label">Blocked</div>
    <div class="scard-value" style="color:#0d9488">{{.campaignVariantCoverage.blocked}}</div>
    <div style="font-size:0.78rem;color:#6e7681">Detected: {{.campaignVariantCoverage.detected}}</div>
  </div>
  <div class="scard" style="border-left:3px solid #2563eb">
    <div class="scard-label">Avg Prevention Score</div>
    <div class="scard-value" style="color:#2563eb">{{printf "%.1f" .campaignVariantCoverage.preventionScore}}%</div>
    <div style="font-size:0.78rem;color:#6e7681">Detection Score: {{printf "%.1f" .campaignVariantCoverage.detectionScore}}%</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .campaignVariantCoverage.bypassed 0.0}}#da3633{{else}}#0d9488{{end}}">
    <div class="scard-label">Bypassed (Total)</div>
    <div class="scard-value" style="color:{{if gt .campaignVariantCoverage.bypassed 0.0}}#da3633{{else}}#0d9488{{end}}">{{.campaignVariantCoverage.bypassed}}</div>
    <div style="font-size:0.78rem;color:#6e7681">across all techniques &amp; runs</div>
  </div>
</div>

{{/* ── Top recurring bypasses ── */}}
{{if .campaignVariantCoverage.topBypasses}}
<h2>Top Recurring Bypasses</h2>
<p style="color:#6e7681;margin-bottom:10px">Techniques that bypassed controls across multiple runs — these represent systemic control gaps, not isolated incidents.</p>
<table>
  <thead><tr>
    <th>Technique</th>
    <th>Tactic</th>
    <th style="text-align:right">Runs With Bypass</th>
    <th>Most Common Bypass</th>
  </tr></thead>
  <tbody>
  {{range .campaignVariantCoverage.topBypasses}}
  <tr>
    <td style="font-weight:600">{{.techniqueId}}{{if .techniqueName}}<br><span style="font-weight:400;font-size:0.78rem;color:#6e7681">{{.techniqueName}}</span>{{end}}</td>
    <td style="font-size:0.82rem;color:#6e7681">{{if .tactic}}{{humanize .tactic}}{{else}}&#8212;{{end}}</td>
    <td style="text-align:right;font-weight:700;color:#da3633">{{.timesObserved}}</td>
    <td style="font-size:0.82rem;font-weight:600">{{if .mostCommonBypass}}{{.mostCommonBypass}}{{else}}&#8212;{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

{{/* ── Tactic risk heatmap ── */}}
{{if .campaignVariantCoverage.tacticBreakdown}}
<h2 style="margin-top:22px">Control Effectiveness by ATT&amp;CK Tactic</h2>
<p style="color:#6e7681;margin-bottom:10px">Aggregate prevention rate per tactic across all campaign runs. Drives security roadmap prioritisation.</p>
<table>
  <thead><tr>
    <th>Tactic</th>
    <th style="text-align:right">Techniques</th>
    <th style="text-align:right">Bypasses</th>
    <th style="text-align:right">Prevention Rate</th>
    <th>Risk</th>
    <th style="min-width:120px">Prevention</th>
  </tr></thead>
  <tbody>
  {{range .campaignVariantCoverage.tacticBreakdown}}
  <tr>
    <td style="font-weight:600">{{humanize .tactic}}</td>
    <td style="text-align:right">{{.tested}}</td>
    <td style="text-align:right;color:{{if gt .bypassed 0.0}}#da3633{{else}}#6e7681{{end}};font-weight:{{if gt .bypassed 0.0}}700{{else}}400{{end}}">{{.bypassed}}</td>
    <td style="text-align:right;font-weight:700;color:{{if gt .preventionRate 94.9}}#0d9488{{else if gt .preventionRate 79.9}}#d29922{{else}}#da3633{{end}}">{{printf "%.1f" .preventionRate}}%</td>
    <td>
      <span style="font-size:0.78rem;font-weight:700;border-radius:4px;padding:2px 8px;
        {{if eq .riskLevel "High"}}background:#fef2f2;border:1px solid #fca5a5;color:#991b1b
        {{else if eq .riskLevel "Medium"}}background:#fffbeb;border:1px solid #fde68a;color:#92400e
        {{else}}background:#f0fdf4;border:1px solid #86efac;color:#15803d{{end}}">
        {{.riskLevel}}
      </span>
    </td>
    <td>
      <div style="background:#e5e7eb;border-radius:3px;height:8px;overflow:hidden">
        <div style="height:100%;background:{{if gt .preventionRate 94.9}}#0d9488{{else if gt .preventionRate 79.9}}#d29922{{else}}#da3633{{end}};width:{{printf "%.0f" .preventionRate}}%"></div>
      </div>
    </td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<div class="pf">
  <span>{{.agent.hostname}} &#8212; Variant Coverage Trends</span>
  {{template "pf-right" .}}
</div>
</div>
</div>
{{end}}{{end}}
<!-- ═══ 12. ASSESSMENT INSIGHTS ═════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 12</div>
<div class="stitle">Assessment Insights</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Insights</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 13. ACTION PLAN ═════════════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 13</div>
<div class="stitle">Action Plan</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Action Plan</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 14. COMPLIANCE STATUS ═══════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 14</div>
<div class="stitle">Regulatory Compliance Status</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Compliance Status</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 15. SCENARIO RUN HISTORY ════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 15</div>
<div class="stitle">Scenario Run History</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Run History</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 16. TECHNICAL FINDINGS ══════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 16</div>
<div class="stitle">Technical Findings</div>

{{$hasFindings := false}}
{{range .techniqueMatrix}}{{if and (eq .execVerdict "fail") (or (eq .severity "Critical") (eq .severity "High"))}}{{$hasFindings = true}}{{end}}{{end}}
{{if $hasFindings}}
<p style="color:#6e7681;margin-bottom:14px">Critical and High severity techniques that executed successfully — the associated controls did <strong>not</strong> prevent the attack. Each card includes the specific blocking control (if any), detection source, and residual artifact state.</p>
{{range .techniqueMatrix}}
{{if and (eq .execVerdict "fail") (or (eq .severity "Critical") (eq .severity "High"))}}
{{$sevClass := "fc-medium"}}
{{if eq .severity "Critical"}}{{$sevClass = "fc-critical"}}{{end}}
{{if eq .severity "High"}}{{$sevClass = "fc-high"}}{{end}}
<div class="fc {{$sevClass}}">
  <div class="fc-stripe"></div>
  <div class="fc-header">
    <div class="fc-sev-block {{lower .severity}}">
      {{if eq .severity "Critical"}}&#9650;{{else}}&#8679;{{end}} {{upper .severity}}
    </div>
    <div class="fc-heading">
      <div class="fc-name{{if eq .severity "Critical"}} critical{{end}}">
        {{.techniqueName}}
        {{$actors := techActors .techniqueId}}{{if $actors}}&nbsp;<span style="font-size:0.62rem;color:#9aa5b5;font-weight:400">&#8212; {{range $i,$a := $actors}}{{if $i}}, {{end}}{{$a}}{{end}}</span>{{end}}
      </div>
      <div class="fc-tid">{{.techniqueId}} &nbsp;&#183;&nbsp; {{humanize .tactic}} &nbsp;&#183;&nbsp; Duration: {{if .durationMs}}{{.durationMs}}ms{{else}}&#8212;{{end}}{{if .framework}} &nbsp;&#183;&nbsp; <span style="color:#58a6ff;font-weight:700;text-transform:uppercase;font-size:0.52rem">{{.framework}}</span>{{end}}</div>
    </div>
    <span class="vb vb-missed">&#10007; EVADED</span>
  </div>
  <div class="fc-body">
    <div class="fc-grid">
      <div>
        <div class="fc-detail-row">
          <div class="fc-detail-label">What Happened</div>
          {{if .details}}<div class="fc-detail-value">{{.details}}</div>
          {{else}}<div class="fc-detail-value" style="color:#da3633;font-weight:600">Technique executed to completion without being blocked or detected. No security control intervened during the simulation window.</div>{{end}}
        </div>
        {{if or .executedAs .requestedPriv}}<div class="fc-detail-row">
          <div class="fc-detail-label">Executed As</div>
          <div class="fc-detail-value">
            {{if .executedAs}}<span style="font-family:monospace;font-size:0.72rem;font-weight:700;
              {{if eq .executedAs "System"}}color:#da3633{{else if eq .executedAs "Admin"}}color:#f0883e{{else if contains .executedAs "→"}}color:#d29922{{else if eq .executedAs "Legacy"}}color:#9aa5b5{{else}}color:#2563eb{{end}}">{{.executedAs}}</span>{{end}}
            {{if and .requestedPriv (ne .requestedPriv .executedAs)}}<span style="color:#9aa5b5;font-size:0.65rem"> (requested: {{.requestedPriv}})</span>{{end}}
            {{if and .requestedPrivMin (ne .requestedPrivMin "Legacy")}}<span style="color:#9aa5b5;font-size:0.63rem;margin-left:4px">&#9492; min: {{.requestedPrivMin}}{{if and .requestedPrivPref (ne .requestedPrivPref "Legacy")}} / preferred: {{.requestedPrivPref}}{{end}}</span>{{end}}
          </div>
        </div>
        {{$pc := privConclusion .executedAs .execVerdict}}{{if $pc}}<div style="font-size:0.75rem;color:#c9d1d9;line-height:1.65;padding:8px 12px;background:#0d1117;border-radius:6px;border-left:3px solid #30363d;margin-bottom:7px">{{$pc}}</div>{{end}}
        {{end}}
        <div class="fc-detail-row">
          <div class="fc-detail-label">Blocked By</div>
          <div class="fc-detail-value">
            {{if .controlName}}<span class="fc-blocked-by">&#128737; {{.controlName}}{{if .controlRuleId}} &nbsp;&#183;&nbsp; {{.controlRuleId}}{{end}}</span>
            {{else}}<span class="fc-blocked-none">&#10007; None &#8212; no control prevented this technique</span>{{end}}
          </div>
        </div>
        <div class="fc-detail-row">
          <div class="fc-detail-label">Detection</div>
          <div class="fc-detail-value">
            {{if eq .detectionVerdict "detected"}}
              <span style="color:#2f81f7;font-weight:700">&#9679; Alert raised</span>
              {{if .alertProvider}} &nbsp;&#183;&nbsp; <strong>{{.alertProvider}}</strong>{{end}}
              {{if .alertEventId}} &nbsp;&#183;&nbsp; Event {{.alertEventId}}{{end}}
              {{if .mttdMs}} &nbsp;&#183;&nbsp; MTTD: <strong>{{mttd .mttdMs}}</strong>{{end}}
              {{if .alertThreatName}}<br><span style="font-size:0.68rem;color:#6e7681">{{.alertThreatName}}</span>{{end}}
            {{else}}<span style="color:#da3633;font-weight:600">&#10007; No detection &#8212; technique executed unseen</span>{{end}}
          </div>
        </div>
      </div>
      <div>
        <div class="fc-evidence">
          <div class="fc-ev-hdr">Execution Evidence</div>
          <div class="fc-ev-row"><div class="fc-ev-k">Exec Verdict</div><div class="fc-ev-v bad">FAIL — technique ran to completion; no control blocked execution</div></div>
          {{if .durationMs}}<div class="fc-ev-row"><div class="fc-ev-k">Duration</div><div class="fc-ev-v">{{.durationMs}} ms</div></div>{{end}}
          {{if .command}}<div class="fc-ev-row"><div class="fc-ev-k">Command Used</div><div class="fc-ev-v code" style="word-break:break-all;font-size:0.62rem;line-height:1.5">{{.command}}</div></div>{{end}}
          {{if .framework}}<div class="fc-ev-row"><div class="fc-ev-k">Framework</div><div class="fc-ev-v"><span style="color:#58a6ff;font-weight:700;text-transform:uppercase">{{.framework}}</span></div></div>{{end}}
          {{if .alertProvider}}<div class="fc-ev-sec">
            <div class="fc-ev-sec-lbl">Detection Details</div>
            {{if .alertProvider}}<div class="fc-ev-row"><div class="fc-ev-k">Source</div><div class="fc-ev-v">{{.alertProvider}}</div></div>{{end}}
            {{if .alertEventId}}<div class="fc-ev-row"><div class="fc-ev-k">Event ID</div><div class="fc-ev-v">{{.alertEventId}}</div></div>{{end}}
            {{if .alertThreatName}}<div class="fc-ev-row"><div class="fc-ev-k">Threat Name</div><div class="fc-ev-v code">{{.alertThreatName}}</div></div>{{end}}
            {{if .mttdMs}}<div class="fc-ev-row"><div class="fc-ev-k">MTTD</div><div class="fc-ev-v warn">{{mttd .mttdMs}}</div></div>{{end}}
            {{if .confidence}}<div class="fc-ev-row"><div class="fc-ev-k">Confidence</div><div class="fc-ev-v">{{.confidence}}</div></div>{{end}}
          {{end}}</div>
          <div class="fc-ev-sec">
            <div class="fc-ev-sec-lbl">Cleanup &amp; Residual Risk</div>
            {{if eq (str .cleanupVerdict) "reverted"}}
              <div class="fc-ev-row"><div class="fc-ev-k">Cleanup</div><div class="fc-ev-v ok">&#10003; Reverted</div></div>
              <div class="fc-ev-row"><div class="fc-ev-k">Residual Risk</div><div class="fc-ev-v fc-rr-none">None</div></div>
            {{else if eq (str .cleanupVerdict) "partial"}}
              <div class="fc-ev-row"><div class="fc-ev-k">Cleanup</div><div class="fc-ev-v warn">Partial</div></div>
              <div class="fc-ev-row"><div class="fc-ev-k">Residual Risk</div><div class="fc-ev-v fc-rr-partial">Partial &#8212; artifacts may remain; manual review advised</div></div>
            {{else if eq (str .cleanupVerdict) "leaked"}}
              <div class="fc-ev-row"><div class="fc-ev-k">Cleanup</div><div class="fc-ev-v bad">Leaked (timeout / failure)</div></div>
              <div class="fc-ev-row"><div class="fc-ev-k">Residual Risk</div><div class="fc-ev-v fc-rr-leaked">Manual verification required</div></div>
            {{else}}
              <div class="fc-ev-row"><div class="fc-ev-k">Residual Risk</div><div class="fc-ev-v fc-rr-none-dash">&#8212;</div></div>
            {{end}}
          </div>
        </div>
      </div>
    </div>
    {{if .businessImpact}}
    <div style="background:#fffbeb;border:1px solid #fde68a;border-left:4px solid #d29922;border-radius:0 7px 7px 0;padding:10px 14px;margin-top:8px">
      <div style="font-size:0.6rem;font-weight:800;text-transform:uppercase;letter-spacing:0.1em;color:#92400e;margin-bottom:4px">&#9888; Business Impact</div>
      <div style="font-size:0.8rem;color:#78350f;line-height:1.55">{{.businessImpact}}</div>
    </div>
    {{end}}
    {{if .remediation}}
    <div class="fc-remediation">
      <div class="fc-rem-label">&#9654; Recommended Remediation</div>
      <div class="fc-rem-text">{{.remediation}}</div>
    </div>
    {{end}}
    {{if or .remPlan.priority .remPlan.owner}}
    <div style="margin-top:12px;border-top:1px solid #e7eaf0;padding-top:10px">
      <div style="font-size:0.6rem;font-weight:800;text-transform:uppercase;letter-spacing:0.1em;color:#6e7681;margin-bottom:8px">&#9654; Remediation Plan</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px">
        {{if .remPlan.priority}}<div style="background:#f8faff;border:1px solid #e7eaf0;border-radius:6px;padding:7px 10px">
          <div style="font-size:0.5rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#9aa5b5;margin-bottom:2px">Priority</div>
          <div style="font-size:0.78rem;font-weight:800;color:{{if eq .remPlan.priority "Critical"}}#da3633{{else if eq .remPlan.priority "High"}}#f0883e{{else if eq .remPlan.priority "Medium"}}#d29922{{else}}#0d9488{{end}}">{{.remPlan.priority}}</div>
        </div>{{end}}
        {{if .remPlan.owner}}<div style="background:#f8faff;border:1px solid #e7eaf0;border-radius:6px;padding:7px 10px">
          <div style="font-size:0.5rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#9aa5b5;margin-bottom:2px">Owner</div>
          <div style="font-size:0.72rem;font-weight:600;color:#24292f;line-height:1.4">{{.remPlan.owner}}</div>
        </div>{{end}}
        {{if .remPlan.effort}}<div style="background:#f8faff;border:1px solid #e7eaf0;border-radius:6px;padding:7px 10px">
          <div style="font-size:0.5rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#9aa5b5;margin-bottom:2px">Estimated Effort</div>
          <div style="font-size:0.78rem;font-weight:600;color:#24292f">{{.remPlan.effort}}</div>
        </div>{{end}}
        {{if .remPlan.verification}}<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:7px 10px;grid-column:span 2">
          <div style="font-size:0.5rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#166534;margin-bottom:3px">How to Verify Fix</div>
          <div style="font-size:0.68rem;color:#166534;line-height:1.55">{{.remPlan.verification}}</div>
        </div>{{end}}
      </div>
    </div>
    {{end}}
  </div>
</div>
{{end}}
{{end}}
{{else if .topFindings}}
<p style="color:#6e7681;margin-bottom:14px">Critical and High severity technique failures from the latest run.</p>
<table>
  <thead><tr><th>Severity</th><th>Technique</th><th>Tactic</th><th>Details &amp; Remediation</th></tr></thead>
  <tbody>
  {{range .topFindings}}
  <tr>
    <td><span class="dot" style="background:{{sevColor .severity}}"></span>{{.severity}}</td>
    <td><code>{{.techniqueId}}</code>{{if .kev}}&nbsp;<span style="background:#fef2f2;color:#991b1b;border:1px solid #fca5a5;border-radius:3px;padding:1px 5px;font-size:0.65rem;font-weight:700;vertical-align:middle">KEV</span>{{end}}<br>{{.techniqueName}}</td>
    <td>{{humanize .tactic}}</td>
    <td>{{.details}}{{if .remediation}}<div class="remediation">{{.remediation}}</div>{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{else}}
<p style="color:#0d9488;font-weight:600">&#10003; No Critical or High severity failures in the latest run. Continue to validate with future assessments.</p>
{{end}}

<div class="pf">
  <span>{{.agent.hostname}} — Technical Findings</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 17. ENVIRONMENT RESTORATION ════════════════════════════════════════ -->
{{if .envRestoration}}{{if .envRestoration.hasData}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 17</div>
<div class="stitle">Environment Restoration</div>

<p style="color:#6e7681;margin-bottom:14px">Documents whether all simulation-induced environment changes were successfully reverted. Answers the key enterprise question: <em>"Did the BAS restore everything it touched?"</em></p>

{{/* ── Headline status card ── */}}
<div style="border-radius:8px;padding:20px 24px;margin-bottom:20px;
  {{if eq .envRestoration.impactLevel "clean"}}background:#f0fdf4;border:2px solid #86efac
  {{else if eq .envRestoration.impactLevel "minor"}}background:#fffbeb;border:2px solid #fde68a
  {{else}}background:#fef2f2;border:2px solid #fca5a5{{end}}">
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
    <div style="font-size:2.4rem;line-height:1;
      {{if eq .envRestoration.impactLevel "clean"}}color:#15803d{{else if eq .envRestoration.impactLevel "minor"}}color:#d97706{{else}}color:#991b1b{{end}}">
      {{if eq .envRestoration.impactLevel "clean"}}&#10003;{{else if eq .envRestoration.impactLevel "minor"}}&#9888;{{else}}&#10007;{{end}}
    </div>
    <div>
      <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;
        {{if eq .envRestoration.impactLevel "clean"}}color:#15803d{{else if eq .envRestoration.impactLevel "minor"}}color:#92400e{{else}}color:#991b1b{{end}}">
        Environment Restoration
      </div>
      <div style="font-size:1.4rem;font-weight:800;
        {{if eq .envRestoration.impactLevel "clean"}}color:#15803d{{else if eq .envRestoration.impactLevel "minor"}}color:#92400e{{else}}color:#991b1b{{end}}">
        {{.envRestoration.statusLabel}}
      </div>
      <div style="font-size:0.9rem;font-weight:600;margin-top:2px;
        {{if eq .envRestoration.impactLevel "clean"}}color:#166534{{else if eq .envRestoration.impactLevel "minor"}}color:#78350f{{else}}color:#7f1d1d{{end}}">
        {{.envRestoration.impactLabel}}
      </div>
    </div>
  </div>
  <div style="font-size:0.88rem;line-height:1.5;color:#374151">{{.envRestoration.execSummary}}</div>
</div>

{{/* ── KPI tiles ── */}}
<div class="score-row">
  <div class="scard" style="border-left:3px solid {{if gt .envRestoration.cleanupRate 99.9}}#0d9488{{else if gt .envRestoration.cleanupRate 79.9}}#d29922{{else}}#da3633{{end}}">
    <div class="scard-label">Cleanup Success Rate</div>
    <div class="scard-value" style="color:{{if gt .envRestoration.cleanupRate 99.9}}#0d9488{{else if gt .envRestoration.cleanupRate 79.9}}#d29922{{else}}#da3633{{end}}">{{printf "%.1f" .envRestoration.cleanupRate}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{printf "%.0f" .envRestoration.cleanupRate}}%;background:{{if gt .envRestoration.cleanupRate 99.9}}#0d9488{{else if gt .envRestoration.cleanupRate 79.9}}#d29922{{else}}#da3633{{end}}"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">stepsCleaned / (cleaned + leaked)</div>
  </div>
  <div class="scard">
    <div class="scard-label">Coverage Rate</div>
    <div class="scard-value" style="color:#2563eb">{{printf "%.0f" .envRestoration.coverageRate}}%</div>
    <div class="scard-bar"><div class="scard-bar-fill" style="width:{{printf "%.0f" .envRestoration.coverageRate}}%;background:#2563eb"></div></div>
    <div style="font-size:0.72rem;color:#6e7681;margin-top:5px">Steps with cleanup defined</div>
  </div>
  <div class="scard" style="border-left:3px solid #0d9488">
    <div class="scard-label">Steps Cleaned</div>
    <div class="scard-value" style="color:#0d9488">{{.envRestoration.stepsCleaned}}</div>
    <div style="font-size:0.78rem;color:#6e7681">of {{.envRestoration.stepsWithCleanup}} cleanup-capable</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .envRestoration.stepsLeaked 0.0}}#da3633{{else}}#6e7681{{end}}">
    <div class="scard-label">Steps Leaked</div>
    <div class="scard-value" style="color:{{if gt .envRestoration.stepsLeaked 0.0}}#da3633{{else}}#6e7681{{end}}">{{.envRestoration.stepsLeaked}}</div>
    <div style="font-size:0.78rem;color:#6e7681">cleanup failed or timed out</div>
  </div>
  {{if gt .envRestoration.revertedCount 0.0}}
  <div class="scard">
    <div class="scard-label">Agent-Confirmed Rollbacks</div>
    <div class="scard-value" style="color:#0d9488">{{.envRestoration.revertedCount}}</div>
    <div style="font-size:0.78rem;color:#6e7681">endpoint changes confirmed reverted</div>
  </div>
  {{end}}
  {{if gt .envRestoration.stepsNoCleanup 0.0}}
  <div class="scard">
    <div class="scard-label">No Cleanup Defined</div>
    <div class="scard-value" style="color:#6e7681">{{.envRestoration.stepsNoCleanup}}</div>
    <div style="font-size:0.78rem;color:#6e7681">steps with no cleanup command</div>
  </div>
  {{end}}
</div>

{{if .envRestoration}}
{{/* ── Campaign run breakdown (only for campaign reports with multi-run data) ── */}}
{{if gt (num .envRestoration.runCount) 1.0}}
<div style="background:#f7f9fc;border-radius:6px;padding:12px 16px;margin-top:16px;font-size:0.85rem">
  <div style="font-weight:700;color:#1e293b;margin-bottom:6px">Campaign Run Breakdown</div>
  <div style="display:flex;gap:24px;color:#374151">
    <span>Total Runs: <strong>{{.envRestoration.runCount}}</strong></span>
    <span style="color:#15803d">Perfect Cleanup: <strong>{{.envRestoration.runsClean}}</strong></span>
    <span style="color:{{if gt (num .envRestoration.runsWithIssues) 0.0}}#da3633{{else}}#6e7681{{end}}">Residual Changes: <strong>{{.envRestoration.runsWithIssues}}</strong></span>
  </div>
</div>
{{end}}

{{/* ── Leaked steps detail table ── */}}
{{if gt .envRestoration.stepsLeaked 0.0}}
<h2 style="margin-top:20px">Steps Requiring Manual Remediation</h2>
<p style="color:#da3633;font-size:0.82rem;margin-bottom:10px">The following techniques did not successfully revert their cleanup commands. Review and remediate manually.</p>
<table>
  <thead><tr>
    <th>Technique</th>
    <th>Tactic</th>
    <th>Verdict</th>
    <th>Cleanup Status</th>
  </tr></thead>
  <tbody>
  {{range .techniqueMatrix}}{{if or (eq (str .cleanupVerdict) "partial") (eq (str .cleanupVerdict) "leaked")}}
  <tr>
    <td style="font-weight:600">{{.techniqueId}}{{if .techniqueName}}<br><span style="font-weight:400;font-size:0.78rem;color:#6e7681">{{.techniqueName}}</span>{{end}}</td>
    <td style="font-size:0.82rem;color:#6e7681">{{if .tactic}}{{humanize .tactic}}{{end}}</td>
    <td><span style="font-size:0.78rem;padding:2px 8px;border-radius:4px;font-weight:700;background:{{verdictBg .execVerdict}};color:{{verdictColor .execVerdict}}">{{upper .execVerdict}}</span></td>
    <td style="font-weight:700;color:{{cleanupVerdictColor .cleanupVerdict}}">{{cleanupVerdictLabel .cleanupVerdict}}</td>
  </tr>
  {{end}}{{end}}
  </tbody>
</table>
{{end}}
{{end}}

{{/* ── Agent-confirmed rollback list ── */}}
{{if .reverted}}
<h2 style="margin-top:20px">Agent-Confirmed Rollbacks</h2>
<p style="color:#6e7681;font-size:0.82rem;margin-bottom:8px">Endpoint changes confirmed reverted by the agent post-run.</p>
<ul style="padding-left:20px;color:#374151;font-size:0.82rem;line-height:1.8">{{range .reverted}}<li>{{.}}</li>{{end}}</ul>
{{end}}

<div class="pf">
  <span>{{.agent.hostname}} &#8212; Environment Restoration</span>
  {{template "pf-right" .}}
</div>
</div>
</div>
{{end}}{{end}}
<!-- ═══ 18. DETECTION VALIDATION ════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 18</div>
<div class="stitle">Detection Validation</div>

<p style="color:#6e7681;margin-bottom:14px">Per-technique outcome from the post-run EDR/alert sweep. <strong>PREVENTED</strong> = control blocked execution before it could run. <strong>DETECTED</strong> = technique executed and the security control raised an alert (detection source shown). <strong>UNDETECTED</strong> = technique executed with no alert — the security gap an attacker would exploit silently. Techniques where the agent has not yet submitted detection telemetry show "NO DATA".</p>

{{if .detectionValidation.hasData}}
{{$dv := .detectionValidation}}
<h3 style="margin-top:16px;margin-bottom:6px">Expected vs Observed — Control Validation</h3>
<p style="color:#6e7681;font-size:0.85rem;margin-bottom:6px">This scenario declares the detections a mature SOC is expected to produce. Each expected control is compared against what actually fired. <strong>Detection Coverage</strong> = weighted share of verifiable required/recommended controls that responded. <strong>Verification Completeness</strong> = share of expectations conclusively verified on-host; off-host SIEM/identity/cloud controls await manual attestation and are not counted as failures.</p>
{{if $dv.profiles}}
<p style="color:#9aa5b5;font-size:0.72rem;margin-bottom:14px">Validated against {{range $i, $p := $dv.profiles}}{{if $i}}, {{end}}<strong>{{$p.profile}}</strong>&nbsp;v{{$p.version}}{{end}}</p>
{{end}}

<div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap">
  <div style="flex:1;min-width:150px;padding:14px 16px;border-radius:6px;border:1px solid var(--line);background:var(--surface);text-align:center">
    <div style="font-size:0.62rem;color:#6e7681;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Detection Coverage</div>
    <div style="font-size:1.8rem;font-weight:700;color:{{compColor $dv.coverage}}">{{pct $dv.coverage}}</div>
    <div style="font-size:0.66rem;color:#6e7681">{{$dv.detected}} of {{$dv.verified}} verifiable responded</div>
  </div>
  <div style="flex:1;min-width:150px;padding:14px 16px;border-radius:6px;border:1px solid var(--line);background:var(--surface);text-align:center">
    <div style="font-size:0.62rem;color:#6e7681;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Verification Completeness</div>
    <div style="font-size:1.8rem;font-weight:700;color:{{compColor $dv.verificationCompleteness}}">{{pct $dv.verificationCompleteness}}</div>
    <div style="font-size:0.66rem;color:#6e7681">{{$dv.verified}} of {{$dv.expected}} expectations verified</div>
  </div>
  <div style="flex:1;min-width:150px;padding:14px 16px;border-radius:6px;border:1px solid var(--line);background:var(--surface);text-align:center">
    <div style="font-size:0.62rem;color:#6e7681;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Telemetry Completeness</div>
    <div style="font-size:1.8rem;font-weight:700;color:{{compColor $dv.telemetryCompleteness}}">{{pct $dv.telemetryCompleteness}}</div>
    <div style="font-size:0.66rem;color:#6e7681">expected event IDs observed</div>
  </div>
</div>

{{if $dv.byDomain}}
<h4 style="margin-top:8px;margin-bottom:8px">Validation by Domain</h4>
<table style="width:100%;margin-bottom:20px;max-width:680px">
  <thead><tr>
    <th style="text-align:left">Domain</th>
    <th style="text-align:right">Expected</th>
    <th style="text-align:right">Verified</th>
    <th style="text-align:right">Detected</th>
    <th style="text-align:right">Coverage</th>
    <th style="text-align:right">Verification</th>
  </tr></thead>
  <tbody>
  {{range $dv.byDomain}}
  <tr>
    <td style="text-transform:capitalize">{{.domain}}</td>
    <td style="text-align:right">{{.expected}}</td>
    <td style="text-align:right">{{.verified}}</td>
    <td style="text-align:right">{{.detected}}</td>
    <td style="text-align:right;font-weight:600;color:{{compColor .coverage}}">{{if .verified}}{{pct .coverage}}{{else}}—{{end}}</td>
    <td style="text-align:right;color:#6e7681">{{pct .verificationCompleteness}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<h4 style="margin-top:8px;margin-bottom:8px">Expected Detections</h4>
<table style="width:100%;margin-bottom:20px">
  <thead><tr>
    <th style="text-align:left">Technique</th>
    <th style="text-align:left">Expected Control</th>
    <th style="text-align:left">Domain</th>
    <th style="text-align:left">Confidence</th>
    <th style="text-align:left">Verification</th>
    <th style="text-align:left">Status</th>
    <th style="text-align:left">Observed Source</th>
    <th style="text-align:left">Analyst</th>
    <th style="text-align:left">Verified</th>
    <th style="text-align:left">Evidence</th>
    <th style="text-align:left">Integrity</th>
  </tr></thead>
  <tbody>
  {{range $dv.rows}}
  <tr>
    <td><code style="font-size:0.75rem">{{.techniqueId}}</code></td>
    <td style="font-size:0.82rem"><strong>{{.provider}}</strong></td>
    <td style="font-size:0.8rem;text-transform:capitalize;color:#6e7681">{{.domain}}</td>
    <td style="font-size:0.8rem;text-transform:capitalize">{{.confidence}}</td>
    <td style="font-size:0.8rem;text-transform:capitalize;color:#6e7681">{{.verification}}</td>
    <td>
      <span style="font-size:0.76rem;font-weight:700;color:{{dvStatusColor .status}}">{{dvStatusLabel .status}}</span>
      {{if .workflowState}}{{if ne .workflowState "Approved"}}<span style="font-size:0.64rem;color:#d29922;display:block">{{.workflowState}}</span>{{end}}{{end}}
    </td>
    <td style="font-size:0.76rem;color:#6e7681;max-width:160px;word-break:break-word">{{if .source}}{{.source}}{{else}}—{{end}}</td>
    <td style="font-size:0.76rem;color:#6e7681">{{if .analyst}}{{.analyst}}{{else}}—{{end}}</td>
    <td style="font-size:0.72rem;color:#6e7681;white-space:nowrap">{{if .timestamp}}{{.timestamp}}{{else}}—{{end}}</td>
    <td style="font-size:0.76rem;color:#6e7681;text-align:center">{{if .evidenceCount}}{{.evidenceCount}}{{else}}—{{end}}</td>
    <td style="font-size:0.7rem;color:#238636;max-width:150px">{{if .integrity}}✓ {{.integrity}}{{else}}—{{end}}</td>
  </tr>
  {{end}}
  </tbody>
</table>

{{if $dv.falseSilence}}
<h4 style="margin-top:8px;margin-bottom:6px">Gap Analysis — False Silence</h4>
<p style="color:#6e7681;font-size:0.82rem;margin-bottom:12px">Required or recommended controls that stayed silent when the technique executed. Each is an exploitable blind spot: the adversary action succeeded without raising the alert your policy expects.</p>
{{range $dv.falseSilence}}
<div style="border:1px solid var(--line);border-left:4px solid {{sevColor .severity}};border-radius:6px;padding:12px 14px;margin-bottom:10px;background:var(--surface)">
  <div style="display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:4px">
    <div style="font-weight:600;font-size:0.9rem">{{.title}}</div>
    <span style="font-size:0.66rem;font-weight:700;text-transform:uppercase;color:{{sevColor .severity}};white-space:nowrap">{{.severity}}</span>
  </div>
  <div style="font-size:0.74rem;color:#6e7681;margin-bottom:6px"><code>{{.techniqueId}}</code> · {{.provider}} · <span style="text-transform:capitalize">{{.domain}}</span> · <span style="text-transform:capitalize">{{.confidence}}</span> control</div>
  {{if .remediation}}<div style="font-size:0.8rem;margin-bottom:4px"><strong>Remediation:</strong> {{.remediation}}</div>{{end}}
  {{if .reference}}<div style="font-size:0.72rem;color:#9aa5b5">Reference: {{.reference}}</div>{{end}}
</div>
{{end}}
{{end}}

{{if $dv.unexpectedDetections}}
<h4 style="margin-top:16px;margin-bottom:6px">Unexpected Detections</h4>
<p style="color:#6e7681;font-size:0.82rem;margin-bottom:12px">Controls that alerted with no matching expectation for the step. Confirm each is intended coverage rather than a noisy or duplicate rule.</p>
<table style="width:100%;margin-bottom:20px">
  <thead><tr><th style="text-align:left">Technique</th><th style="text-align:left">Alerting Control</th><th style="text-align:left">Severity</th><th style="text-align:left">Note</th></tr></thead>
  <tbody>
  {{range $dv.unexpectedDetections}}
  <tr>
    <td><code style="font-size:0.75rem">{{.techniqueId}}</code></td>
    <td style="font-size:0.82rem">{{.provider}}</td>
    <td style="font-size:0.78rem;color:#d29922">{{.severity}}</td>
    <td style="font-size:0.76rem;color:#6e7681">{{.detail}}</td>
  </tr>
  {{end}}
  </tbody>
</table>
{{end}}

<hr style="border:none;border-top:1px solid var(--line);margin:24px 0">
{{end}}

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
    <th>Technique</th><th>Tactic</th><th>Sev</th><th>Execution</th><th>Requested Priv</th><th>Executed As</th><th>Detection</th><th>Alert Source</th><th>Event&nbsp;ID</th><th>Threat&nbsp;/&nbsp;Process</th><th>MTTD</th><th>Cleanup</th><th>Blocking Control</th>
  </tr></thead>
  <tbody>
  {{range .techniqueMatrix}}
  <tr>
    <td><code style="font-size:0.78rem">{{.techniqueId}}</code><br><span style="font-size:0.8rem">{{.techniqueName}}</span></td>
    <td style="font-size:0.8rem;color:#6e7681">{{humanize .tactic}}</td>
    <td><span class="dot" style="background:{{sevColor .severity}}"></span>{{.severity}}</td>
    <td><span style="font-size:0.78rem;font-weight:600;color:{{execVerdictColor .execVerdict}}">{{upper .execVerdict}}</span></td>
    <td style="font-size:0.78rem;color:#6e7681;white-space:nowrap">
      {{.requestedPriv}}
      {{if and .requestedPrivMin (ne .requestedPrivMin "Legacy") (ne .requestedPrivPref "")}}<span style="font-size:0.65rem;color:#9aa5b5;display:block">min:{{.requestedPrivMin}} / pref:{{.requestedPrivPref}}</span>{{end}}
    </td>
    <td style="font-size:0.78rem;white-space:nowrap;{{if contains .executedAs "→"}}color:#d29922;font-weight:600{{else if eq .executedAs "Legacy"}}color:#6e7681{{else}}color:#9aa9bc{{end}}">{{.executedAs}}</td>
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

<div class="pf">
  <span>{{.agent.hostname}} — Detection Validation</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 19. COVERAGE ANALYTICS ══════════════════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 19</div>
<div class="stitle">Coverage Analytics</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — Coverage Analytics</span>
  {{template "pf-right" .}}
</div>
</div>
</div>

<!-- ═══ 20. TECHNICAL APPENDIX — GLOSSARY ═══════════════════════════════ -->
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 20</div>
<div class="stitle">Technical Appendix — ATT&amp;CK Glossary</div>

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

<div class="pf">
  <span>{{.agent.hostname}} — ATT&amp;CK Glossary</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>
</div>

<!-- ═══ 21. THREAT INTELLIGENCE ═══════════════════════════════════════════ -->
{{if .threatIntel}}
<div class="page">
<div class="inner">
<div class="ph">
  <div class="ph-left">
    <div class="ph-logo">Aud<span>spect</span> BAS</div>
    <div class="ph-sep"></div>
    <div class="ph-title">{{if .scope}}{{.scope.title}}{{else}}{{.summary.lastScenarioName}}{{end}}</div>
  </div>
  <div class="ph-right">
    <div class="ph-endpoint">{{if .scope}}Campaign{{else}}{{.agent.hostname}}{{end}}</div>
    <div class="ph-class">CONFIDENTIAL</div>
  </div>
</div>
<div class="stag">Section 21</div>
<div class="stitle">Threat Intelligence</div>

<p style="color:#6e7681;margin-bottom:14px">Indicators of compromise (IPs, domains, URLs, file hashes, CVEs) observed in this run's execution evidence, checked against {{.threatIntel.provider}} threat intelligence. Answers: did this execution produce artifacts already known to the security community?</p>

<div class="score-row">
  <div class="scard">
    <div class="scard-label">Extracted IOCs</div>
    <div class="scard-value">{{.threatIntel.summary.extractedCount}}</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .threatIntel.summary.maliciousAssociatedCount 0.0}}#da3633{{else}}#6e7681{{end}}">
    <div class="scard-label">Malicious-Associated</div>
    <div class="scard-value" style="color:{{if gt .threatIntel.summary.maliciousAssociatedCount 0.0}}#da3633{{else}}#6e7681{{end}}">{{.threatIntel.summary.maliciousAssociatedCount}}</div>
  </div>
  <div class="scard" style="border-left:3px solid {{if gt .threatIntel.summary.suspiciousCount 0.0}}#d29922{{else}}#6e7681{{end}}">
    <div class="scard-label">Suspicious</div>
    <div class="scard-value" style="color:{{if gt .threatIntel.summary.suspiciousCount 0.0}}#d29922{{else}}#6e7681{{end}}">{{.threatIntel.summary.suspiciousCount}}</div>
  </div>
  <div class="scard">
    <div class="scard-label">Unknown</div>
    <div class="scard-value">{{.threatIntel.summary.unknownCount}}</div>
  </div>
  <div class="scard">
    <div class="scard-label">Pending</div>
    <div class="scard-value">{{.threatIntel.summary.pendingCount}}</div>
  </div>
</div>

<table>
  <thead><tr><th>Type</th><th>Indicator</th><th>Technique(s)</th><th>Tier</th><th>Pulses</th><th>Malware / Adversary / Tags</th></tr></thead>
  {{range .threatIntel.indicators}}
  <tr>
    <td>{{upper .type}}</td>
    <td style="font-family:monospace;font-size:0.78rem">{{.value}}</td>
    <td style="font-size:0.78rem">{{range $i,$t := .techniqueIds}}{{if $i}}, {{end}}{{$t}}{{end}}</td>
    <td><strong style="{{if eq .tier "malicious-associated"}}color:#da3633{{else if eq .tier "suspicious"}}color:#d29922{{else if eq .tier "pending"}}color:#6e7681{{else}}color:#374151{{end}}">{{if eq .tier "malicious-associated"}}Malicious-Associated{{else if eq .tier "suspicious"}}Suspicious{{else if eq .tier "pending"}}Pending{{else}}Unknown{{end}}</strong></td>
    <td>{{.pulseCount}}</td>
    <td style="font-size:0.78rem">{{range $i,$m := .malwareFamilies}}{{if $i}}, {{end}}{{$m}}{{end}}{{if and .malwareFamilies .adversaryNames}} &nbsp;·&nbsp; {{end}}{{range $i,$a := .adversaryNames}}{{if $i}}, {{end}}{{$a}}{{end}}{{if and (or .malwareFamilies .adversaryNames) .tags}} &nbsp;·&nbsp; {{end}}{{range $i,$g := .tags}}{{if $i}}, {{end}}{{$g}}{{end}}</td>
  </tr>
  {{end}}
</table>

<div class="pf">
  <span>{{.agent.hostname}} — Threat Intelligence</span>
  <span>Generated {{fmtTime .generatedAt}} &nbsp;·&nbsp; Audspect BAS Platform &nbsp;·&nbsp; CONFIDENTIAL</span>
</div>
</div>
</div>
{{end}}

</body>
</html>`
