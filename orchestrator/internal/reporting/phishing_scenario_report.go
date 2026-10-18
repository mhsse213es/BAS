package reporting

// Phishing scenario run report -- HTML only, mirroring
// av_efficacy_scenario.go's lightweight wiring pass with one
// deliberate divergence: this report sources from an already-
// persisted phishingrun.PhishingRun (via its Result column), never a
// live re-evaluation. av_efficacy_scenario.go's own
// avefficacy.EvaluateScenarioBySlug call recomputes fresh on every
// render; a phishing run's acceptance criteria require the report to
// reflect exactly what was recorded when the run completed, since a
// live recomputation could drift from the persisted Outcome (a later
// catalog edit, a provider whose answer changed) and silently show a
// different verdict than the one actually stored.

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishingrun"
	"github.com/audspect/bas/internal/phishval"
)

// PhishingReportDimension is one dimension's graded result, carried
// into the report verbatim from the persisted phishval.Outcome.
type PhishingReportDimension struct {
	Name       string
	Verdict    string
	Reason     string
	Evidence   string
	Confidence string
}

// PhishingScenarioReport is the canonical input to
// PhishingScenarioReportHTML. Build it with BuildPhishingScenarioReport.
type PhishingScenarioReport struct {
	RunID        string
	ScenarioID   string
	ScenarioName string

	GeneratedAt    time.Time
	RunStartedAt   time.Time
	RunCompletedAt *time.Time
	RunStatus      string

	Dimensions         []PhishingReportDimension
	CatalogLimitations string
	// Experimental is true when this run's own evidence carries
	// EvidenceInferred on at least one dimension -- the exact signal
	// FromMFAFatigueHeuristic/FromSessionTheftResponseHeuristic/
	// FromSingleDimensionResponseVerdict-on-Inconclusive all produce.
	// Detected from the evidence itself, never from scenario ID string
	// matching, so this keeps working correctly if a future slice
	// registers PH-ID-004/PH-ID-005.
	Experimental bool
}

// BuildPhishingScenarioReport builds the report for an already-
// persisted run -- the one unmarshal of run.Result into a
// phishval.Outcome, never a re-evaluation. catalogEntry supplies the
// scenario's own Name/Limitations text (never hand-duplicated here).
func BuildPhishingScenarioReport(run *phishingrun.PhishingRun, catalogEntry phishcatalog.Scenario) (PhishingScenarioReport, error) {
	rep := PhishingScenarioReport{
		RunID:              run.ID,
		ScenarioID:         run.ScenarioID,
		ScenarioName:       catalogEntry.Name,
		GeneratedAt:        time.Now().UTC(),
		RunStartedAt:       run.StartedAt,
		RunCompletedAt:     run.CompletedAt,
		RunStatus:          string(run.Status),
		CatalogLimitations: catalogEntry.Limitations,
	}

	if len(run.Result) == 0 {
		// A run that hasn't reached a terminal status yet (pending/running)
		// has no Result -- the report renders the run's own Status as-is,
		// with zero dimensions, never a fabricated verdict.
		return rep, nil
	}

	var outcome phishval.Outcome
	if err := json.Unmarshal(run.Result, &outcome); err != nil {
		return PhishingScenarioReport{}, fmt.Errorf("reporting: unmarshal phishing run result: %w", err)
	}

	named := []struct {
		name string
		dim  phishval.DimensionResult
	}{
		{"Delivery", outcome.Delivery},
		{"Enforcement", outcome.Enforcement},
		{"Detection", outcome.Detection},
		{"UserInteraction", outcome.UserInteraction},
		{"Response", outcome.Response},
	}
	for _, n := range named {
		if n.dim.Verdict == "" || n.dim.Verdict == phishval.VerdictNotApplicable {
			continue
		}
		rep.Dimensions = append(rep.Dimensions, PhishingReportDimension{
			Name:       n.name,
			Verdict:    string(n.dim.Verdict),
			Reason:     n.dim.Reason,
			Evidence:   string(n.dim.Evidence),
			Confidence: string(n.dim.Confidence),
		})
		if n.dim.Evidence == phishval.EvidenceInferred {
			rep.Experimental = true
		}
	}

	return rep, nil
}

var phishingScenarioReportTmpl = template.Must(template.New("phishing-scenario-run").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.ScenarioName}}</title>
<style>
body{font-family:"Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif;color:#1a2332;background:#fff;margin:0;padding:32px;line-height:1.6}
h1{font-size:1.4rem;font-weight:800;margin-bottom:4px}
.generated{font-size:.75rem;color:#6b7689;margin-bottom:8px}
.meta{font-size:.8rem;color:#3a4656;margin-bottom:12px}
.status{display:inline-block;font-size:.85rem;font-weight:700;text-transform:uppercase;padding:4px 10px;border-radius:4px;margin-bottom:12px}
.status-completed{background:#e3f6e8;color:#1a7d3f}
.status-failed{background:#fdeaea;color:#b3261e}
.status-partial,.status-pending,.status-running{background:#f2f3f5;color:#5a6472}
.experimental{border:2px solid #b3261e;background:#fdeaea;color:#7a1a16;font-weight:700;padding:10px 14px;border-radius:6px;margin-bottom:16px}
.dim{border:1px solid #e8edf4;border-radius:8px;padding:10px 16px;margin-bottom:8px;font-size:.85rem}
.dim-head{font-weight:700}
.limitations{font-size:.75rem;color:#6b7689;margin-top:24px;border-top:1px solid #e8edf4;padding-top:12px}
</style>
</head>
<body>
<h1>{{.ScenarioName}}</h1>
<div class="generated">Generated {{.GeneratedAt.Format "02 Jan 2006 15:04 UTC"}} -- run {{.RunID}} ({{.ScenarioID}})</div>
<div class="status status-{{.RunStatus}}">{{.RunStatus}}</div>
{{if .Experimental}}
<div class="experimental">EXPERIMENTAL -- not a vendor-verified detection; see this scenario's own catalog Limitations below.</div>
{{end}}
{{range .Dimensions}}
<div class="dim">
  <div class="dim-head">{{.Name}}: {{.Verdict}} ({{.Confidence}}) -- {{.Reason}}</div>
  <div>Evidence: {{.Evidence}}</div>
</div>
{{end}}
{{if .CatalogLimitations}}
<div class="limitations">Limitations: {{.CatalogLimitations}}</div>
{{end}}
</body>
</html>
`))

// PhishingScenarioReportHTML renders rep as a plain styled HTML page.
// html/template auto-escapes every field, so a reason or scenario
// name can never inject markup into the page.
func PhishingScenarioReportHTML(w io.Writer, rep PhishingScenarioReport) error {
	return phishingScenarioReportTmpl.Execute(w, rep)
}
