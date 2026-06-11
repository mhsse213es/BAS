// Package reporting builds full assessment reports and audit-pack ZIPs.
package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// Engine aggregates data from the DB into structured reports.
type Engine struct {
	db *pgxpool.Pool
}

func NewEngine(db *pgxpool.Pool) *Engine { return &Engine{db: db} }

// ── Report types ──────────────────────────────────────────────────────────────

// FullReport is the complete assessment output for one agent.
type FullReport struct {
	GeneratedAt         time.Time        `json:"generatedAt"`
	Agent               models.Agent     `json:"agent"`
	Summary             ExecutiveSummary `json:"summary"`
	TacticHeatmap       []TacticEntry    `json:"tacticHeatmap"`
	TopFindings         []Finding        `json:"topFindings"`
	Runs                []RunSummary     `json:"runs"`
	SecurityTools       []string         `json:"securityTools"`
	DetectionCategories []Category       `json:"detectionCategories"`
	ObjectiveRisks      []ObjectiveRisk  `json:"objectiveRisks"`
	Reverted            []string         `json:"reverted"` // endpoint changes rolled back post-run (cleanup evidence)
}

// ObjectiveRisk expresses the run's outcome in business terms an executive cares
// about ("Can credentials be stolen?") rather than raw percentages. Derived from
// the per-tactic pass/fail of the run; ERROR/SKIPPED are excluded.
type ObjectiveRisk struct {
	Objective string `json:"objective"`
	Tactic    string `json:"tactic"`
	Risk      string `json:"risk"` // High | Medium | Low
	Tested    int    `json:"tested"`
	Failed    int    `json:"failed"`
}

// objectiveByTactic maps an ATT&CK tactic to the business objective an attacker
// achieves with it, in the order executives read risk.
var objectiveByTactic = []struct{ tactic, objective string }{
	{"credential-access", "Credential Theft"},
	{"privilege-escalation", "Privilege Escalation"},
	{"persistence", "Persistence"},
	{"lateral-movement", "Lateral Movement"},
	{"command-and-control", "Command & Control"},
	{"exfiltration", "Data Exfiltration"},
	{"impact", "Ransomware / Impact"},
	{"defense-evasion", "Defense Evasion"},
	{"execution", "Code Execution"},
	{"discovery", "Discovery"},
}

// buildObjectiveRisks rolls per-tactic results up to a business-objective risk
// band: High when most tested techniques in the objective went unprevented,
// Medium when some did, Low when all were blocked. Objectives with no executed
// techniques are omitted (we do not assert risk for untested objectives).
func buildObjectiveRisks(results []models.SimulationResult) []ObjectiveRisk {
	type agg struct{ tested, failed int }
	m := make(map[string]*agg)
	for _, r := range results {
		if r.Result == models.ResultError || r.Result == models.ResultSkipped {
			continue
		}
		a := m[r.Technique.Tactic]
		if a == nil {
			a = &agg{}
			m[r.Technique.Tactic] = a
		}
		a.tested++
		if r.Result == models.ResultFail {
			a.failed++
		}
	}
	var out []ObjectiveRisk
	for _, o := range objectiveByTactic {
		a := m[o.tactic]
		if a == nil || a.tested == 0 {
			continue
		}
		risk := "Low"
		switch {
		case a.failed == 0:
			risk = "Low"
		case a.failed*100/a.tested >= 50:
			risk = "High"
		default:
			risk = "Medium"
		}
		out = append(out, ObjectiveRisk{
			Objective: o.objective, Tactic: o.tactic, Risk: risk,
			Tested: a.tested, Failed: a.failed,
		})
	}
	return out
}

// ExecutiveSummary is the top-level risk picture derived from the latest run.
type ExecutiveSummary struct {
	RiskScore          int                      `json:"riskScore"`
	Classification     string                   `json:"classification"`
	PreventionScore    float64                  `json:"preventionScore"`
	ExposureScore      float64                  `json:"exposureScore"`
	CoverageScore      float64                  `json:"coverageScore"`      // defense rate — tactics fully blocked
	KillChainCoverage  float64                  `json:"killChainCoverage"`  // breadth — % of 14 ATT&CK tactics exercised
	KillChainAmplifier float64                  `json:"killChainAmplifier"`
	Trend              string                   `json:"trend"`
	TotalRuns          int                      `json:"totalRuns"`
	TotalTechniques    int                      `json:"totalTechniques"`
	PassedTechniques   int                      `json:"passedTechniques"`
	FailedTechniques   int                      `json:"failedTechniques"`
	ErroredTechniques  int                      `json:"erroredTechniques"` // BAS could not execute — excluded from scoring
	SkippedTechniques  int                      `json:"skippedTechniques"` // intentionally not run — excluded from scoring
	LastRunAt          time.Time                `json:"lastRunAt"`
	LastScenarioName   string                   `json:"lastScenarioName"`
	CriticalFailures   []models.CriticalFailure `json:"criticalFailures"`
	Recommendations    []string                 `json:"recommendations"`
}

// TacticEntry is one row of the ATT&CK tactic heatmap.
type TacticEntry struct {
	Tactic  string `json:"tactic"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Total   int    `json:"total"`
	PassPct int    `json:"passPct"`
	Weight  string `json:"weight"` // Critical | High | Medium | Low
}

// Finding is a single Critical or High severity failure surfaced in the report.
type Finding struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Tactic        string `json:"tactic"`
	Severity      string `json:"severity"`
	Details       string `json:"details"`
	Remediation   string `json:"remediation"`
	ScenarioName  string `json:"scenarioName"`
}

// RunSummary is one row in the Scenario Run History table.
type RunSummary struct {
	ID               string     `json:"id"`
	ScenarioName     string     `json:"scenarioName"`
	Status           string     `json:"status"`
	StartedAt        time.Time  `json:"startedAt"`
	CompletedAt      *time.Time `json:"completedAt,omitempty"`
	RiskScore        int        `json:"riskScore"`
	Classification   string     `json:"classification"`
	PreventionScore  float64    `json:"preventionScore"`
	ExposureScore    float64    `json:"exposureScore"`
	TotalTechniques  int        `json:"totalTechniques"`
	FailedTechniques int        `json:"failedTechniques"`
}

// Category is one detection category from the agent's posture report.
type Category struct {
	Name   string `json:"name"`
	Result string `json:"result"` // pass | fail | unknown
}

// ── Builder ───────────────────────────────────────────────────────────────────

// Build constructs a FullReport for the given agent from current DB state.
func (e *Engine) Build(ctx context.Context, agentID string) (*FullReport, error) {
	report := &FullReport{GeneratedAt: time.Now().UTC()}

	// ── 1. Agent metadata ─────────────────────────────────────────────────
	row := e.db.QueryRow(ctx,
		`SELECT agent_id, hostname, ip_address, os_version, username,
		        status, env_label, has_report, binary_hash, binary_trusted, last_update
		 FROM agents WHERE agent_id = $1`, agentID)
	if err := row.Scan(
		&report.Agent.AgentID, &report.Agent.Hostname, &report.Agent.IPAddress,
		&report.Agent.OSVersion, &report.Agent.Username, &report.Agent.Status,
		&report.Agent.EnvLabel, &report.Agent.HasReport,
		&report.Agent.BinaryHash, &report.Agent.BinaryTrusted, &report.Agent.LastUpdate,
	); err != nil {
		report.Agent.AgentID = agentID
	}

	// ── 2. Scenario run history (last 20) ─────────────────────────────────
	rows, err := e.db.Query(ctx,
		`SELECT id, name, status, score, started_at, completed_at
		 FROM scenario_runs
		 WHERE agent_id = $1
		 ORDER BY started_at DESC
		 LIMIT 20`, agentID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rs RunSummary
			var scoreRaw []byte
			rows.Scan(&rs.ID, &rs.ScenarioName, &rs.Status, &scoreRaw, &rs.StartedAt, &rs.CompletedAt)
			if len(scoreRaw) > 0 {
				var sc models.Score
				if json.Unmarshal(scoreRaw, &sc) == nil {
					rs.RiskScore = sc.RiskScore
					rs.Classification = sc.Classification
					rs.PreventionScore = sc.PreventionScore
					rs.ExposureScore = sc.ExposureScore
					rs.TotalTechniques = sc.TotalTechniques
					rs.FailedTechniques = sc.FailedTechniques
				}
			}
			report.Runs = append(report.Runs, rs)
		}
	}

	// ── 3. Latest completed run — for detailed analysis ────────────────────
	var latestResults []models.SimulationResult
	var latestScenarioName string
	var latestRunAt time.Time
	var latestScore models.Score

	latestRow := e.db.QueryRow(ctx,
		`SELECT name, results, score, started_at, reverted
		 FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial')
		 ORDER BY started_at DESC LIMIT 1`, agentID)
	var resultsRaw, scoreRaw2, revertedRaw []byte
	if err := latestRow.Scan(&latestScenarioName, &resultsRaw, &scoreRaw2, &latestRunAt, &revertedRaw); err == nil {
		json.Unmarshal(resultsRaw, &latestResults)
		json.Unmarshal(scoreRaw2, &latestScore)
		json.Unmarshal(revertedRaw, &report.Reverted)
	}

	// ── 4. Tactic heatmap from latest run ────────────────────────────────
	report.TacticHeatmap = buildTacticHeatmap(latestResults)

	// ── 5. Top findings (Critical + High failures) from latest run ────────
	report.TopFindings = buildTopFindings(latestResults, latestScenarioName)
	report.ObjectiveRisks = buildObjectiveRisks(latestResults)

	// ── 6. Executive summary ─────────────────────────────────────────────
	report.Summary = ExecutiveSummary{
		RiskScore:          latestScore.RiskScore,
		Classification:     latestScore.Classification,
		PreventionScore:    latestScore.PreventionScore,
		ExposureScore:      latestScore.ExposureScore,
		CoverageScore:      latestScore.CoverageScore,
		KillChainCoverage:  latestScore.KillChainCoverage,
		KillChainAmplifier: latestScore.KillChainAmplifier,
		Trend:              latestScore.Trend,
		TotalRuns:          len(report.Runs),
		TotalTechniques:    latestScore.TotalTechniques,
		PassedTechniques:   latestScore.PassedTechniques,
		FailedTechniques:   latestScore.FailedTechniques,
		ErroredTechniques:  latestScore.ErroredTechniques,
		SkippedTechniques:  latestScore.SkippedTechniques,
		LastRunAt:          latestRunAt,
		LastScenarioName:   latestScenarioName,
		CriticalFailures:   latestScore.CriticalFailures,
		Recommendations:    buildRecommendations(latestScore, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}

	// ── 7. Detection coverage by tactic (re-derived from live run results) ─
	// The legacy agent-submitted posture report (/api/report → reports table)
	// is no longer fed by the agent — it posts only to /api/scenarios/result.
	// Derive per-tactic verdicts from the latest run instead. SecurityTools has
	// no live source, so it is intentionally left empty.
	report.DetectionCategories = buildDetectionCategories(latestResults)

	return report, nil
}

// BuildFromRun constructs a FullReport scoped to a single scenario run.
// Useful for per-run export and HTML report without needing the full agent history.
func (e *Engine) BuildFromRun(ctx context.Context, runID string) (*FullReport, error) {
	report := &FullReport{GeneratedAt: time.Now().UTC()}

	var agentID, scenarioName, status string
	var resultsRaw, scoreRaw []byte
	var startedAt time.Time
	var completedAt *time.Time

	var revertedRaw []byte
	err := e.db.QueryRow(ctx,
		`SELECT agent_id, name, status, results, score, started_at, completed_at, reverted
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &scenarioName, &status, &resultsRaw, &scoreRaw, &startedAt, &completedAt, &revertedRaw)
	if err != nil {
		return nil, fmt.Errorf("run %s not found: %w", runID, err)
	}

	var results []models.SimulationResult
	var score models.Score
	json.Unmarshal(resultsRaw, &results)
	json.Unmarshal(scoreRaw, &score)
	json.Unmarshal(revertedRaw, &report.Reverted)

	// Agent metadata
	row := e.db.QueryRow(ctx,
		`SELECT agent_id, hostname, ip_address, os_version, username,
		        status, env_label, has_report, binary_hash, binary_trusted, last_update
		 FROM agents WHERE agent_id = $1`, agentID)
	row.Scan(
		&report.Agent.AgentID, &report.Agent.Hostname, &report.Agent.IPAddress,
		&report.Agent.OSVersion, &report.Agent.Username, &report.Agent.Status,
		&report.Agent.EnvLabel, &report.Agent.HasReport,
		&report.Agent.BinaryHash, &report.Agent.BinaryTrusted, &report.Agent.LastUpdate,
	)
	if report.Agent.AgentID == "" {
		report.Agent.AgentID = agentID
	}

	report.TacticHeatmap = buildTacticHeatmap(results)
	report.DetectionCategories = buildDetectionCategories(results)
	report.TopFindings = buildTopFindings(results, scenarioName)
	report.ObjectiveRisks = buildObjectiveRisks(results)

	report.Summary = ExecutiveSummary{
		RiskScore:          score.RiskScore,
		Classification:     score.Classification,
		PreventionScore:    score.PreventionScore,
		ExposureScore:      score.ExposureScore,
		CoverageScore:      score.CoverageScore,
		KillChainCoverage:  score.KillChainCoverage,
		KillChainAmplifier: score.KillChainAmplifier,
		Trend:              score.Trend,
		TotalRuns:          1,
		TotalTechniques:    score.TotalTechniques,
		PassedTechniques:   score.PassedTechniques,
		FailedTechniques:   score.FailedTechniques,
		ErroredTechniques:  score.ErroredTechniques,
		SkippedTechniques:  score.SkippedTechniques,
		LastRunAt:          startedAt,
		LastScenarioName:   scenarioName,
		CriticalFailures:   score.CriticalFailures,
		Recommendations:    buildRecommendations(score, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}

	report.Runs = []RunSummary{{
		ID: runID, ScenarioName: scenarioName, Status: status,
		StartedAt: startedAt, CompletedAt: completedAt,
		RiskScore: score.RiskScore, Classification: score.Classification,
		PreventionScore: score.PreventionScore, ExposureScore: score.ExposureScore,
		TotalTechniques: score.TotalTechniques, FailedTechniques: score.FailedTechniques,
	}}

	return report, nil
}

// TechniqueGroup aggregates every result for one ATT&CK technique so the report
// shows a single rolled-up entry with counts, instead of repeating the same
// technique (and its identical threat/remediation) dozens of times — the
// "report fatigue" the ART selective review flagged.
type TechniqueGroup struct {
	TechniqueID string
	Name        string
	Tactic      string
	Severity    string
	Executed    int // FAIL — ran without being blocked
	Blocked     int // PASS / BLOCKED — a control stopped it
	Errored     int // ERROR — BAS could not execute (excluded from scoring)
	Skipped     int // SKIPPED — intentionally not run
	Total       int
	Results     []models.SimulationResult
}

// groupResultsByTechnique rolls results up by technique ID (falling back to name
// for non-ATT&CK checks), preserving first-seen order. Counts are tallied per the
// 4-verdict taxonomy so the report can summarise ERROR/SKIPPED noise rather than
// rendering a block for each one.
func groupResultsByTechnique(results []models.SimulationResult) []TechniqueGroup {
	idx := make(map[string]int)
	var groups []TechniqueGroup
	for _, r := range results {
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		i, ok := idx[key]
		if !ok {
			i = len(groups)
			idx[key] = i
			groups = append(groups, TechniqueGroup{
				TechniqueID: r.Technique.ID,
				Name:        r.Technique.Name,
				Tactic:      r.Technique.Tactic,
				Severity:    r.Severity,
			})
		}
		g := &groups[i]
		g.Total++
		g.Results = append(g.Results, r)
		switch r.Result {
		case models.ResultFail:
			g.Executed++
		case models.ResultPass, models.ResultBlocked:
			g.Blocked++
		case models.ResultError:
			g.Errored++
		case models.ResultSkipped:
			g.Skipped++
		}
	}
	return groups
}

// ── helpers ───────────────────────────────────────────────────────────────────

var tacticOrder = []string{
	"initial-access", "execution", "persistence", "privilege-escalation",
	"defense-evasion", "credential-access", "discovery",
	"lateral-movement", "collection", "exfiltration", "command-and-control", "impact",
}

var tacticWeight = map[string]string{
	"credential-access": "Critical", "lateral-movement": "Critical", "privilege-escalation": "Critical",
	"persistence": "High", "defense-evasion": "High", "execution": "High",
	"command-and-control": "High", "impact": "High", "exfiltration": "High", "collection": "High",
	"initial-access": "Medium", "discovery": "Low", "reconnaissance": "Low",
}

func buildTacticHeatmap(results []models.SimulationResult) []TacticEntry {
	passed := make(map[string]int)
	failed := make(map[string]int)
	for _, r := range results {
		// ERROR (BAS could not execute) and SKIPPED (not run) are not security
		// outcomes — they must not taint a tactic as failed.
		if r.Result == models.ResultSkipped || r.Result == models.ResultError {
			continue
		}
		t := r.Technique.Tactic
		if t == "" {
			continue
		}
		if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
			passed[t]++
		} else {
			failed[t]++
		}
	}
	var out []TacticEntry
	for _, tactic := range tacticOrder {
		p, f := passed[tactic], failed[tactic]
		total := p + f
		if total == 0 {
			continue
		}
		pct := 0
		if total > 0 {
			pct = p * 100 / total
		}
		out = append(out, TacticEntry{
			Tactic: tactic, Passed: p, Failed: f, Total: total, PassPct: pct,
			Weight: tacticWeight[tactic],
		})
	}
	return out
}

// buildDetectionCategories rolls the run's checks up to a per-tactic verdict for
// the report's "Detection Coverage" section: a tactic is "pass" when all its
// executed checks passed, "fail" when any failed, "unknown" when it was only
// skipped. Re-derived from live results (each check carries its ATT&CK tactic),
// replacing the legacy agent-submitted posture report. Ordered by kill-chain
// phase and consistent with the tactic heatmap (a single failure taints the
// tactic — same rule as CoverageScore).
func buildDetectionCategories(results []models.SimulationResult) []Category {
	type agg struct{ exec, fail int }
	m := make(map[string]*agg)
	for _, r := range results {
		t := r.Technique.Tactic
		if t == "" {
			continue
		}
		a := m[t]
		if a == nil {
			a = &agg{}
			m[t] = a
		}
		if r.Result == models.ResultSkipped || r.Result == models.ResultError {
			continue
		}
		a.exec++
		if r.Result != models.ResultPass && r.Result != models.ResultBlocked {
			a.fail++
		}
	}
	var out []Category
	for _, tactic := range tacticOrder {
		a := m[tactic]
		if a == nil {
			continue
		}
		result := "unknown" // tested but only skipped
		if a.exec > 0 {
			if a.fail == 0 {
				result = "pass"
			} else {
				result = "fail"
			}
		}
		out = append(out, Category{Name: tactic, Result: result})
	}
	return out
}

func buildTopFindings(results []models.SimulationResult, scenarioName string) []Finding {
	var findings []Finding
	// Deduplicate by technique: the same technique failing across several atomic
	// tests is ONE finding, not the "Critical, Critical, Critical…" repetition the
	// ART review flagged. Keep the first occurrence (first-seen order).
	seen := make(map[string]bool)
	for _, r := range results {
		if r.Result != models.ResultFail {
			continue
		}
		if r.Severity != "Critical" && r.Severity != "High" {
			continue
		}
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			TechniqueID:   r.Technique.ID,
			TechniqueName: r.Technique.Name,
			Tactic:        r.Technique.Tactic,
			Severity:      r.Severity,
			Details:       r.Details,
			Remediation:   r.Remediation,
			ScenarioName:  scenarioName,
		})
	}
	return findings
}

func buildRecommendations(score models.Score, heatmap []TacticEntry) []string {
	var recs []string
	if score.PreventionScore < 50 {
		recs = append(recs, "Overall prevention score is critically low. Prioritise endpoint hardening and EDR deployment across all assets.")
	} else if score.PreventionScore < 70 {
		recs = append(recs, "Prevention score indicates significant control gaps. Review failed techniques and apply vendor hardening guides.")
	}
	for _, t := range heatmap {
		if t.Failed > 0 && t.Weight == "Critical" {
			recs = append(recs, "Critical tactic '"+t.Tactic+"' has "+formatInt(t.Failed)+" failing technique(s). Address immediately — this tactic has the highest attacker value in BFSI environments.")
		}
	}
	if score.KillChainAmplifier >= 1.8 {
		recs = append(recs, "Kill-chain amplifier is "+formatFloat(score.KillChainAmplifier)+"× — an attacker can traverse multiple consecutive kill-chain phases unimpeded. Implement network segmentation and lateral movement controls.")
	}
	if score.ExposureScore > 60 {
		recs = append(recs, "Exposure score exceeds 60. Deploy a 24×7 SOC with SIEM correlation rules aligned to detected failure patterns.")
	}
	if score.KillChainCoverage < 50 {
		recs = append(recs, "Tactic coverage is below 50%. Run additional scenarios (ART full sweep, Caldera lateral movement) to exercise more of the ATT&CK kill chain before next audit.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Maintain current security posture. Schedule next BAS assessment within 30 days to verify continued effectiveness.")
	}
	return recs
}

func formatInt(n int) string {
	return fmt.Sprintf("%d", n)
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.1f", f)
}
