// Package reporting builds full assessment reports and audit-pack ZIPs.
package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/detect"
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
	Detection           DetectionSummary `json:"detection"`
	TrendAnalysis       TrendSummary     `json:"trendAnalysis"`
	AttackPath          AttackPath       `json:"attackPath"`
}

// AttackPathStep is one kill-chain phase the endpoint did not prevent, with the
// unprevented technique(s) in that phase.
type AttackPathStep struct {
	Tactic     string   `json:"tactic"`
	Techniques []string `json:"techniques"` // "T1059.001 — PowerShell"
}

// AttackPath is the chain of consecutive kill-chain phases this run's unprevented
// techniques actually form — the executive's-eye view the ART review asked for
// (attackers chain steps; they do not operate one ATT&CK ID at a time). It is
// grounded strictly in observed FAILs ordered by kill-chain phase: the path the
// endpoint's gaps permit, not a hypothetical or inferred causal chain.
type AttackPath struct {
	Steps []AttackPathStep `json:"steps"`
}

// buildAttackPath orders the run's unprevented techniques (FAIL) by kill-chain
// phase into a single realized path. Techniques are de-duplicated per phase;
// PASS/ERROR/SKIPPED never appear (they are not part of an attacker's successful
// chain). Honest by design — no technique→technique causal inference, only the
// observed traversal across phases.
func buildAttackPath(results []models.SimulationResult) AttackPath {
	type acc struct {
		techs []string
		seen  map[string]bool
	}
	m := make(map[string]*acc)
	for _, r := range results {
		if r.Result != models.ResultFail {
			continue
		}
		t := r.Technique.Tactic
		if t == "" {
			continue
		}
		a := m[t]
		if a == nil {
			a = &acc{seen: make(map[string]bool)}
			m[t] = a
		}
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		if key == "" || a.seen[key] {
			continue
		}
		a.seen[key] = true
		label := strings.TrimSpace(r.Technique.Name)
		switch {
		case r.Technique.ID != "" && label != "":
			label = r.Technique.ID + " — " + label
		case r.Technique.ID != "":
			label = r.Technique.ID
		}
		a.techs = append(a.techs, label)
	}
	var ap AttackPath
	for _, tactic := range tacticOrder {
		a := m[tactic]
		if a == nil || len(a.techs) == 0 {
			continue
		}
		ap.Steps = append(ap.Steps, AttackPathStep{Tactic: tactic, Techniques: a.techs})
	}
	return ap
}

// TrendPoint is one scored assessment in the endpoint's history, for the trend
// sparkline (oldest → newest).
type TrendPoint struct {
	RunID           string    `json:"runId"`
	Date            time.Time `json:"date"`
	PreventionScore float64   `json:"preventionScore"`
	RiskScore       int       `json:"riskScore"`
}

// TrendSummary answers "are we improving?" — the question a BAS is bought to
// answer. It compares the current run's prevention effectiveness to the previous
// scored assessment for the same endpoint and carries a short history for a
// sparkline. A snapshot becomes a programme metric.
type TrendSummary struct {
	HasPrevious        bool         `json:"hasPrevious"`
	CurrentPrevention  float64      `json:"currentPrevention"`
	PreviousPrevention float64      `json:"previousPrevention"`
	DeltaPrevention    float64      `json:"deltaPrevention"` // current − previous (pts)
	CurrentRisk        int          `json:"currentRisk"`
	PreviousRisk       int          `json:"previousRisk"`
	History            []TrendPoint `json:"history"` // oldest → newest, ≤6 points
}

// buildTrendSummary derives the prevention trend from the endpoint's run history.
// Only scored runs (completed/partial) count; the newest is "current", the next
// is "previous". History is capped to the most recent few, oldest-first for
// display. With fewer than two scored runs the trend is simply marked absent —
// we never invent a baseline.
func buildTrendSummary(runs []RunSummary) TrendSummary {
	var scored []RunSummary
	for _, r := range runs {
		if r.Status == "completed" || r.Status == "partial" {
			scored = append(scored, r)
		}
	}
	var t TrendSummary
	if len(scored) == 0 {
		return t
	}
	cur := scored[0]
	t.CurrentPrevention = cur.PreventionScore
	t.CurrentRisk = cur.RiskScore

	const maxPts = 6
	pts := scored
	if len(pts) > maxPts {
		pts = pts[:maxPts]
	}
	for i := len(pts) - 1; i >= 0; i-- {
		t.History = append(t.History, TrendPoint{
			RunID: pts[i].ID, Date: pts[i].StartedAt,
			PreventionScore: pts[i].PreventionScore, RiskScore: pts[i].RiskScore,
		})
	}
	if len(scored) >= 2 {
		prev := scored[1]
		t.HasPrevious = true
		t.PreviousPrevention = prev.PreventionScore
		t.DeltaPrevention = cur.PreventionScore - prev.PreventionScore
		t.PreviousRisk = prev.RiskScore
	}
	return t
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
	CoverageScore      float64                  `json:"coverageScore"`     // defense rate — tactics fully blocked
	KillChainCoverage  float64                  `json:"killChainCoverage"` // breadth — % of 14 ATT&CK tactics exercised
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
	DetectionRate      int                      `json:"detectionRate"`  // detected ÷ executed-not-prevented
	UndetectedRate     int                      `json:"undetectedRate"` // blind spots — succeeded with no alert
	MTTDMs             int64                    `json:"mttdMs"`         // mean time-to-detect across detected techniques
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
		        status, env_label, has_report, binary_hash, binary_trusted, last_update,
		        security_products
		 FROM agents WHERE agent_id = $1`, agentID)
	var agentSecProducts []byte
	if err := row.Scan(
		&report.Agent.AgentID, &report.Agent.Hostname, &report.Agent.IPAddress,
		&report.Agent.OSVersion, &report.Agent.Username, &report.Agent.Status,
		&report.Agent.EnvLabel, &report.Agent.HasReport,
		&report.Agent.BinaryHash, &report.Agent.BinaryTrusted, &report.Agent.LastUpdate,
		&agentSecProducts,
	); err != nil {
		report.Agent.AgentID = agentID
	}
	json.Unmarshal(agentSecProducts, &report.SecurityTools)

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
	report.Detection = buildDetectionSummary(latestResults)
	report.TrendAnalysis = buildTrendSummary(report.Runs)
	report.AttackPath = buildAttackPath(latestResults)

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
	var detRate, undetRate *int
	var mttd *int64
	err := e.db.QueryRow(ctx,
		`SELECT agent_id, name, status, results, score, started_at, completed_at, reverted,
		        detection_rate, undetected_rate, mttd_ms
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &scenarioName, &status, &resultsRaw, &scoreRaw, &startedAt, &completedAt, &revertedRaw,
		&detRate, &undetRate, &mttd)
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
		        status, env_label, has_report, binary_hash, binary_trusted, last_update,
		        security_products
		 FROM agents WHERE agent_id = $1`, agentID)
	var agentSecProducts []byte
	row.Scan(
		&report.Agent.AgentID, &report.Agent.Hostname, &report.Agent.IPAddress,
		&report.Agent.OSVersion, &report.Agent.Username, &report.Agent.Status,
		&report.Agent.EnvLabel, &report.Agent.HasReport,
		&report.Agent.BinaryHash, &report.Agent.BinaryTrusted, &report.Agent.LastUpdate,
		&agentSecProducts,
	)
	json.Unmarshal(agentSecProducts, &report.SecurityTools)
	if report.Agent.AgentID == "" {
		report.Agent.AgentID = agentID
	}

	report.TacticHeatmap = buildTacticHeatmap(results)
	report.DetectionCategories = buildDetectionCategories(results)
	report.TopFindings = buildTopFindings(results, scenarioName)
	report.ObjectiveRisks = buildObjectiveRisks(results)
	report.Detection = buildDetectionSummary(results)
	report.AttackPath = buildAttackPath(results)

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
	if detRate != nil {
		report.Summary.DetectionRate = *detRate
	}
	if undetRate != nil {
		report.Summary.UndetectedRate = *undetRate
	}
	if mttd != nil {
		report.Summary.MTTDMs = *mttd
	}

	report.Runs = []RunSummary{{
		ID: runID, ScenarioName: scenarioName, Status: status,
		StartedAt: startedAt, CompletedAt: completedAt,
		RiskScore: score.RiskScore, Classification: score.Classification,
		PreventionScore: score.PreventionScore, ExposureScore: score.ExposureScore,
		TotalTechniques: score.TotalTechniques, FailedTechniques: score.FailedTechniques,
	}}

	// Trend: a per-run report still shows the endpoint's programme trend, not just
	// this run in isolation. Pull the agent's scored run history for the comparison.
	var trendRuns []RunSummary
	if trows, terr := e.db.Query(ctx,
		`SELECT id, status, score, started_at
		   FROM scenario_runs
		  WHERE agent_id = $1 AND status IN ('completed','partial')
		  ORDER BY started_at DESC LIMIT 20`, agentID); terr == nil {
		defer trows.Close()
		for trows.Next() {
			var rs RunSummary
			var scoreRaw []byte
			trows.Scan(&rs.ID, &rs.Status, &scoreRaw, &rs.StartedAt)
			if len(scoreRaw) > 0 {
				var sc models.Score
				if json.Unmarshal(scoreRaw, &sc) == nil {
					rs.PreventionScore = sc.PreventionScore
					rs.RiskScore = sc.RiskScore
				}
			}
			trendRuns = append(trendRuns, rs)
		}
	}
	report.TrendAnalysis = buildTrendSummary(trendRuns)

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

// Detection is the per-technique detection verdict derived from the event-log
// telemetry the agent collected during the step. It answers the ART review's
// "was the attack detected, and by what" — honestly limited to what is locally
// observable (Microsoft Defender + Sysmon/Security); third-party EDR alerts are
// never asserted because they are not locally queryable.
type Detection struct {
	Detected bool   // a real detection alert fired (Defender)
	Status   string // "Detected" | "Logged" | "None"
	Source   string // "Microsoft Defender" | "Sysmon" | "Windows Security" | ""
	Detail   string // human phrase for the report
}

// defenderDetectIDs are Microsoft Defender Operational event IDs that mean a
// threat was detected / acted on (not benign update/scan noise).
var defenderDetectIDs = map[string]bool{
	"1006": true, "1007": true, "1008": true, "1009": true, "1010": true,
	"1011": true, "1012": true, "1015": true, "1116": true, "1117": true,
	"1118": true, "1119": true,
}

// classifyDetection maps the agent's raw "id:log" event tokens to a detection
// verdict. A Defender detection event = Detected; any other telemetry (Sysmon,
// Security, benign Defender events) = Logged (visibility, no alert); nothing =
// None. Interpretation lives here on the server, not on the agent.
func classifyDetection(events []string) Detection {
	loggedSource := ""
	for _, ev := range events {
		id, logName, ok := splitEventToken(ev)
		if !ok {
			continue
		}
		llog := strings.ToLower(logName)
		switch {
		case strings.Contains(llog, "defender"):
			if defenderDetectIDs[id] {
				return Detection{
					Detected: true, Status: "Detected", Source: "Microsoft Defender",
					Detail: "Microsoft Defender raised a detection (event " + id + ")",
				}
			}
			if loggedSource == "" {
				loggedSource = "Microsoft Defender"
			}
		case strings.Contains(llog, "sysmon"):
			if loggedSource == "" {
				loggedSource = "Sysmon"
			}
		case detect.IsEDRProvider(logName):
			return Detection{
				Detected: true, Status: "Detected", Source: logName,
				Detail: "Third-party EDR raised a detection (" + logName + " event " + id + ")",
			}
		default:
			if loggedSource == "" {
				loggedSource = "Windows Security"
			}
		}
	}
	if loggedSource != "" {
		return Detection{
			Status: "Logged", Source: loggedSource,
			Detail: "Activity logged by " + loggedSource + " — no detection alert raised",
		}
	}
	return Detection{Status: "None", Detail: "No detection telemetry observed"}
}

// asrBlockIDs are Microsoft Defender Operational event IDs that mean an Attack
// Surface Reduction (or related Defender exploit-guard) rule BLOCKED an action —
// not merely audited it. Used to attribute a PASS to Defender ASR specifically.
var asrBlockIDs = map[string]bool{
	"1121": true, // ASR rule blocked
	"1123": true, // Controlled folder access blocked
	"1125": true, // Network protection blocked
}

// attributeControl names the security control that blocked a technique, when the
// evidence honestly supports a specific attribution — addressing the ART review's
// "PASS, but which control?". Order of confidence: Defender Operational events
// (ASR rule action / threat action), then recognisable block signatures in the
// captured output. Returns "" when no control can be evidenced; the caller then
// states a control blocked it WITHOUT guessing a product. We never assert a
// control we cannot evidence. Framework-agnostic — keys off events and output.
func attributeControl(r models.SimulationResult) string {
	for _, ev := range r.Events {
		id, logName, ok := splitEventToken(ev)
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(logName), "defender") {
			if asrBlockIDs[id] {
				return "Microsoft Defender (ASR rule)"
			}
			if defenderDetectIDs[id] {
				return "Microsoft Defender"
			}
		}
	}
	low := strings.ToLower(r.RawOutput)
	switch {
	case strings.Contains(low, "defender"),
		strings.Contains(low, "antivirus"),
		strings.Contains(low, "threat detected"),
		strings.Contains(low, "quarantined"),
		strings.Contains(low, "operation did not complete successfully"):
		return "Microsoft Defender (from output)"
	case strings.Contains(low, "blocked by group policy"),
		strings.Contains(low, "blocked by your administrator"),
		strings.Contains(low, "this program is blocked"),
		strings.Contains(low, "this app has been blocked"):
		return "Application Control / Group Policy"
	case strings.Contains(low, "constrained language"):
		return "PowerShell Constrained Language Mode"
	case strings.Contains(low, "amsi"):
		return "Antimalware Scan Interface (AMSI)"
	}
	return ""
}

// DetectionSummary is the defence-in-depth rollup of executed (FAIL) techniques:
// a FAIL means prevention did not stop the technique, but the SOC outcome differs
// sharply depending on whether it was also detected. This reframes a raw FAIL
// count into the actionable "prevented? detected?" matrix a BAS buyer expects.
type DetectionSummary struct {
	ExecutedUnprevented int  // FAIL count — prevention controls did not stop execution
	Detected            int  // …of which a detection alert fired (Microsoft Defender)
	LoggedOnly          int  // …of which telemetry exists but no alert was raised
	Undetected          int  // …of which no telemetry was observed (executed unseen)
	TelemetryObserved   bool // any host telemetry was collected this run at all
}

// buildDetectionSummary tallies the prevention/detection matrix and records
// whether ANY host telemetry was collected during the run. The distinction is
// critical and honest: when no events were collected for the entire run (an old
// agent build, the agent offline, or Defender disabled), "Undetected" does NOT
// mean the techniques evaded detection — it means detection could not be measured
// at all. The report must say so rather than implying every technique slipped past
// the SOC. When telemetry exists, an undetected FAIL is a genuine visibility gap.
func buildDetectionSummary(results []models.SimulationResult) DetectionSummary {
	var s DetectionSummary
	for _, r := range results {
		if len(r.Events) > 0 {
			s.TelemetryObserved = true
		}
		if r.Result != models.ResultFail {
			continue
		}
		s.ExecutedUnprevented++
		switch classifyDetection(r.Events).Status {
		case "Detected":
			s.Detected++
		case "Logged":
			s.LoggedOnly++
		default:
			s.Undetected++
		}
	}
	return s
}

// splitEventToken parses a "id:logName" telemetry token. Log names contain no
// colon, so a split on the first colon is unambiguous.
func splitEventToken(tok string) (id, logName string, ok bool) {
	i := strings.IndexByte(tok, ':')
	if i <= 0 || i >= len(tok)-1 {
		return "", "", false
	}
	return strings.TrimSpace(tok[:i]), strings.TrimSpace(tok[i+1:]), true
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
