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
}

// ExecutiveSummary is the top-level risk picture derived from the latest run.
type ExecutiveSummary struct {
	RiskScore          int                      `json:"riskScore"`
	Classification     string                   `json:"classification"`
	PreventionScore    float64                  `json:"preventionScore"`
	ExposureScore      float64                  `json:"exposureScore"`
	CoverageScore      float64                  `json:"coverageScore"`
	KillChainAmplifier float64                  `json:"killChainAmplifier"`
	Trend              string                   `json:"trend"`
	TotalRuns          int                      `json:"totalRuns"`
	TotalTechniques    int                      `json:"totalTechniques"`
	PassedTechniques   int                      `json:"passedTechniques"`
	FailedTechniques   int                      `json:"failedTechniques"`
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
		`SELECT name, results, score, started_at
		 FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial')
		 ORDER BY started_at DESC LIMIT 1`, agentID)
	var resultsRaw, scoreRaw2 []byte
	if err := latestRow.Scan(&latestScenarioName, &resultsRaw, &scoreRaw2, &latestRunAt); err == nil {
		json.Unmarshal(resultsRaw, &latestResults)
		json.Unmarshal(scoreRaw2, &latestScore)
	}

	// ── 4. Tactic heatmap from latest run ────────────────────────────────
	report.TacticHeatmap = buildTacticHeatmap(latestResults)

	// ── 5. Top findings (Critical + High failures) from latest run ────────
	report.TopFindings = buildTopFindings(latestResults, latestScenarioName)

	// ── 6. Executive summary ─────────────────────────────────────────────
	report.Summary = ExecutiveSummary{
		RiskScore:          latestScore.RiskScore,
		Classification:     latestScore.Classification,
		PreventionScore:    latestScore.PreventionScore,
		ExposureScore:      latestScore.ExposureScore,
		CoverageScore:      latestScore.CoverageScore,
		KillChainAmplifier: latestScore.KillChainAmplifier,
		Trend:              latestScore.Trend,
		TotalRuns:          len(report.Runs),
		TotalTechniques:    latestScore.TotalTechniques,
		PassedTechniques:   latestScore.PassedTechniques,
		FailedTechniques:   latestScore.FailedTechniques,
		LastRunAt:          latestRunAt,
		LastScenarioName:   latestScenarioName,
		CriticalFailures:   latestScore.CriticalFailures,
		Recommendations:    buildRecommendations(latestScore, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}

	// ── 7. Agent posture report (security tools, detection categories) ────
	var toolsRaw, catsRaw []byte
	e.db.QueryRow(ctx,
		`SELECT security_tools, categories FROM reports WHERE agent_id = $1`, agentID,
	).Scan(&toolsRaw, &catsRaw)

	var toolsList []struct {
		Name string `json:"name"`
	}
	if len(toolsRaw) > 0 {
		json.Unmarshal(toolsRaw, &toolsList)
		for _, t := range toolsList {
			if t.Name != "" {
				report.SecurityTools = append(report.SecurityTools, t.Name)
			}
		}
	}
	var catsList []struct {
		Name   string `json:"name"`
		Result string `json:"result"`
	}
	if len(catsRaw) > 0 {
		json.Unmarshal(catsRaw, &catsList)
		for _, c := range catsList {
			report.DetectionCategories = append(report.DetectionCategories, Category{Name: c.Name, Result: c.Result})
		}
	}

	return report, nil
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
		if r.Result == models.ResultSkipped {
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

func buildTopFindings(results []models.SimulationResult, scenarioName string) []Finding {
	var findings []Finding
	for _, r := range results {
		if r.Result != models.ResultFail {
			continue
		}
		if r.Severity != "Critical" && r.Severity != "High" {
			continue
		}
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
	if score.CoverageScore < 50 {
		recs = append(recs, "Tactic coverage is below 50%. Run additional scenarios (ART full sweep, Caldera lateral movement) to increase test coverage before next audit.")
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
