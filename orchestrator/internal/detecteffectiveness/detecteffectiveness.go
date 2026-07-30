// Package detecteffectiveness computes prevented/detectedOnly/missed
// analytics across recent scenario runs -- per-technique, per-tactic, and
// per-privilege-tier. Extracted from internal/api/handlers.go's
// GetCoverageAnalytics handler, matching the internal/campaign precedent
// from Sub-project A: real computation lives in its own package, the
// handler becomes a thin caller.
//
// This is a genuinely different question from internal/coverage.Compute
// (does content exist for a technique at all) and
// internal/pathcorrelation.Correlate (graph/attack-path-weighted detection
// score) -- see docs/superpowers/specs/2026-07-30-detection-reconciliation-design.md.
package detecteffectiveness

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
)

// Verdict ranks a technique's best-observed outcome across runs: missed is
// worst, prevented is best. Ordering matters -- ByTechnique sorts missed
// first via this ranking, and "best" tracking uses v > e.best.
type Verdict int

const (
	VerdictMissed       Verdict = 0
	VerdictDetectedOnly Verdict = 1
	VerdictPrevented    Verdict = 2
)

// VerdictString renders a Verdict as its JSON string form.
func VerdictString(v Verdict) string {
	switch v {
	case VerdictPrevented:
		return "prevented"
	case VerdictDetectedOnly:
		return "detectedOnly"
	default:
		return "missed"
	}
}

// NormPrivTier maps a raw ExecutedAs value from SimulationResult to one of
// "user" | "admin" | "system" | "inherited".
func NormPrivTier(executedAs string) string {
	switch {
	case executedAs == "":
		return "inherited"
	case executedAs == "system":
		return "system"
	case executedAs == "admin" || strings.Contains(executedAs, "→"):
		return "admin"
	default:
		return "user"
	}
}

// CoverageAnalytics is the aggregate coverage view across a set of runs.
type CoverageAnalytics struct {
	RunsAnalyzed      int                  `json:"runsAnalyzed"`
	Summary           AnalyticsSummary     `json:"summary"`
	ByTechnique       []TechniqueAnalytic  `json:"byTechnique"`
	ByTactic          []TacticAnalytic     `json:"byTactic"`
	RecentRuns        []RunAnalyticSummary `json:"recentRuns"`
	PrivilegeCoverage PrivilegeCoverage    `json:"privilegeCoverage"`
}

// PrivilegeCoverage is the per-execution-tier breakdown of coverage results.
type PrivilegeCoverage struct {
	ByTier   []TierStat         `json:"byTier"`
	GapTechs []PrivGapTechnique `json:"gapTechs"`
}

// TierStat is the prevention/detection summary for one execution tier.
type TierStat struct {
	Tier           string `json:"tier"` // user | admin | system | inherited
	Attempted      int    `json:"attempted"`
	Prevented      int    `json:"prevented"`
	DetectedOnly   int    `json:"detectedOnly"`
	Missed         int    `json:"missed"`
	PreventionRate int    `json:"preventionRate"` // prevented/attempted*100
}

// PrivGapTechnique is a technique tested only at elevated tier(s), never at user.
type PrivGapTechnique struct {
	TechniqueID string   `json:"techniqueId"`
	Name        string   `json:"name,omitempty"`
	Tiers       []string `json:"tiers"` // tiers actually tested (e.g. ["admin"])
}

type AnalyticsSummary struct {
	Attempted         int `json:"attempted"`
	Prevented         int `json:"prevented"`
	DetectedOnly      int `json:"detectedOnly"`
	Missed            int `json:"missed"`
	PreventionRate    int `json:"preventionRate"`    // prevented/attempted*100
	DetectionCoverage int `json:"detectionCoverage"` // (prevented+detected)/attempted*100
}

type TechniqueAnalytic struct {
	TechniqueID  string `json:"techniqueId"`
	Name         string `json:"name,omitempty"`
	Tactic       string `json:"tactic,omitempty"`
	BestVerdict  string `json:"bestVerdict"` // prevented | detectedOnly | missed
	RunCount     int    `json:"runCount"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

type TacticAnalytic struct {
	Tactic       string `json:"tactic"`
	Attempted    int    `json:"attempted"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

type RunAnalyticSummary struct {
	RunID        string    `json:"runId"`
	ScenarioID   string    `json:"scenarioId"`
	Name         string    `json:"name"`
	AgentID      string    `json:"agentId"`
	StartedAt    time.Time `json:"startedAt"`
	Attempted    int       `json:"attempted"`
	Prevented    int       `json:"prevented"`
	DetectedOnly int       `json:"detectedOnly"`
	Missed       int       `json:"missed"`
}

// Compute aggregates prevented/detectedOnly/missed analytics across recent
// completed/partial scenario_runs, optionally filtered to one scenario
// and/or one agent, capped at limit runs (most recent first).
func Compute(ctx context.Context, pool *pgxpool.Pool, scenarioID, agentID string, limit int) (CoverageAnalytics, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, scenario_id, name, agent_id, results, detection_summary, started_at
		   FROM scenario_runs
		  WHERE status IN ('completed', 'partial')
		    AND results IS NOT NULL
		    AND ($1 = '' OR scenario_id = $1)
		    AND ($2 = '' OR agent_id = $2)
		  ORDER BY started_at DESC LIMIT $3`,
		scenarioID, agentID, limit)
	if err != nil {
		return CoverageAnalytics{}, err
	}
	defer rows.Close()

	type techEntry struct {
		name   string
		tactic string
		best   Verdict // best across all runs
		runs   int
		prev   int
		det    int
		miss   int
		// per-tier tallies: tier → [attempted, prevented, detectedOnly, missed]
		tierStats map[string]*[4]int
	}
	type privTechEntry struct {
		name  string
		tiers map[string]bool
	}
	techMap := map[string]*techEntry{}
	tacticMap := map[string]*TacticAnalytic{}
	privTechs := map[string]*privTechEntry{} // techniqueID → tiers seen
	var recent []RunAnalyticSummary
	runsAnalyzed := 0

	for rows.Next() {
		var rid, scID, name, agID string
		var resRaw, detRaw []byte
		var startedAt time.Time
		if err := rows.Scan(&rid, &scID, &name, &agID, &resRaw, &detRaw, &startedAt); err != nil {
			continue
		}
		var results []models.SimulationResult
		if len(resRaw) > 0 {
			json.Unmarshal(resRaw, &results)
		}
		detected := reporting.DetectedTechniques(detRaw, results)
		runsAnalyzed++

		runSumm := RunAnalyticSummary{RunID: rid, ScenarioID: scID, Name: name, AgentID: agID, StartedAt: startedAt}

		for _, res := range results {
			switch res.Result {
			case models.ResultError, models.ResultSkipped:
				continue
			}
			tid := strings.ToUpper(res.Technique.ID)
			if tid == "" {
				continue
			}
			var v Verdict
			switch res.Result {
			case models.ResultPass, models.ResultBlocked:
				v = VerdictPrevented
			case models.ResultFail:
				if detected[res.Technique.ID] || detected[tid] {
					v = VerdictDetectedOnly
				} else {
					v = VerdictMissed
				}
			default:
				continue
			}

			e := techMap[tid]
			if e == nil {
				e = &techEntry{name: res.Technique.Name, tactic: res.Technique.Tactic, tierStats: map[string]*[4]int{}}
				techMap[tid] = e
			}
			if res.Technique.Name != "" && e.name == "" {
				e.name = res.Technique.Name
			}
			if res.Technique.Tactic != "" && e.tactic == "" {
				e.tactic = res.Technique.Tactic
			}
			e.runs++
			if v > e.best {
				e.best = v
			}
			switch v {
			case VerdictPrevented:
				e.prev++
			case VerdictDetectedOnly:
				e.det++
			default:
				e.miss++
			}

			// Privilege tier tracking.
			tier := NormPrivTier(res.ExecutedAs)
			ts := e.tierStats[tier]
			if ts == nil {
				ts = &[4]int{}
				e.tierStats[tier] = ts
			}
			ts[0]++ // attempted
			switch v {
			case VerdictPrevented:
				ts[1]++
			case VerdictDetectedOnly:
				ts[2]++
			default:
				ts[3]++
			}
			pt := privTechs[tid]
			if pt == nil {
				pt = &privTechEntry{name: res.Technique.Name, tiers: map[string]bool{}}
				privTechs[tid] = pt
			}
			if res.Technique.Name != "" && pt.name == "" {
				pt.name = res.Technique.Name
			}
			pt.tiers[tier] = true

			// per-run counts
			switch v {
			case VerdictPrevented:
				runSumm.Prevented++
			case VerdictDetectedOnly:
				runSumm.DetectedOnly++
			default:
				runSumm.Missed++
			}
			runSumm.Attempted++
		}
		recent = append(recent, runSumm)
	}

	// Build ByTechnique (sorted: missed first, then detectedOnly, then prevented, then by ID).
	techList := make([]TechniqueAnalytic, 0, len(techMap))
	for tid, e := range techMap {
		tacKey := e.tactic
		if tacKey == "" {
			tacKey = "unknown"
		}
		if tacticMap[tacKey] == nil {
			tacticMap[tacKey] = &TacticAnalytic{Tactic: tacKey}
		}
		tac := tacticMap[tacKey]
		tac.Attempted++
		switch e.best {
		case VerdictPrevented:
			tac.Prevented++
		case VerdictDetectedOnly:
			tac.DetectedOnly++
		default:
			tac.Missed++
		}
		techList = append(techList, TechniqueAnalytic{
			TechniqueID: tid, Name: e.name, Tactic: e.tactic,
			BestVerdict: VerdictString(e.best),
			RunCount:    e.runs, Prevented: e.prev, DetectedOnly: e.det, Missed: e.miss,
		})
	}
	sort.Slice(techList, func(i, j int) bool {
		bi := techMap[techList[i].TechniqueID].best
		bj := techMap[techList[j].TechniqueID].best
		if bi != bj {
			return bi < bj // missed first
		}
		return techList[i].TechniqueID < techList[j].TechniqueID
	})

	// Build ByTactic (sorted by missed desc).
	tacList := make([]TacticAnalytic, 0, len(tacticMap))
	for _, t := range tacticMap {
		tacList = append(tacList, *t)
	}
	sort.Slice(tacList, func(i, j int) bool {
		if tacList[i].Missed != tacList[j].Missed {
			return tacList[i].Missed > tacList[j].Missed
		}
		return tacList[i].Tactic < tacList[j].Tactic
	})

	// Summary.
	var summ AnalyticsSummary
	for _, t := range techList {
		summ.Attempted++
		switch t.BestVerdict {
		case "prevented":
			summ.Prevented++
		case "detectedOnly":
			summ.DetectedOnly++
		default:
			summ.Missed++
		}
	}
	if summ.Attempted > 0 {
		summ.PreventionRate = summ.Prevented * 100 / summ.Attempted
		summ.DetectionCoverage = (summ.Prevented + summ.DetectedOnly) * 100 / summ.Attempted
	}

	// Build PrivilegeCoverage: per-tier stats + gap list.
	tierOrder := []string{"user", "admin", "system", "inherited"}
	tierAgg := map[string]*[4]int{}
	for _, e := range techMap {
		for tier, ts := range e.tierStats {
			agg := tierAgg[tier]
			if agg == nil {
				agg = &[4]int{}
				tierAgg[tier] = agg
			}
			agg[0] += ts[0]
			agg[1] += ts[1]
			agg[2] += ts[2]
			agg[3] += ts[3]
		}
	}
	var tierStats []TierStat
	for _, tier := range tierOrder {
		ts := tierAgg[tier]
		if ts == nil || ts[0] == 0 {
			continue
		}
		pct := 0
		if ts[0] > 0 {
			pct = ts[1] * 100 / ts[0]
		}
		tierStats = append(tierStats, TierStat{
			Tier: tier, Attempted: ts[0], Prevented: ts[1],
			DetectedOnly: ts[2], Missed: ts[3], PreventionRate: pct,
		})
	}
	var gapTechs []PrivGapTechnique
	for tid, pt := range privTechs {
		if pt.tiers["user"] {
			continue // tested at user — not a gap
		}
		if !pt.tiers["admin"] && !pt.tiers["system"] {
			continue // only inherited, not elevated — not a meaningful gap
		}
		var tiers []string
		for _, t := range []string{"admin", "system", "inherited"} {
			if pt.tiers[t] {
				tiers = append(tiers, t)
			}
		}
		gapTechs = append(gapTechs, PrivGapTechnique{TechniqueID: tid, Name: pt.name, Tiers: tiers})
	}
	sort.Slice(gapTechs, func(i, j int) bool { return gapTechs[i].TechniqueID < gapTechs[j].TechniqueID })

	return CoverageAnalytics{
		RunsAnalyzed:      runsAnalyzed,
		Summary:           summ,
		ByTechnique:       techList,
		ByTactic:          tacList,
		RecentRuns:        recent,
		PrivilegeCoverage: PrivilegeCoverage{ByTier: tierStats, GapTechs: gapTechs},
	}, nil
}
