package models

import "math"

// killChainTactics is the ordered ATT&CK kill-chain path used for amplification.
// Consecutive failures in this sequence amplify the Exposure Score.
var killChainTactics = []string{
	"initial-access", "execution", "persistence",
	"privilege-escalation", "defense-evasion", "credential-access",
	"lateral-movement", "collection", "exfiltration",
}

// enterpriseTacticCount is the number of tactics in MITRE ATT&CK Enterprise
// (reconnaissance, resource-development, initial-access, execution, persistence,
// privilege-escalation, defense-evasion, credential-access, discovery,
// lateral-movement, collection, command-and-control, exfiltration, impact).
// Used as the denominator for KillChainCoverage (testing breadth).
const enterpriseTacticCount = 14

// tacticExposureWeight returns the tactic-level weight for Exposure Score.
// Mirrors the severity tiers defined in Severity(tactic).
func tacticExposureWeight(tactic string) float64 {
	switch tactic {
	case "credential-access", "lateral-movement", "privilege-escalation":
		return 4
	case "persistence", "defense-evasion", "execution",
		"command-and-control", "impact", "exfiltration", "collection":
		return 3
	case "initial-access":
		return 2
	default:
		return 1
	}
}

// ComputeScore derives a multi-dimensional Score from SimulationResults.
//
// Five primary dimensions:
//   - PreventionScore  — severity-weighted pass rate (higher = safer)
//   - ExposureScore    — tactic-weighted fail rate, amplified by kill-chain depth
//   - CoverageScore    — defense rate: % of tested ATT&CK tactics with zero failures
//   - KillChainCoverage — breadth: % of the 14 ATT&CK enterprise tactics exercised
//   - KillChainAmplifier — consecutive kill-chain phase failures multiplier
//   - Trend            — comparison against prev run (Improving/Degrading/Stable/Baseline)
//
// Pass prev=nil when no prior run exists; Trend will be "Baseline".
func ComputeScore(results []SimulationResult, prev *Score) Score {
	if len(results) == 0 {
		return Score{
			Trend:            "Baseline",
			TacticBreakdown:  make(map[string]TacticScore),
			CriticalFailures: []CriticalFailure{},
		}
	}

	var (
		total    int
		executed int
		passed   int
		failed   int

		weightedPassed float64
		weightedTotal  float64

		tacticWeightFailed float64
		tacticWeightTotal  float64

		tacticPassCount = make(map[string]int)
		tacticFailCount = make(map[string]int)
		tacticCount     = make(map[string]int)

		criticalFailures []CriticalFailure
	)

	for _, r := range results {
		total++
		tactic := r.Technique.Tactic
		tw := tacticExposureWeight(tactic)

		if r.Result == ResultSkipped {
			continue
		}
		executed++

		sw := float64(severityWeight(r.Severity))
		weightedTotal += sw
		if tactic != "" {
			tacticWeightTotal += tw
			tacticCount[tactic]++
		}

		switch r.Result {
		case ResultPass, ResultBlocked:
			passed++
			weightedPassed += sw
			if tactic != "" {
				tacticPassCount[tactic]++
			}
		case ResultFail:
			failed++
			if tactic != "" {
				tacticWeightFailed += tw
				tacticFailCount[tactic]++
			}
			if r.Severity == "Critical" || r.Severity == "High" {
				criticalFailures = append(criticalFailures, CriticalFailure{
					TechniqueID: r.Technique.ID,
					Name:        r.Technique.Name,
					Tactic:      tactic,
					Severity:    r.Severity,
				})
			}
		}
	}

	// ── Prevention Score (0–100, higher = better) ─────────────────────────────
	preventionScore := 0.0
	if weightedTotal > 0 {
		preventionScore = clampF(weightedPassed/weightedTotal*100, 0, 100)
	}

	// ── Tactic Breakdown ─────────────────────────────────────────────────────
	tacticBreakdown := make(map[string]TacticScore)
	for tactic, cnt := range tacticCount {
		p := tacticPassCount[tactic]
		f := tacticFailCount[tactic]
		passPct := 0
		if cnt > 0 {
			passPct = p * 100 / cnt
		}
		tacticBreakdown[tactic] = TacticScore{
			Tactic:  tactic,
			Passed:  p,
			Failed:  f,
			Total:   cnt,
			PassPct: passPct,
		}
	}

	// ── Coverage Score (0–100, higher = better) ───────────────────────────────
	// A tactic is "covered" when it has been tested and has zero failures.
	testedTactics := len(tacticCount)
	coveredTactics := 0
	for tactic := range tacticCount {
		if tacticFailCount[tactic] == 0 {
			coveredTactics++
		}
	}
	coverageScore := 0.0
	if testedTactics > 0 {
		coverageScore = clampF(float64(coveredTactics)/float64(testedTactics)*100, 0, 100)
	}

	// ── Kill-Chain Coverage (0–100) ───────────────────────────────────────────
	// Breadth: how much of the ATT&CK Enterprise kill chain this run exercised,
	// regardless of pass/fail. Unlike CoverageScore (a defense-success metric),
	// this measures testing completeness so a run that touches few tactics reads
	// low even when every technique was blocked.
	killChainCoverage := clampF(float64(testedTactics)/float64(enterpriseTacticCount)*100, 0, 100)

	// ── Kill Chain Amplifier ──────────────────────────────────────────────────
	// Find the longest consecutive sequence of kill-chain phase failures.
	maxConsec := 0
	consec := 0
	for _, t := range killChainTactics {
		if tacticFailCount[t] > 0 {
			consec++
			if consec > maxConsec {
				maxConsec = consec
			}
		} else {
			consec = 0
		}
	}
	amplifier := 1.0
	switch {
	case maxConsec >= 5:
		amplifier = 2.5
	case maxConsec >= 3:
		amplifier = 1.8
	case maxConsec >= 2:
		amplifier = 1.3
	}

	// ── Exposure Score (0–100, higher = worse) ───────────────────────────────
	rawExposure := 0.0
	if tacticWeightTotal > 0 {
		rawExposure = tacticWeightFailed / tacticWeightTotal * 100
	}
	exposureScore := clampF(rawExposure*amplifier, 0, 100)

	// ── Confidence ────────────────────────────────────────────────────────────
	// Blends two dimensions:
	//   execution rate  — % of steps that actually ran (not skipped due to errors)
	//   tactic coverage — % of the ATT&CK kill chain covered (9 main phases)
	// A scan that skips many checks OR covers only 1-2 tactics should show lower
	// confidence so analysts know the risk score is less representative.
	confidence := 0
	if total > 0 {
		execRate := float64(executed) / float64(total) * 100.0

		const mainKillChainPhases = 9 // initial-access through exfiltration
		tacticCov := float64(testedTactics) / mainKillChainPhases * 100.0
		if tacticCov > 100 {
			tacticCov = 100
		}

		blended := (execRate + tacticCov) / 2.0
		confidence = clamp(int(math.Round(blended)), 0, 100)
	}

	// ── Trend ─────────────────────────────────────────────────────────────────
	trend := "Baseline"
	prevPreventionScore := 0.0
	if prev != nil {
		prevPreventionScore = prev.PreventionScore
		delta := preventionScore - prevPreventionScore
		switch {
		case delta >= 5:
			trend = "Improving"
		case delta <= -5:
			trend = "Degrading"
		default:
			trend = "Stable"
		}
	}

	if criticalFailures == nil {
		criticalFailures = []CriticalFailure{}
	}

	riskScore := clamp(int(math.Round(exposureScore)), 0, 100)

	return Score{
		PreventionScore:         preventionScore,
		ExposureScore:           rawExposure,
		CoverageScore:           coverageScore,
		KillChainCoverage:       killChainCoverage,
		KillChainAmplifier:      amplifier,
		Trend:                   trend,
		PreviousPreventionScore: prevPreventionScore,
		TacticBreakdown:         tacticBreakdown,
		CriticalFailures:        criticalFailures,

		TotalTechniques:  total,
		PassedTechniques: passed,
		FailedTechniques: failed,

		RiskScore:               riskScore,
		Classification:          classify(riskScore),
		Confidence:              confidence,
		PreventionEffectiveness: clamp(int(math.Round(preventionScore)), 0, 100),
	}
}

func severityWeight(sev string) int {
	switch sev {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	default:
		return 1
	}
}

func classify(riskScore int) string {
	switch {
	case riskScore <= 20:
		return "Protected"
	case riskScore <= 40:
		return "Low Risk"
	case riskScore <= 60:
		return "Medium Risk"
	case riskScore <= 80:
		return "High Risk"
	default:
		return "Critical"
	}
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func clampF(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
