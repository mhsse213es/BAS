package models

// ComputeScore derives a risk Score from a slice of SimulationResults.
//
// Severity-weighted risk formula:
//   - Each result is weighted by severity (Critical=4, High=3, Medium=2, Low=1)
//   - RiskScore = (weighted failed steps / weighted executed steps) * 100
//   - Higher RiskScore = attacker got through more = worse posture
func ComputeScore(results []SimulationResult) Score {
	if len(results) == 0 {
		return Score{}
	}

	var (
		total    int
		executed int // non-skipped
		passed   int // result == pass or blocked
		failed   int // result == fail

		weightedFailed   float64
		weightedExecuted float64

		tacticsFailed  = make(map[string]bool)
		tacticsAll     = make(map[string]bool)
		stepsWithEvents int
	)

	for _, r := range results {
		total++
		if r.Technique.Tactic != "" {
			tacticsAll[r.Technique.Tactic] = true
		}

		if r.Result == ResultSkipped {
			continue
		}
		executed++

		w := float64(severityWeight(r.Severity))
		weightedExecuted += w

		if len(r.Events) > 0 {
			stepsWithEvents++
		}

		switch r.Result {
		case ResultPass, ResultBlocked:
			passed++
		case ResultFail:
			failed++
			weightedFailed += w
			if r.Technique.Tactic != "" {
				tacticsFailed[r.Technique.Tactic] = true
			}
		}
	}

	const totalTactics = 14 // ATT&CK Enterprise tactic count

	riskScore := 0
	if weightedExecuted > 0 {
		riskScore = clamp(int(weightedFailed/weightedExecuted*100), 0, 100)
	}

	confidence := 0
	if total > 0 {
		confidence = clamp(executed*100/total, 0, 100)
	}

	preventionEff := 0
	if executed > 0 {
		preventionEff = clamp(passed*100/executed, 0, 100)
	}

	objectiveSuccess := 0
	if executed > 0 {
		objectiveSuccess = clamp(failed*100/executed, 0, 100)
	}

	attackProgression := clamp(len(tacticsFailed)*100/totalTactics, 0, 100)
	blastRadius := clamp(len(tacticsAll)*100/totalTactics, 0, 100)

	detectionTiming := 0
	if executed > 0 {
		detectionTiming = clamp(stepsWithEvents*100/executed, 0, 100)
	}

	return Score{
		RiskScore:               riskScore,
		Classification:          classify(riskScore),
		Confidence:              confidence,
		ExecutionReliability:    confidence,
		AttackProgression:       attackProgression,
		ObjectiveSuccess:        objectiveSuccess,
		DetectionTiming:         detectionTiming,
		BlastRadius:             blastRadius,
		PreventionEffectiveness: preventionEff,
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
